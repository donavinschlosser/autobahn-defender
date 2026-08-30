"""
Autobahn Defender v2.0 -- Ollama sidecar process manager.

Manages a bundled Ollama server as a subprocess. The user never
interacts with Ollama directly. Auto-selects a free port, creates
the model from a Modelfile on first run, and shuts down on app exit.

All parameters are hardcoded -- NOT user-configurable.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests

from . import (
    MODEL_NAME,
    BASE_MODEL,
    GGUF_PATH,
    CHAT_TEMPLATE,
    NUM_CTX,
    TEMPERATURE,
    KEEP_ALIVE,
    OLLAMA_DATA_DIR,
    MODEL_DIR,
    OLLAMA_BIN_CANDIDATES,
    OLLAMA_LIB_DIR,
)

log = logging.getLogger(__name__)


def find_ollama_binary() -> str | None:
    """Return the first existing Ollama binary path, or None."""
    for p in OLLAMA_BIN_CANDIDATES:
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return p
    return shutil.which("ollama")


def _find_free_port(start: int = 11435, end: int = 12000) -> int:
    """Find a free TCP port in [start, end). Falls back to OS-assigned."""
    for port in range(start, end):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_ollama(base_url: str, timeout: float = 60.0) -> bool:
    """Poll Ollama /api/tags until it responds or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/api/tags", timeout=2)
            if r.status_code == 200:
                return True
        except (requests.RequestException, ConnectionError):
            pass
        time.sleep(0.5)
    return False


class OllamaManager:
    """Manages the Ollama sidecar subprocess and model lifecycle."""

    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None
        self._base_url: str | None = None
        self._ready: bool = False
        self._model_ready: bool = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def base_url(self) -> str | None:
        return self._base_url

    @property
    def port(self) -> int | None:
        return self._port

    @property
    def model_ready(self) -> bool:
        return self._model_ready

    def start(self, progress_cb=None) -> bool:
        with self._lock:
            return self._start_locked(progress_cb)

    def _start_locked(self, progress_cb) -> bool:
        bin_path = find_ollama_binary()
        if bin_path is None:
            if progress_cb:
                progress_cb("Ollama binary not found -- AI features disabled.")
            log.error("Ollama binary not found.")
            return False

        if self.is_running and self._ready:
            return True

        self._port = _find_free_port()
        host = "127.0.0.1"
        self._base_url = f"http://{host}:{self._port}"

        OLLAMA_DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(str(OLLAMA_DATA_DIR), 0o700)
        except OSError:
            pass
        env = os.environ.copy()
        env["OLLAMA_HOST"] = f"{host}:{self._port}"
        env["OLLAMA_MODELS"] = str(OLLAMA_DATA_DIR / "models")
        env["OLLAMA_ORIGINS"] = "*"
        env.setdefault("OLLAMA_DEBUG", "0")

        # FORCE CPU-ONLY
        env["CUDA_VISIBLE_DEVICES"] = "-1"
        env["HIP_VISIBLE_DEVICES"] = "-1"
        env["ROCR_VISIBLE_DEVICES"] = "-1"
        env["OLLAMA_VULKAN"] = "0"
        env["GGML_VK_VISIBLE_DEVICES"] = "-1"
        env["OLLAMA_GPU_LAYERS"] = "0"
        env["OLLAMA_NOGPU"] = "1"

        if Path(OLLAMA_LIB_DIR).is_dir():
            existing_ld = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = (
                f"{OLLAMA_LIB_DIR}:{existing_ld}" if existing_ld
                else OLLAMA_LIB_DIR
            )

        if progress_cb:
            progress_cb("Starting Ollama AI engine...")

        try:
            self._proc = subprocess.Popen(
                [bin_path, "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
        except OSError as e:
            log.error("Failed to start Ollama: %s", e)
            if progress_cb:
                progress_cb(f"Failed to start Ollama: {e}")
            return False

        if not _wait_for_ollama(self._base_url, timeout=60.0):
            if progress_cb:
                progress_cb("Ollama did not start in time.")
            self.stop()
            return False
        self._ready = True

        if not self._ensure_model(progress_cb):
            self.stop()
            return False

        return True

    def stop(self):
        with self._lock:
            self._ready = False
            self._model_ready = False
            if self._proc is not None:
                try:
                    import signal
                    try:
                        os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        self._proc.terminate()
                    try:
                        self._proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            self._proc.kill()
                        self._proc.wait(timeout=5)
                except Exception as e:
                    log.warning("Error stopping Ollama: %s", e)
                finally:
                    self._proc = None
            self._base_url = None
            self._port = None

    def _list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self._base_url}/api/tags", timeout=10)
            r.raise_for_status()
            data = r.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except (requests.RequestException, ValueError):
            return []

    def _ensure_model(self, progress_cb=None) -> bool:
        """Create the model from a Modelfile on first run."""
        existing = self._list_models()
        if any(MODEL_NAME in m for m in existing):
            self._model_ready = True
            if progress_cb:
                progress_cb("AI model ready.")
            return True

        if progress_cb:
            progress_cb("Setting up AI model (first run)...")

        modelfile_text = self._build_modelfile()
        OLLAMA_DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        modelfile_path = str(OLLAMA_DATA_DIR / "Modelfile.tmp")
        with open(modelfile_path, "w") as mf:
            mf.write(modelfile_text)
        os.chmod(modelfile_path, 0o600)

        try:
            if progress_cb:
                progress_cb("Creating AI model (this may take a minute)...")
            ollama_cmd = find_ollama_binary() or "ollama"
            create_env = {**os.environ,
                          "OLLAMA_HOST": f"127.0.0.1:{self._port}",
                          "OLLAMA_MODELS": str(OLLAMA_DATA_DIR / "models")}
            if Path(OLLAMA_LIB_DIR).is_dir():
                existing_ld = create_env.get("LD_LIBRARY_PATH", "")
                create_env["LD_LIBRARY_PATH"] = (
                    f"{OLLAMA_LIB_DIR}:{existing_ld}" if existing_ld
                    else OLLAMA_LIB_DIR
                )
            result = subprocess.run(
                [ollama_cmd, "create", MODEL_NAME, "-f", modelfile_path],
                capture_output=True,
                text=True,
                timeout=600,
                env=create_env,
            )
            if result.returncode != 0:
                log.error("ollama create failed: %s", result.stderr)
                if progress_cb:
                    progress_cb(
                        "Failed to create AI model. "
                        "Check that the GGUF is bundled or network is available."
                    )
                return False
            self._model_ready = True
            if progress_cb:
                progress_cb("AI model ready.")
            return True
        except subprocess.TimeoutExpired:
            log.error("ollama create timed out")
            if progress_cb:
                progress_cb("AI model setup timed out.")
            return False
        finally:
            try:
                os.unlink(modelfile_path)
            except OSError:
                pass

    def _build_modelfile(self) -> str:
        """Build the Modelfile text.

        Uses bundled GGUF if present, otherwise pulls lfm2.5-thinking:2.6b.

        IMPORTANT: We do NOT specify a custom TEMPLATE line. The LFM2.5 GGUF
        from Liquid AI has the correct chat template embedded in the file
        metadata. Ollama detects the LFM2 architecture and uses the built-in
        template automatically. Overriding it with a hand-written template
        caused issues with think tags and tool call formatting.

        We also do NOT use the think-end tag as a stop token. The model needs
        to generate its thinking AND then continue to the actual answer. If
        we stopped at think-end, we'd only get the thinking trace and never
        the analysis. MAX Thinking is enabled via the API think parameter
        set to "max" in each request, NOT via the Modelfile.

        Stop tokens are only <|im_end|> and <|im_start|> (ChatML boundaries).
        """
        if Path(GGUF_PATH).is_file():
            source = f"FROM {GGUF_PATH}"
        else:
            source = f"FROM {BASE_MODEL}"

        return (
            source + "\n"
            + f"PARAMETER num_ctx {NUM_CTX}\n"
            + f"PARAMETER temperature {TEMPERATURE}\n"
            + "PARAMETER top_p 0.1\n"
            + "PARAMETER top_k 50\n"
            + "PARAMETER repeat_penalty 1.05\n"
            + 'PARAMETER stop "<|im_end|>"\n'
            + 'PARAMETER stop "<|im_start|>"\n'
            + 'SYSTEM You are Autobahn Defender AI v2.0, a Linux security analysis assistant. You analyze system security by calling tools and producing clear, actionable findings. Always call tools to gather data before drawing conclusions. Be concise and specific. Never invent data. Use thinking to reason through findings step by step. Never recommend dangerous commands (rm -rf, dd, mkfs, fdisk, shutdown, reboot). You are an advisor — the user executes commands, not you.\n'
        )

    def health_check(self) -> bool:
        """Quick liveness check."""
        if not self._base_url:
            return False
        try:
            r = requests.get(f"{self._base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except requests.RequestException:
            return False