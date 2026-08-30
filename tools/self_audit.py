"""Self-audit sweep for Autobahn Defender.

  1. syntax compile check (all live files)
  2. scope-aware AST undefined-call scan (audit's A-bug detector)
  3. dangerous-pattern scan (shell=True / os.system / eval / exec) with
     comments AND docstrings stripped to kill string-literal false positives
  4. pytest suite

Usage:  python3 tools/self_audit.py    (exit 0 = clean, 1 = problems)
"""
import ast
import builtins
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path("/home/kristopher/Projects/Autobahn Defender")
EXCLUDED = {"ai_tab.py"}
BASES = [ROOT, ROOT / "engine", ROOT / "engine" / "intel",
         ROOT / "engine" / "watch", ROOT / "cli", ROOT / "ai",
         ROOT / "tests", ROOT / "tools"]


def live_files():
    files = []
    for base in BASES:
        if base.exists():
            files.extend(base.glob("*.py"))
    return sorted(
        (f for f in set(files)
         if f.is_file() and f.name not in EXCLUDED
         and "__pycache__" not in str(f)),
        key=lambda p: str(p))


def module_globals(tree) -> set:
    g = {n for n in dir(builtins) if not n.startswith("__")}
    g |= {"__name__", "__file__", "__doc__", "__package__", "__spec__",
          "__import__"}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            g.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                for nm in ast.walk(t):
                    if isinstance(nm, ast.Name):
                        g.add(nm.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            g.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                g.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, (ast.If, ast.Try)):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for a in sub.names:
                        g.add((a.asname or a.name).split(".")[0])
                elif isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        if isinstance(t, ast.Name):
                            g.add(t.id)
    return g


def collect_bound(fn_node) -> set:
    """Names bound inside a function (params, locals, nested defs, imports)."""
    names = set()
    for node in ast.walk(fn_node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                for arg in list(a.args) + list(a.kwonlyargs):
                    names.add(arg.arg)
                if a.vararg:
                    names.add(a.vararg.arg)
                if a.kwarg:
                    names.add(a.kwarg.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                names.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def _ancestor_bound(tree, fn_node) -> set:
    """Names bound by any function that ENCLOSES fn_node (closure chain)."""
    parent_map = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    names = set()
    chain = []
    node = fn_node
    while node is not None:
        chain.append(node)
        node = parent_map.get(node)
    for anc in chain[1:]:
        if isinstance(anc, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names |= collect_bound(anc)
    return names


def strip_code_noise(src: str) -> str:
    """Return source with every comment AND string literal blanked out
    (docstrings included), keeping line count so numbers stay accurate."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src
    lines = src.splitlines()

    def span_to_blank(start: int, end: int) -> None:
        # replace literal span with equivalent number of blank lines
        for i in range(start - 1, min(end, len(lines))):
            lines[i] = ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s, e = node.lineno, (node.end_lineno or node.lineno)
            # only blank MULTILINE strings (docstrings); single-line strings
            # may be part of legit code (e.g. dict values like "0" thresholds)
            if e > s:
                for i in range(s - 1, e):
                    if 0 <= i < len(lines):
                        lines[i] = ""
    return "\n".join(lines)


def strip_comments(src: str) -> str:
    out = []
    for line in src.splitlines():
        s = line.lstrip()
        if s.startswith("#"):
            out.append("")
        elif " #" in line and '"' not in line.split(" #")[0]:
            out.append(line.split(" #", 1)[0])
        else:
            out.append(line)
    return "\n".join(out)


def main() -> int:
    files = live_files()
    problems = 0
    print(f"self-audit over {len(files)} files")

    # ── 1. syntax ────────────────────────────────────────────────────────
    for f in files:
        try:
            compile(f.read_text(errors="replace"), str(f), "exec")
        except SyntaxError as e:
            print(f"SYNTAX {f.name}:{e.lineno}: {e.msg}")
            problems += 1
    print("[1] syntax OK" if not problems else "[1] syntax: see above")

    # ── 2. scope-aware undefined-call scan ───────────────────────────────
    for f in files:
        if f.parent.name in ("tests", "ai", "tools"):
            continue  # ai/ = archive; tools = this file
        try:
            tree = ast.parse(f.read_text(errors="replace"))
        except SyntaxError:
            continue
        g = module_globals(tree)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    if sub.func.id not in g:
                        print(f"UNDEFINED-CALL {f.name}:{sub.lineno} "
                              f"{sub.func.id}()")
                        problems += 1
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = g | collect_bound(fn)
                # Include names bound in ENCLOSING functions (closures) —
                # e.g. build_cmd() defined in a parent and called in a nested
                # worker function. Walk ancestor FunctionDefs.
                anc = _ancestor_bound(tree, fn)
                scope |= anc
                for sub in ast.walk(fn):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        if sub.func.id not in scope:
                            print(f"UNDEFINED-CALL {f.name}:{sub.lineno} "
                                  f"{sub.func.id}()")
                            problems += 1
    print("[2] AST undefined-name done")

    # ── 3. dangerous patterns (docstrings + comments stripped) ──────────
    pats = {
        "shell=True": re.compile(r"shell\s*=\s*True"),
        "os.system": re.compile(r"os\.system\s*\("),
        "eval-call": re.compile(r"(?<![.\w])eval\s*\("),
        "exec-call": re.compile(r"(?<![.\w])exec\s*\("),
    }
    for f in files:
        if f.parent.name in ("tests", "tools", "docs", "ai"):
            continue
        src = f.read_text(errors="replace")
        no_strings = strip_code_noise(src)
        no_comments = strip_comments(no_strings)
        for i, line in enumerate(no_comments.splitlines(), 1):
            if ".eval(" in line:
                continue
            for name, rx in pats.items():
                if rx.search(line):
                    print(f"PATTERN {f.name}:{i} [{name}] {line.strip()[:90]}")
                    problems += 1
    print("[3] pattern scan done")

    # ── 4. pytest ────────────────────────────────────────────────────────
    r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"],
                       capture_output=True, text=True, timeout=280, cwd=str(ROOT))
    tail = r.stdout.strip().splitlines()[-1] if r.stdout else "(no output)"
    print(f"[4] pytest: {tail}")
    if " failed" in tail:
        problems += 1

    print()
    verdict = ("CLEAN" if problems == 0
               else f"{problems} PROBLEM(S) — FIX BEFORE BUILD")
    print("SELF-AUDIT:", verdict)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())