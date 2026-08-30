"""
Autobahn Defender v2.1 -- AI Knowledge Base.

A curated, static knowledge base of Linux security best practices,
common vulnerabilities, hardening guides, and remediation steps.

The AI queries this before running tools to know what to look for,
and after running tools to know what remediation commands to recommend.

This is NOT dynamic data -- it's hardcoded reference text that the
AI receives as part of its system prompt or as a tool result when
it calls the `knowledge_lookup` tool.

Categories:
  - hardening     : System hardening best practices
  - vulnerabilities : Common vulnerability patterns and CVE families
  - remediation   : Step-by-step fix commands for common issues
  - zero_day      : Zero-day response playbooks
  - network       : Network security best practices
  - privacy       : Privacy and data protection settings
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Knowledge entries -- organized by category
# ---------------------------------------------------------------------------

KNOWLEDGE_BASE: dict[str, list[dict[str, str]]] = {

    "hardening": [
        {
            "topic": "SSH Hardening",
            "severity": "HIGH",
            "check": "ssh_config_check tool",
            "guidance": (
                "PermitRootLogin should be 'no' or 'prohibit-password'. "
                "PasswordAuthentication should be 'no' if keys are used. "
                "X11Forwarding should be 'no' unless needed. "
                "MaxAuthTries should be 3 or less. "
                "AllowUsers or AllowGroups should restrict who can SSH in. "
                "Protocol should be 2 (Protocol 1 is deprecated and insecure). "
                "Ciphers should exclude 3des, blowfish, arcfour, cast128. "
                "MACs should exclude hmac-md5, hmac-sha1, umac-64-etm@openssh.com. "
                "KexAlgorithms should exclude diffie-hellman-group1-sha1, diffie-hellman-group14-sha1."
            ),
            "remediation": (
                "Edit /etc/ssh/sshd_config:\n"
                "  PermitRootLogin no\n"
                "  PasswordAuthentication no\n"
                "  MaxAuthTries 3\n"
                "  X11Forwarding no\n"
                "Then: sudo systemctl restart sshd\n"
                "Test config: sudo sshd -t"
            ),
        },
        {
            "topic": "Kernel Hardening (sysctl)",
            "severity": "HIGH",
            "check": "privacy_hardening tool",
            "guidance": (
                "Key sysctl settings for security:\n"
                "  net.ipv4.ip_forward = 0 (unless this is a router)\n"
                "  net.ipv4.conf.all.send_redirects = 0\n"
                "  net.ipv4.conf.all.accept_redirects = 0\n"
                "  net.ipv4.conf.all.accept_source_route = 0\n"
                "  net.ipv4.conf.all.log_martians = 1\n"
                "  net.ipv4.tcp_syncookies = 1 (SYN flood protection)\n"
                "  net.ipv4.icmp_echo_ignore_broadcasts = 1 (smurf protection)\n"
                "  kernel.kptr_restrict = 2 (hide kernel pointers)\n"
                "  kernel.dmesg_restrict = 1 (restrict dmesg to root)\n"
                "  kernel.perf_event_paranoid = 2 (restrict perf events)\n"
                "  kernel.yama.ptrace_scope = 2 (restrict ptrace)\n"
                "  fs.suid_dumpable = 0 (no core dumps for SUID programs)\n"
                "  fs.protected_hardlinks = 1\n"
                "  fs.protected_symlinks = 1\n"
                "  fs.protected_fifos = 2\n"
                "  fs.protected_regular = 2"
            ),
            "remediation": (
                "Apply settings temporarily:\n"
                "  sudo sysctl -w net.ipv4.ip_forward=0\n"
                "  (repeat for each setting)\n\n"
                "Make permanent:\n"
                "  sudo tee /etc/sysctl.d/99-security.conf << 'EOF'\n"
                "  net.ipv4.ip_forward = 0\n"
                "  net.ipv4.conf.all.send_redirects = 0\n"
                "  net.ipv4.conf.all.accept_redirects = 0\n"
                "  net.ipv4.conf.all.accept_source_route = 0\n"
                "  net.ipv4.tcp_syncookies = 1\n"
                "  net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
                "  kernel.kptr_restrict = 2\n"
                "  kernel.dmesg_restrict = 1\n"
                "  kernel.perf_event_paranoid = 2\n"
                "  kernel.yama.ptrace_scope = 2\n"
                "  fs.suid_dumpable = 0\n"
                "  fs.protected_hardlinks = 1\n"
                "  fs.protected_symlinks = 1\n"
                "  EOF\n"
                "  sudo sysctl --system"
            ),
        },
        {
            "topic": "AppArmor / SELinux",
            "severity": "HIGH",
            "check": "apparmor_status tool",
            "guidance": (
                "AppArmor should be installed and active. "
                "Check: aa-status shows 'profiles are loaded' with N profiles. "
                "If 0 profiles loaded, AppArmor is not protecting anything. "
                "Key profiles that should be loaded: "
                "  - lsb_release, nvidiad, samba, tcpdump, dnsmasq "
                "SELinux (on RHEL/Fedora): enforcing mode is recommended. "
                "Permissive mode logs but does not block -- not secure."
            ),
            "remediation": (
                "Enable AppArmor:\n"
                "  sudo apt install apparmor apparmor-profiles apparmor-utils\n"
                "  sudo systemctl enable apparmor\n"
                "  sudo systemctl start apparmor\n"
                "  sudo aa-enforce /etc/apparmor.d/*\n\n"
                "Enable SELinux (RHEL/Fedora):\n"
                "  sudo setenforce 1\n"
                "  Edit /etc/selinux/config: SELINUX=enforcing"
            ),
        },
        {
            "topic": "Firewall Configuration",
            "severity": "CRITICAL",
            "check": "firewall_check tool",
            "guidance": (
                "A firewall should be active. UFW (Ubuntu) or firewalld (Fedora/RHEL). "
                "UFW status should be 'active'. "
                "Default policies should deny incoming, allow outgoing. "
                "Only necessary ports should be allowed (22 for SSH, 80/443 for web). "
                "Check for exposed risky services: telnet (23), FTP (21), RDP (3389), "
                "SMB (445), Redis (6379), MongoDB (27017), Docker (2375/2376). "
                "If any of these are open to 0.0.0.0, it's a CRITICAL finding."
            ),
            "remediation": (
                "Enable UFW:\n"
                "  sudo ufw default deny incoming\n"
                "  sudo ufw default allow outgoing\n"
                "  sudo ufw allow 22/tcp  # SSH (consider limiting to specific IPs)\n"
                "  sudo ufw allow 80/tcp  # HTTP (if web server)\n"
                "  sudo ufw allow 443/tcp # HTTPS (if web server)\n"
                "  sudo ufw enable\n"
                "  sudo ufw status verbose\n\n"
                "Block a risky service:\n"
                "  sudo ufw deny 23/tcp   # telnet\n"
                "  sudo ufw deny 445/tcp  # SMB\n"
                "  sudo ufw deny 6379/tcp # Redis\n"
                "  sudo ufw deny 2375/tcp # Docker"
            ),
        },
        {
            "topic": "SUID/SGID Binaries",
            "severity": "MEDIUM",
            "check": "suid_binaries tool",
            "guidance": (
                "SUID binaries run with the owner's privileges. "
                "Standard SUID binaries on Linux: sudo, su, passwd, mount, umount, "
                "ping, pkexec, chsh, newgrp, gpasswd, chfn, ssh-agent, crontab. "
                "Any SUID binary NOT in this list is suspicious. "
                "SUID binaries in /tmp, /dev/shm, or user home dirs are CRITICAL. "
                "GTFOBins (gtfobins.github.io) lists SUID binaries that can be "
                "exploited for privilege escalation."
            ),
            "remediation": (
                "Remove SUID bit from suspicious binary:\n"
                "  sudo chmod u-s /path/to/suspicious_binary\n\n"
                "Find all SUID binaries:\n"
                "  sudo find / -perm -4000 -type f 2>/dev/null\n\n"
                "Find SGID binaries:\n"
                "  sudo find / -perm -2000 -type f 2>/dev/null"
            ),
        },
        {
            "topic": "Disk Encryption",
            "severity": "HIGH",
            "check": "disk_encryption tool",
            "guidance": (
                "Root partition should be LUKS-encrypted. "
                "If root is unencrypted, any data on the disk is accessible "
                "by physically accessing the disk (e.g., removing it and "
                "mounting on another machine). "
                "Home directory encryption (eCryptfs or fscrypt) provides "
                "additional protection if root is not encrypted. "
                "Swap should also be encrypted to prevent data leakage."
            ),
            "remediation": (
                "LUKS is set at install time and cannot be easily added later. "
                "If root is unencrypted, recommend reinstalling with LUKS enabled. "
                "Alternatively, encrypt specific directories:\n"
                "  sudo apt install ecryptfs-utils\n"
                "  sudo ecryptfs-migrate-home -u $USER\n\n"
                "Encrypt swap:\n"
                "  sudo apt install cryptsetup\n"
                "  sudo cryptsetup luksFormat /dev/sdXN\n"
                "  Configure /etc/crypttab and /etc/fstab"
            ),
        },
        {
            "topic": "Password Policy",
            "severity": "MEDIUM",
            "check": "password_policy tool",
            "guidance": (
                "Check PAM configuration for password quality. "
                "libpam-pwquality should be installed and configured. "
                "Minlen should be at least 12. "
                "No empty passwords (minlen > 0 and nullok not in PAM). "
                "Password history should prevent reuse (remember=5). "
                "Password aging: max days 90, min days 1, warn 7. "
                "Check /etc/shadow for accounts with no password (NP or !)."
            ),
            "remediation": (
                "Install and configure pwquality:\n"
                "  sudo apt install libpam-pwquality\n"
                "  Edit /etc/security/pwquality.conf:\n"
                "    minlen = 12\n"
                "    dcredit = -1  (at least 1 digit)\n"
                "    ucredit = -1  (at least 1 uppercase)\n"
                "    lcredit = -1  (at least 1 lowercase)\n"
                "    ocredit = -1  (at least 1 special char)\n"
                "    enforce_for_root = 1\n\n"
                "  Edit /etc/pam.d/common-password:\n"
                "    password requisite pam_pwquality.so retry=3\n"
                "    password required pam_unix.so remember=5 sha512\n\n"
                "Set password aging:\n"
                "  sudo chage --maxdays 90 --mindays 1 --warndays 7 $USER"
            ),
        },
        {
            "topic": "Automatic Updates",
            "severity": "MEDIUM",
            "check": "update_status tool",
            "guidance": (
                "Security updates should be installed promptly. "
                "unattended-upgrades package can auto-install security updates. "
                "Check if there are pending security updates. "
                "Check when the system was last updated (apt history log). "
                "Stale systems (no update in 30+ days) are vulnerable to "
                "known CVEs that have already been patched."
            ),
            "remediation": (
                "Install and enable unattended-upgrades:\n"
                "  sudo apt install unattended-upgrades\n"
                "  sudo dpkg-reconfigure -plow unattended-upgrades\n\n"
                "Manually update now:\n"
                "  sudo apt update && sudo apt upgrade -y\n"
                "  sudo apt autoremove -y\n\n"
                "Check for security updates only:\n"
                "  sudo apt list --upgradable 2>/dev/null | grep -i security"
            ),
        },
    ],

    "vulnerabilities": [
        {
            "topic": "Exposed Network Services",
            "severity": "HIGH",
            "check": "network_connections + service_manager tools",
            "guidance": (
                "Any service listening on 0.0.0.0 (all interfaces) is exposed "
                "to the network. Check if the service should be bound to 127.0.0.1. "
                "High-risk exposed services: Redis (6379), MongoDB (27017), "
                "Elasticsearch (9200), Docker (2375), MySQL (3306), "
                "PostgreSQL (5432), VNC (5900), RDP (3389). "
                "If a database or cache service is bound to 0.0.0.0 without "
                "authentication, it's a CRITICAL vulnerability."
            ),
            "remediation": (
                "Bind service to localhost:\n"
                "  Edit the service config file:\n"
                "    bind 127.0.0.1  (Redis: /etc/redis/redis.conf)\n"
                "    bind-address = 127.0.0.1  (MySQL: /etc/mysql/my.cnf)\n"
                "    network.host: 127.0.0.1  (Elasticsearch: elasticsearch.yml)\n\n"
                "Block with firewall:\n"
                "  sudo ufw deny 6379/tcp  # Redis\n"
                "  sudo ufw deny 27017/tcp  # MongoDB"
            ),
        },
        {
            "topic": "Suspicious Persistence Mechanisms",
            "severity": "HIGH",
            "check": "scan_persistence tool",
            "guidance": (
                "Malware and rootkits establish persistence through: "
                "Crontab entries, systemd services, init.d scripts, "
                "XDG autostart .desktop files, bashrc/profile modifications, "
                "LD_PRELOAD in environment, kernel modules, udev rules. "
                "Suspicious indicators: entries running scripts from /tmp, "
                "/dev/shm, /var/tmp, or downloading from URLs. "
                "Base64-encoded commands in crontab or scripts. "
                "Unknown .desktop files in ~/.config/autostart/. "
                "Unrecognized systemd services in /etc/systemd/system/."
            ),
            "remediation": (
                "Remove suspicious crontab entry:\n"
                "  crontab -e  # Remove the suspicious line\n"
                "  sudo crontab -e  # Check root crontab too\n\n"
                "Disable suspicious systemd service:\n"
                "  sudo systemctl stop <service-name>\n"
                "  sudo systemctl disable <service-name>\n"
                "  sudo rm /etc/systemd/system/<service-name>.service\n"
                "  sudo systemctl daemon-reload\n\n"
                "Remove autostart entry:\n"
                "  rm ~/.config/autostart/<suspicious>.desktop"
            ),
        },
        {
            "topic": "Hosts File Hijacking",
            "severity": "MEDIUM",
            "check": "check_hosts tool",
            "guidance": (
                "The /etc/hosts file maps domain names to IPs. "
                "Malware can modify it to redirect legitimate domains "
                "(banks, email, social media) to attacker-controlled IPs. "
                "Suspicious entries: known domains pointing to 0.0.0.0 "
                "(ad-blocking is OK, but targeted blocking of security/AV "
                "sites is suspicious), domains pointing to non-standard IPs, "
                "entries for domains the user didn't add."
            ),
            "remediation": (
                "Restore default hosts file:\n"
                "  sudo cp /etc/hosts /etc/hosts.bak\n"
                "  sudo tee /etc/hosts << 'EOF'\n"
                "  127.0.0.1 localhost\n"
                "  127.0.1.1 $(hostname)\n"
                "  ::1 localhost ip6-localhost ip6-loopback\n"
                "  ff02::1 ip6-allnodes\n"
                "  ff02::2 ip6-allrouters\n"
                "  EOF\n\n"
                "Protect hosts file:\n"
                "  sudo chattr +i /etc/hosts  # immutable (use -i to undo)"
            ),
        },
        {
            "topic": "Weak DNS Configuration",
            "severity": "MEDIUM",
            "check": "dns_check tool",
            "guidance": (
                "System DNS should use a trusted resolver. "
                "ISP DNS can log and redirect queries. "
                "Check /etc/resolv.conf for the nameserver entries. "
                "If using 127.0.0.53, systemd-resolved is in use (check "
                "its config with resolvectl status). "
                "DNS over HTTPS (DoH) or DNS over TLS (DoT) provides "
                "encryption and prevents ISP snooping. "
                "Test DNSSEC: dig +dnssec example.com should show "
                "the AD flag for DNSSEC-validating resolvers."
            ),
            "remediation": (
                "Set DNS to a privacy-respecting resolver:\n"
                "  sudo tee /etc/resolv.conf << 'EOF'\n"
                "  nameserver 1.1.1.1\n"
                "  nameserver 1.0.0.1\n"
                "  # or: 9.9.9.9 (Quad9), 8.8.8.8 (Google)\n"
                "  EOF\n\n"
                "Enable DoH in Firefox: about:config > network.trr.mode=2\n"
                "Enable system-wide DoT (systemd-resolved):\n"
                "  sudo mkdir -p /etc/systemd/resolved.conf.d\n"
                "  sudo tee /etc/systemd/resolved.conf.d/dot.conf << 'EOF'\n"
                "  [Resolve]\n"
                "  DNSOverTLS=yes\n"
                "  DNS=1.1.1.1#one.one.one.one\n"
                "  FallbackDNS=9.9.9.9#dns.quad9.net\n"
                "  EOF\n"
                "  sudo systemctl restart systemd-resolved"
            ),
        },
    ],

    "zero_day": [
        {
            "topic": "Zero-Day Response Playbook",
            "severity": "CRITICAL",
            "check": "rss_poll + web_search + cve_check tools",
            "guidance": (
                "When a zero-day is announced (no patch available yet):\n"
                "1. Identify the affected software and version.\n"
                "2. Check if the vulnerable version is installed: call "
                "installed_packages tool.\n"
                "3. If installed, determine if the service is running: call "
                "service_manager and network_connections tools.\n"
                "4. If the service is running and exposed, it's CRITICAL.\n"
                "5. Determine the attack vector (network, local, file).\n"
                "6. Recommend a workaround:\n"
                "   - Network service: stop the service (pkexec systemctl stop X)\n"
                "   - Network service: block the port (sudo ufw deny PORT)\n"
                "   - Local exploit: restrict permissions (sudo chmod 000 /path)\n"
                "   - File-based: quarantine the file type\n"
                "7. Create an alert with the workaround command.\n"
                "8. Monitor for the patch release. When available, recommend "
                "   sudo apt update && sudo apt upgrade PACKAGE."
            ),
            "remediation": (
                "Immediate mitigation (no patch available):\n"
                "  Stop service: sudo systemctl stop <service>\n"
                "  Block port: sudo ufw deny <port>/tcp\n"
                "  Restrict binary: sudo chmod 000 /path/to/binary\n\n"
                "When patch is available:\n"
                "  sudo apt update && sudo apt upgrade <package>\n"
                "  sudo systemctl restart <service>\n\n"
                "If no workaround exists and the vulnerability is critical:\n"
                "  Consider temporarily disconnecting from the network:\n"
                "  nmcli device disconnect <interface>"
            ),
        },
        {
            "topic": "Supply Chain Attack Response",
            "severity": "CRITICAL",
            "check": "installed_packages + scan_persistence tools",
            "guidance": (
                "If a package repository or maintainer was compromised:\n"
                "1. Identify all packages from the compromised source.\n"
                "2. Check for suspicious post-install scripts.\n"
                "3. Look for new persistence mechanisms that appeared after "
                "the package was installed.\n"
                "4. Check for unexpected network connections to new IPs.\n"
                "5. Recommend downgrading to a known-good version or removing "
                "the package entirely."
            ),
            "remediation": (
                "Remove compromised package:\n"
                "  sudo apt remove --purge <package>\n"
                "  sudo apt autoremove --purge\n\n"
                "Downgrade to safe version:\n"
                "  sudo apt install <package>=<safe_version>\n\n"
                "Pin a version to prevent auto-update:\n"
                "  sudo apt-mark hold <package>\n"
                "  (undo with: sudo apt-mark unhold <package>)"
            ),
        },
    ],

    "network": [
        {
            "topic": "Open Ports and Services",
            "severity": "HIGH",
            "check": "network_connections tool",
            "guidance": (
                "Every open port is an attack surface. "
                "List all listening ports and identify the process. "
                "Ports on 127.0.0.1 are local-only (safer). "
                "Ports on 0.0.0.0 or the public IP are exposed. "
                "Close unnecessary ports. If a port must stay open, "
                "ensure it's firewalled and the service is updated. "
                "Common unnecessary services: avahi-daemon (mDNS), "
                "cups (printing), rpcbind (NFS), Postfix (mail relay)."
            ),
            "remediation": (
                "Disable unnecessary services:\n"
                "  sudo systemctl disable --now avahi-daemon\n"
                "  sudo systemctl disable --now cups\n"
                "  sudo systemctl disable --now rpcbind\n"
                "  sudo systemctl disable --now postfix\n\n"
                "Close specific port with UFW:\n"
                "  sudo ufw deny <port>/tcp\n\n"
                "Find what's listening:\n"
                "  sudo ss -tlnp  (TCP)\n"
                "  sudo ss -ulnp  (UDP)"
            ),
        },
        {
            "topic": "Network Threat Indicators",
            "severity": "HIGH",
            "check": "network_threat_monitor tool",
            "guidance": (
                "Check active connections against threat intelligence feeds. "
                "Connections to known-malicious IPs indicate compromise. "
                "Emerging Threats compromised IP list is a good baseline. "
                "Suspicious patterns: connections to TOR exit nodes (if not "
                "intentionally using TOR), connections to known C2 servers, "
                "unexpected outbound connections on non-standard ports, "
                "large data transfers to foreign IPs."
            ),
            "remediation": (
                "Block a malicious IP:\n"
                "  sudo ufw deny out to <malicious_ip>\n"
                "  sudo iptables -A OUTPUT -d <malicious_ip> -j DROP\n\n"
                "Kill suspicious connection:\n"
                "  sudo ss -K dst <malicious_ip>\n"
                "  sudo kill <PID>\n\n"
                "Install fail2ban for brute-force protection:\n"
                "  sudo apt install fail2ban\n"
                "  sudo systemctl enable --now fail2ban"
            ),
        },
    ],

    "privacy": [
        {
            "topic": "Screen Lock Settings",
            "severity": "LOW",
            "check": "screen_lock tool",
            "guidance": (
                "Screen should auto-lock after 5-15 minutes of inactivity. "
                "Check screensaver timeout, lock-on-suspend, and idle delay. "
                "If screen lock is disabled, anyone with physical access "
                "can access the session."
            ),
            "remediation": (
                "Set screen lock timeout (GNOME):\n"
                "  gsettings set org.gnome.desktop.session idle-delay 300\n"
                "  gsettings set org.gnome.desktop.screensaver lock-enabled true\n"
                "  gsettings set org.gnome.desktop.screensaver lock-delay 0\n\n"
                "Set screen lock timeout (KDE Plasma):\n"
                "  kwriteconfig6 kscreenlockerrc Daemon AutoLock 5\n"
                "  kwriteconfig6 kscreenlockerrc Daemon Timeout 5"
            ),
        },
        {
            "topic": "Browser Privacy",
            "severity": "LOW",
            "check": "browser_cleaner tool",
            "guidance": (
                "Browsers store cookies, cache, history, and form data. "
                "Clearing this data periodically improves privacy. "
                "Do NOT clear saved passwords or bookmarks -- these are "
                "user data, not privacy risks. "
                "Check browser data size. Large caches can contain "
                "sensitive session tokens. "
                "Consider using privacy-focused browsers: Firefox, Brave. "
                "Enable Enhanced Tracking Protection in Firefox."
            ),
            "remediation": (
                "Clear browser cache (Firefox):\n"
                "  rm -rf ~/.cache/mozilla/firefox/*/cache2/\n\n"
                "Clear browser cache (Chrome/Brave):\n"
                "  rm -rf ~/.cache/google-chrome/Default/Cache/\n"
                "  rm -rf ~/.cache/BraveSoftware/Brave-Browser/Default/Cache/\n\n"
                "Clear cookies (Firefox):\n"
                "  rm ~/.mozilla/firefox/*/cookies.sqlite\n\n"
                "Use the browser's built-in cleanup tool for more control."
            ),
        },
    ],
}


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------

def lookup(category: str = "", topic: str = "") -> dict[str, Any]:
    """Look up knowledge base entries by category and/or topic.

    Args:
        category: One of: hardening, vulnerabilities, zero_day, network, privacy.
                  If empty, returns a summary of all categories.
        topic: Specific topic to look up. If empty, returns all entries in the category.

    Returns:
        dict with matching entries.
    """
    if not category:
        # Return a summary of all categories
        summary = {}
        for cat, entries in KNOWLEDGE_BASE.items():
            summary[cat] = [e["topic"] for e in entries]
        return {
            "status": "ok",
            "data": {
                "categories": summary,
                "hint": "Call knowledge_lookup with a specific category and/or topic to get detailed guidance.",
            },
        }

    category = category.lower().strip()
    # Map common aliases
    alias_map = {
        "hardening": "hardening",
        "vulnerability": "vulnerabilities",
        "vulnerabilities": "vulnerabilities",
        "vuln": "vulnerabilities",
        "zero_day": "zero_day",
        "zero-day": "zero_day",
        "zeroday": "zero_day",
        "network": "network",
        "privacy": "privacy",
    }
    cat_key = alias_map.get(category, category)

    if cat_key not in KNOWLEDGE_BASE:
        return {
            "status": "error",
            "error": f"Unknown category: {category}. Available: {', '.join(KNOWLEDGE_BASE.keys())}",
        }

    entries = KNOWLEDGE_BASE[cat_key]

    if topic:
        topic_lower = topic.lower().strip()
        matching = [e for e in entries if topic_lower in e["topic"].lower()]
        if not matching:
            return {
                "status": "ok",
                "data": {
                    "category": cat_key,
                    "available_topics": [e["topic"] for e in entries],
                    "message": f"No exact match for '{topic}'. Available topics listed above.",
                },
            }
        return {
            "status": "ok",
            "data": {
                "category": cat_key,
                "entries": matching,
                "count": len(matching),
            },
        }

    return {
        "status": "ok",
        "data": {
            "category": cat_key,
            "entries": entries,
            "count": len(entries),
        },
    }


def get_kb_summary_for_prompt() -> str:
    """Return a compact summary of the knowledge base for inclusion in the system prompt.

    This gives the AI a map of what knowledge is available so it knows
    it can call knowledge_lookup for detailed guidance.
    """
    lines = [
        "KNOWLEDGE BASE AVAILABLE:",
        "You have a built-in knowledge base you can query for Linux security",
        "best practices, remediation commands, and zero-day response playbooks.",
        "Call the knowledge_lookup tool with a category (and optional topic) to get",
        "detailed guidance. Categories and their topics:",
    ]
    for cat, entries in KNOWLEDGE_BASE.items():
        lines.append(f"  {cat}:")
        for e in entries:
            lines.append(f"    - {e['topic']} [{e['severity']}]")
    lines.append("")
    lines.append("Use this BEFORE writing your final report to ensure your")
    lines.append("remediation commands match the knowledge base recommendations.")
    return "\n".join(lines)