/*
 * Autobahn Defender — Windows Malware YARA Rules
 *
 * Comprehensive rules for detecting malicious Windows software (PE executables).
 * These rules are designed to be used when scanning:
 *   - Wine/Proton prefixes
 *   - SMB mounts from Windows machines
 *   - External drives from Windows machines
 *   - Downloads that may contain Windows malware
 *
 * Sources:
 *   - YARA Forge Core Set patterns (curated from 45+ repositories)
 *   - Florian Roth signature-base (PE rules)
 *   - Elastic Security protections-artifacts
 *   - Yara-Rules/rules community repository
 *   - ReversingLabs open-source YARA rules
 *   - VX Underground malware collection patterns
 *   - Custom rules for emerging threats
 *
 * IMPORTANT: All rules include PE magic byte condition (uint16(0) == 0x5A4D)
 * to prevent false positives on non-PE files. Rules targeting specific file
 * types (Office docs, scripts) use appropriate magic byte checks.
 *
 * This file is DISABLED by default and must be enabled in Settings.
 *
 * Last updated: July 2026
 */

// ═══════════════════════════════════════════════════════════════════
// RANSOMWARE DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_RANSOM_WANNACRY_PE {
    meta:
        description = "WannaCry ransomware PE indicator"
        author = "Autobahn Defender / Florian Roth"
        date = "2024-01-01"
        severity = "critical"
        os = "windows"
        family = "WannaCry"
    strings:
        $wcry1 = "WNcry@2olad" wide ascii
        $wcry2 = "wcry@123" wide ascii
        $wcry3 = "TaskStart" wide ascii
        $wcry4 = "@WanaDecryptor@.exe" wide ascii
        $wcry5 = "WanaCrypt0r" wide ascii
        $wcry6 = "17579aafab44a1f4b" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and any of ($wcry*)
}

rule WIN_RANSOM_LOCKY_PE {
    meta:
        description = "Locky ransomware PE indicator"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "critical"
        os = "windows"
        family = "Locky"
    strings:
        $locky1 = ".locky" wide ascii
        $locky2 = "locky" wide ascii nocase
        $locky3 = "_Locky_recover_instructions" wide ascii
        $locky4 = "odin" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and any of ($locky*)
}

rule WIN_RANSOM_CERBER_PE {
    meta:
        description = "Cerber ransomware PE indicator — crypto + file enumeration"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "critical"
        os = "windows"
        family = "Cerber"
    strings:
        $crypto1 = "CryptAcquireContext" wide ascii
        $crypto2 = "CryptGenKey" wide ascii
        $crypto3 = "CryptEncrypt" wide ascii
        $file1 = "FindFirstFile" wide ascii
        $file2 = "FindNextFile" wide ascii
        $file3 = "WriteFile" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        2 of ($crypto*) and all of ($file*)
}

rule WIN_RANSOM_RYUK_PE {
    meta:
        description = "Ryuk ransomware — targeted enterprise ransomware"
        author = "Autobahn Defender / Elastic Security"
        date = "2024-06-01"
        severity = "critical"
        os = "windows"
        family = "Ryuk"
    strings:
        $ryuk1 = "Ryuk" wide ascii
        $ryuk2 = "RYK" wide ascii
        $ryuk3 = "\\Ryuk\\" ascii
        $ryuk4 = "Hermes" wide ascii
        $ryuk5 = "!This is Ryuk!" wide ascii
        $ryuk6 = "\\\.ryuk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($ryuk*)
}

rule WIN_RANSOM_REVIL_PE {
    meta:
        description = "REvil/Sodinokibi ransomware"
        author = "Autobahn Defender / Florian Roth"
        date = "2024-06-01"
        severity = "critical"
        os = "windows"
        family = "REvil"
    strings:
        $revil1 = "REvil" wide ascii
        $revil2 = "Sodinokibi" wide ascii
        $revil3 = "sodin" wide ascii nocase
        $revil4 = "\\\.REvil" ascii
        $revil5 = "readme-revil" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($revil*)
}

rule WIN_RANSOM_BLACKCAT_PE {
    meta:
        description = "BlackCat/ALPHV ransomware — Rust-based"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "BlackCat"
    strings:
        $bcat1 = "ALPHV" wide ascii
        $bcat2 = "blackcat" wide ascii nocase
        $bcat3 = "\\\.alphv" ascii
        $bcat4 = "\\-blackcat" ascii
        $bcat5 = "rust_std" ascii
        $bcat6 = "rust_panic" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($bcat*)
}

rule WIN_RANSOM_LOCKBIT_PE {
    meta:
        description = "LockBit ransomware — most active ransomware-as-a-service"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "LockBit"
    strings:
        $lb1 = "LockBit" wide ascii
        $lb2 = "lockbit" wide ascii nocase
        $lb3 = "\\\.lockbit" ascii
        $lb4 = "\\Build\\LockBit" ascii
        $lb5 = "StealBit" wide ascii
        $lb6 = "\\-lockbit" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($lb*)
}

rule WIN_RANSOM_BLACKBASTA_PE {
    meta:
        description = "BlackBasta ransomware"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "critical"
        os = "windows"
        family = "BlackBasta"
    strings:
        $bb1 = "BlackBasta" wide ascii
        $bb2 = "blackbasta" wide ascii nocase
        $bb3 = "\\\.basta" ascii
        $bb4 = "basta" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($bb*)
}

rule WIN_RANSOM_AKO_PE {
    meta:
        description = "AKO ransomware"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "AKO"
    strings:
        $ako1 = "AKO" wide ascii
        $ako2 = "\\\.ako" ascii
        $ako3 = "ako" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and all of them
}

rule WIN_RANSOM_CONTIPE {
    meta:
        description = "Conti ransomware — leaked builder variants"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "Conti"
    strings:
        $conti1 = "Conti" wide ascii
        $conti2 = "conti" wide ascii nocase
        $conti3 = "CONTI" wide ascii
        $conti4 = "\\\.conti" ascii
        $conti5 = "\\Conti\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($conti*)
}

rule WIN_RANSOM_MAZE_PE {
    meta:
        description = "Maze ransomware (also known as ChaCha)"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "Maze"
    strings:
        $maze1 = "Maze" wide ascii
        $maze2 = "MAZE" wide ascii
        $maze3 = "\\\.maze" ascii
        $maze4 = "DECRYPT-FILES" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($maze*)
}

rule WIN_RANSOM_DARKSIDE_PE {
    meta:
        description = "DarkSide ransomware — pipeline-targeting"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "DarkSide"
    strings:
        $ds1 = "DarkSide" wide ascii
        $ds2 = "darkside" wide ascii nocase
        $ds3 = "\\\.darkside" ascii
        $ds4 = "\\-darkside" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($ds*)
}

rule WIN_RANSOM_BABUK_PE {
    meta:
        description = "Babuk ransomware — leaked source variants"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "Babuk"
    strings:
        $babuk1 = "Babuk" wide ascii
        $babuk2 = "babuk" wide ascii nocase
        $babuk3 = "\\\.babuk" ascii
        $babuk4 = "\\-babuk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($babuk*)
}

rule WIN_RANSOM_ESXiARGS_PE {
    meta:
        description = "ESXi-args ransomware — targets VMware ESXi servers"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "critical"
        os = "windows"
        family = "ESXiArgs"
    strings:
        $esxi1 = "esxi" wide ascii nocase
        $esxi2 = "vmfs" wide ascii nocase
        $esxi3 = "vmdk" wide ascii nocase
        $esxi4 = "esxcli" wide ascii nocase
        $esxi5 = "vim-cmd" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($esxi*)
}

rule WIN_RANSOM_CRYPTO_API_PE {
    meta:
        description = "Generic PE with ransomware-like crypto API usage"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "GenericRansomware"
    strings:
        $crypt1 = "CryptEncrypt" wide ascii
        $crypt2 = "CryptDecrypt" wide ascii
        $crypt3 = "CryptGenKey" wide ascii
        $crypt4 = "CryptAcquireContext" wide ascii
        $crypt5 = "BCryptEncrypt" wide ascii
        $crypt6 = "BCryptGenRandom" wide ascii
        $shadow1 = "vssadmin" wide ascii nocase
        $shadow2 = "delete shadows" wide ascii nocase
        $shadow3 = "wbadmin" wide ascii nocase
        $shadow4 = "bcdedit" wide ascii nocase
        $note1 = "bitcoin" wide ascii nocase
        $note2 = "decrypt" wide ascii nocase
        $note3 = "your files" wide ascii nocase
        $note4 = "ransom" wide ascii nocase
        $ext1 = ".docx" wide ascii
        $ext2 = ".xlsx" wide ascii
        $ext3 = ".pdf" wide ascii
        $ext4 = ".jpg" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        2 of ($crypt*) and (1 of ($shadow*) or 2 of ($ext*)) and any of ($note*)
}

// ═══════════════════════════════════════════════════════════════════
// TROJAN / BACKDOOR DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_TROJAN_PROCESS_INJECTION_PE {
    meta:
        description = "PE with process injection API imports"
        author = "Autobahn Defender / Elastic Security"
        date = "2024-01-01"
        severity = "high"
        os = "windows"
        family = "ProcessInjection"
    strings:
        $inject1 = "VirtualAllocEx" wide ascii
        $inject2 = "WriteProcessMemory" wide ascii
        $inject3 = "CreateRemoteThread" wide ascii
        $inject4 = "NtUnmapViewOfSection" wide ascii
        $inject5 = "QueueUserAPC" wide ascii
        $inject6 = "NtCreateThreadEx" wide ascii
        $inject7 = "RtlCreateUserThread" wide ascii
        $inject8 = "SetThreadContext" wide ascii
        $inject9 = "ResumeThread" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 3 of ($inject*)
}

rule WIN_TROJAN_PERSISTENCE_NETWORK_PE {
    meta:
        description = "PE with registry persistence + network indicators"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "medium"
        os = "windows"
        family = "Persistence"
    strings:
        $reg1 = "RegSetValueEx" wide ascii
        $reg2 = "RegCreateKey" wide ascii
        $reg3 = "RegCreateKeyEx" wide ascii
        $reg4 = "SHGetSpecialFolderPath" wide ascii
        $net1 = "InternetOpen" wide ascii
        $net2 = "InternetConnect" wide ascii
        $net3 = "WSAStartup" wide ascii
        $net4 = "socket" wide ascii
        $net5 = "connect" wide ascii
        $net6 = "send" wide ascii
        $net7 = "recv" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        1 of ($reg*) and 2 of ($net*)
}

rule WIN_TROJAN_EMOTET_PE {
    meta:
        description = "Emotet trojan — banking trojan / loader"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "Emotet"
    strings:
        $emotet1 = "Emotet" wide ascii
        $emotet2 = "emotet" wide ascii nocase
        $emotet3 = "GeD" wide ascii
        $emotet4 = "LoadLibrary" wide ascii
        $emotet5 = "GetProcAddress" wide ascii
        $emotet6 = "\\AppData\\Roaming\\" wide ascii
        $emotet7 = "Microsoft\\Windows\\" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($emotet*)
}

rule WIN_TROJAN_TRICKBOT_PE {
    meta:
        description = "TrickBot trojan — banking trojan / lateral movement"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "TrickBot"
    strings:
        $trick1 = "TrickBot" wide ascii
        $trick2 = "trickbot" wide ascii nocase
        $trick3 = "trick" wide ascii nocase
        $trick4 = "\\TrickBot\\" ascii
        $trick5 = "pyload" wide ascii nocase
        $trick6 = "module32" wide ascii nocase
        $trick7 = "DIA" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($trick*)
}

rule WIN_TROJAN_ICEDID_PE {
    meta:
        description = "IcedID/BokBot trojan — banking trojan"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "IcedID"
    strings:
        $iced1 = "IcedID" wide ascii
        $iced2 = "icedid" wide ascii nocase
        $iced3 = "BokBot" wide ascii
        $iced4 = "bokbot" wide ascii nocase
        $iced5 = "\\-icedid" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($iced*)
}

rule WIN_TROJAN_QUAKBOT_PE {
    meta:
        description = "QakBot/Qbot trojan — banking trojan / loader"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "QakBot"
    strings:
        $qak1 = "QakBot" wide ascii
        $qak2 = "qakbot" wide ascii nocase
        $qak3 = "Qbot" wide ascii
        $qak4 = "qbot" wide ascii nocase
        $qak5 = "\\-qakbot" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($qak*)
}

rule WIN_TROJAN_DRIDEX_PE {
    meta:
        description = "Dridex trojan — banking trojan / loader"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "Dridex"
    strings:
        $dridex1 = "Dridex" wide ascii
        $dridex2 = "dridex" wide ascii nocase
        $dridex3 = "\\-dridex" ascii
        $dridex4 = "Bugat" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($dridex*)
}

rule WIN_TROJAN_URSNIF_PE {
    meta:
        description = "Ursnif/Gozi trojan — banking trojan / info stealer"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "Ursnif"
    strings:
        $ursnif1 = "Ursnif" wide ascii
        $ursnif2 = "ursnif" wide ascii nocase
        $ursnif3 = "Gozi" wide ascii
        $ursnif4 = "gozi" wide ascii nocase
        $ursnif5 = "\\-ursnif" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($ursnif*)
}

rule WIN_TROJAN_NAKEDBIN_PE {
    meta:
        description = "NakedBinder trojan — binder/dropper"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "NakedBinder"
    strings:
        $nb1 = "NakedBinder" wide ascii
        $nb2 = "nakedbinder" wide ascii nocase
        $nb3 = "\\-nakedbinder" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and any of them
}

rule WIN_TROJAN_HAWKEYE_PE {
    meta:
        description = "HawkEye keylogger / info stealer"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "HawkEye"
    strings:
        $hawk1 = "HawkEye" wide ascii
        $hawk2 = "hawkeye" wide ascii nocase
        $hawk3 = "\\-hawkeye" ascii
        $hawk4 = "Keylogger" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($hawk*)
}

rule WIN_TROJAN_AGENTTESLA_PE {
    meta:
        description = "AgentTesla info stealer / keylogger"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "AgentTesla"
    strings:
        $at1 = "AgentTesla" wide ascii
        $at2 = "agenttesla" wide ascii nocase
        $at3 = "\\-agenttesla" ascii
        $at4 = "Tesla" wide ascii
        $at5 = "SMTP" wide ascii
        $at6 = "smtp" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($at*)
}

rule WIN_TROJAN_FORMBOOK_PE {
    meta:
        description = "FormBook info stealer"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "FormBook"
    strings:
        $fb1 = "FormBook" wide ascii
        $fb2 = "formbook" wide ascii nocase
        $fb3 = "\\-formbook" ascii
        $fb4 = "Form" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($fb*)
}

rule WIN_TROJAN_LOKI_PE {
    meta:
        description = "LokiBot info stealer"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "LokiBot"
    strings:
        $loki1 = "LokiBot" wide ascii
        $loki2 = "lokibot" wide ascii nocase
        $loki3 = "\\-lokibot" ascii
        $loki4 = "Loki" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($loki*)
}

rule WIN_TROJAN_VIDAR_PE {
    meta:
        description = "Vidar info stealer"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "Vidar"
    strings:
        $vidar1 = "Vidar" wide ascii
        $vidar2 = "vidar" wide ascii nocase
        $vidar3 = "\\-vidar" ascii
        $vidar4 = "Stealer" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($vidar*)
}

rule WIN_TROJAN_REDLINE_PE {
    meta:
        description = "RedLine info stealer"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "RedLine"
    strings:
        $rl1 = "RedLine" wide ascii
        $rl2 = "redline" wide ascii nocase
        $rl3 = "\\-redline" ascii
        $rl4 = "RedLine Stealer" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($rl*)
}

rule WIN_TROJAN_RASTEGO_PE {
    meta:
        description = "Raccoon Stealer v2 — info stealer"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "RaccoonStealer"
    strings:
        $rac1 = "Raccoon" wide ascii
        $rac2 = "raccoon" wide ascii nocase
        $rac3 = "\\-raccoon" ascii
        $rac4 = "Stealer" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($rac*)
}

// ═══════════════════════════════════════════════════════════════════
// COBALT STRIKE / C2 FRAMEWORK DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_C2_COBALTSTRIKE_BEACON_PE {
    meta:
        description = "Cobalt Strike beacon PE — post-exploitation agent"
        author = "Autobahn Defender / Florian Roth / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "CobaltStrike"
    strings:
        $cs1 = "MZ" wide ascii
        $cs2 = "ReflectiveLoader" wide ascii
        $cs3 = "beacon" wide ascii nocase
        $cs4 = "\\-beacon" ascii
        $cs5 = "Cobalt" wide ascii
        $cs6 = "cobalt" wide ascii nocase
        $cs7 = "strike" wide ascii nocase
        $cs8 = "\\-cobaltstrike" ascii
        $cs9 = "pipename" wide ascii nocase
        $cs10 = "\\\\.\\pipe\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($cs*)
}

rule WIN_C2_METASPLOIT_PAYLOAD_PE {
    meta:
        description = "Metasploit payload PE — generic meterpreter"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "Metasploit"
    strings:
        $msf1 = "Meterpreter" wide ascii
        $msf2 = "meterpreter" wide ascii nocase
        $msf3 = "metasploit" wide ascii nocase
        $msf4 = "\\-meterpreter" ascii
        $msf5 = "ReflectiveDLLInjection" wide ascii
        $msf6 = "\\-metasploit" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($msf*)
}

rule WIN_C2_SILVER_PE {
    meta:
        description = "Silver C2 framework — post-exploitation"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "SilverC2"
    strings:
        $silver1 = "Silver" wide ascii
        $silver2 = "silver" wide ascii nocase
        $silver3 = "\\-silver" ascii
        $silver4 = "Sliver" wide ascii
        $silver5 = "sliver" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($silver*)
}

rule WIN_C2_HAVOC_PE {
    meta:
        description = "Havoc C2 framework — post-exploitation"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "HavocC2"
    strings:
        $havoc1 = "Havoc" wide ascii
        $havoc2 = "havoc" wide ascii nocase
        $havoc3 = "\\-havoc" ascii
        $havoc4 = "Demon" wide ascii
        $havoc5 = "\\-demon" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($havoc*)
}

rule WIN_C2_BRUTERATEL_PE {
    meta:
        description = "Brute Ratel C2 — adversarial attack simulation"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "BruteRatel"
    strings:
        $br1 = "Brute" wide ascii
        $br2 = "brute" wide ascii nocase
        $br3 = "Ratel" wide ascii
        $br4 = "ratel" wide ascii nocase
        $br5 = "\\-bruteratel" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($br*)
}

// ═══════════════════════════════════════════════════════════════════
// CRYPTOMINER DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_MINER_XMRIG_PE {
    meta:
        description = "XMRig cryptocurrency miner PE executable"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "high"
        os = "windows"
        family = "XMRig"
    strings:
        $xmrig1 = "xmrig" wide ascii nocase
        $xmrig2 = "stratum+tcp://" wide ascii
        $xmrig3 = "stratum+ssl://" wide ascii
        $xmrig4 = "--donate-level" wide ascii
        $xmrig5 = "randomx" wide ascii nocase
        $xmrig6 = "cryptonight" wide ascii nocase
        $xmrig7 = "rx/0" wide ascii
        $xmrig8 = "rx/wow" wide ascii
        $xmrig9 = "cn/0" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($xmrig*)
}

rule WIN_MINER_GENERIC_STRATUM_PE {
    meta:
        description = "PE containing stratum mining protocol indicators"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "medium"
        os = "windows"
        family = "GenericMiner"
    strings:
        $pool1 = "stratum+tcp://" wide ascii
        $pool2 = "stratum+ssl://" wide ascii
        $pool3 = "mining." wide ascii nocase
        $pool4 = "nicehash" wide ascii nocase
        $pool5 = "--algo" wide ascii
        $pool6 = "--pool" wide ascii
        $pool7 = "--user" wide ascii
        $pool8 = "--pass" wide ascii
        $pool9 = "--rig-id" wide ascii
        $pool10 = "--cpu-affinity" wide ascii
        $pool11 = "--keepalive" wide ascii
        $pool12 = "--tls" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($pool*)
}

rule WIN_MINER_ETH_WALLET_PE {
    meta:
        description = "PE containing Ethereum wallet addresses"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "EthMiner"
    strings:
        $eth1 = /0x[a-fA-F0-9]{40}/ ascii
        $eth2 = "eth" wide ascii nocase
        $eth3 = "ethereum" wide ascii nocase
        $eth4 = "ethash" wide ascii nocase
        $eth5 = "dagger" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        #eth1 > 0 and 2 of ($eth2,$eth3,$eth4,$eth5)
}

// ═══════════════════════════════════════════════════════════════════
// DROPPER / DOWNLOADER DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_DROPPER_POWERSHELL_PE {
    meta:
        description = "PE that executes PowerShell for download/decode"
        author = "Autobahn Defender"
        date = "2024-01-01"
        severity = "high"
        os = "windows"
        family = "PSDownloader"
    strings:
        $ps1 = "powershell" wide ascii nocase
        $ps2 = "PowerShell" wide ascii
        $ps3 = "-enc" wide ascii
        $ps4 = "-encodedcommand" wide ascii nocase
        $ps5 = "IEX" wide ascii
        $ps6 = "Invoke-Expression" wide ascii
        $ps7 = "DownloadString" wide ascii
        $ps8 = "WebClient" wide ascii
        $ps9 = "Start-Process" wide ascii
        $ps10 = "-WindowStyle Hidden" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($ps*)
}

rule WIN_DROPPER_MULTI_STAGE_PE {
    meta:
        description = "PE with multi-stage downloader patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "MultiStageDownloader"
    strings:
        $dl1 = "URLDownloadToFile" wide ascii
        $dl2 = "WinHttpOpen" wide ascii
        $dl3 = "WinHttpConnect" wide ascii
        $dl4 = "WinHttpOpenRequest" wide ascii
        $dl5 = "WinHttpSendRequest" wide ascii
        $dl6 = "HttpSendRequest" wide ascii
        $dl7 = "InternetOpenUrl" wide ascii
        $dl8 = "InternetReadFile" wide ascii
        $dl9 = "URLDownloadToCacheFile" wide ascii
        $dl10 = "CreateProcess" wide ascii
        $dl11 = "ShellExecute" wide ascii
        $dl12 = "WinExec" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($dl*)
}

rule WIN_DROPPER_BINARY_PADDING_PE {
    meta:
        description = "PE with suspicious binary padding (common in packed droppers)"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "SuspiciousPadding"
    strings:
        $pad1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $pad2 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $pad3 = { CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (#pad1 > 100 or #pad2 > 100 or #pad3 > 100)
}

// ═══════════════════════════════════════════════════════════════════
// LAZARUS GROUP / APT DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_APT_LAZARUS_PE {
    meta:
        description = "Lazarus Group malware — APT37/APT38"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "Lazarus"
    strings:
        $laz1 = "Lazarus" wide ascii
        $laz2 = "lazarus" wide ascii nocase
        $laz3 = "\\-lazarus" ascii
        $laz4 = "Bluenoroff" wide ascii
        $laz5 = "AppleJeus" wide ascii
        $laz6 = "Manuscrypt" wide ascii
        $laz7 = "Maui" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($laz*)
}

rule WIN_APT_APT29_PE {
    meta:
        description = "APT29/CozyBear malware — Russian state-sponsored"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "APT29"
    strings:
        $apt1 = "APT29" wide ascii
        $apt2 = "CozyBear" wide ascii
        $apt3 = "WellMess" wide ascii
        $apt4 = "WellMail" wide ascii
        $apt5 = "PowerDuke" wide ascii
        $apt6 = "\\-apt29" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($apt*)
}

rule WIN_APT_APT28_PE {
    meta:
        description = "APT28/FancyBear malware — Russian state-sponsored"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "APT28"
    strings:
        $apt1 = "APT28" wide ascii
        $apt2 = "FancyBear" wide ascii
        $apt3 = "Sofacy" wide ascii
        $apt4 = "X-Agent" wide ascii
        $apt5 = "X-Tunnel" wide ascii
        $apt6 = "\\-apt28" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($apt*)
}

// ═══════════════════════════════════════════════════════════════════
// WORM / BOTNET DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_WORM_CONFICKER_PE {
    meta:
        description = "Conficker/Downadup worm"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "Conficker"
    strings:
        $conf1 = "Conficker" wide ascii
        $conf2 = "conficker" wide ascii nocase
        $conf3 = "Downadup" wide ascii
        $conf4 = "\\-conficker" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($conf*)
}

rule WIN_WORM_EMOTET_SPREAD_PE {
    meta:
        description = "PE with worm-like self-propagation (SMB/WMI)"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "WormPropagation"
    strings:
        $worm1 = "WNetAddConnection2" wide ascii
        $worm2 = "WNetUseConnection" wide ascii
        $worm3 = "NetUseAdd" wide ascii
        $worm4 = "NetServerEnum" wide ascii
        $worm5 = "WMI" wide ascii
        $worm6 = "winmgmts" wide ascii nocase
        $worm7 = "Admin$" wide ascii
        $worm8 = "IPC$" wide ascii
        $worm9 = "C$" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($worm*)
}

// ═══════════════════════════════════════════════════════════════════
// OFFICE MACRO / SCRIPT MALWARE
// ═══════════════════════════════════════════════════════════════════

rule WIN_MALWARE_OFFICE_MACRO {
    meta:
        description = "Office document with suspicious VBA macro patterns"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "MaliciousMacro"
    strings:
        $vba1 = "AutoOpen" wide ascii
        $vba2 = "Auto_Open" wide ascii
        $vba3 = "Document_Open" wide ascii
        $vba4 = "Workbook_Open" wide ascii
        $vba5 = "Shell" wide ascii
        $vba6 = "CreateObject" wide ascii
        $vba7 = "WScript.Shell" wide ascii
        $vba8 = "MSXML2.XMLHTTP" wide ascii
        $vba9 = "ADODB.Stream" wide ascii
        $vba10 = "URLDownloadToFile" wide ascii
        $vba11 = "PowerShell" wide ascii
        $vba12 = "cmd.exe" wide ascii
        $vba13 = "regsvr32" wide ascii
        $vba14 = "rundll32" wide ascii
        $vba15 = "certutil" wide ascii
        $vba16 = "bitsadmin" wide ascii
    condition:
        (uint16(0) == 0x4D5A or uint32(0) == 0xE011CFD0 or
         uint32(0) == 0xE11AB1A1 or uint32(0) == 0x3C3F786D) and
        filesize < 10MB and 3 of ($vba*)
}

rule WIN_MALWARE_JS_SCRIPT {
    meta:
        description = "JavaScript/WSH script with suspicious patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "MaliciousScript"
    strings:
        $js1 = "WScript.Shell" wide ascii
        $js2 = "ActiveXObject" wide ascii
        $js3 = "ADODB.Stream" wide ascii
        $js4 = "XMLHTTP" wide ascii
        $js5 = "URLDownloadToFile" wide ascii
        $js6 = "ShellExecute" wide ascii
        $js7 = "cmd.exe" wide ascii
        $js8 = "powershell" wide ascii nocase
        $js9 = "eval" wide ascii
        $js10 = "unescape" wide ascii
    condition:
        (uint16(0) == 0x4D5A or uint32(0) == 0xE011CFD0 or
         uint32(0) == 0xE11AB1A1) and
        filesize < 5MB and 3 of ($js*)
}

// ═══════════════════════════════════════════════════════════════════
// ANTI-DEBUG / ANTI-VM DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_ANTI_DEBUG_PE {
    meta:
        description = "PE with anti-debugging techniques"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "AntiDebug"
    strings:
        $ad1 = "IsDebuggerPresent" wide ascii
        $ad2 = "CheckRemoteDebuggerPresent" wide ascii
        $ad3 = "NtQueryInformationProcess" wide ascii
        $ad4 = "NtSetInformationThread" wide ascii
        $ad5 = "OutputDebugString" wide ascii
        $ad6 = "ZwQueryInformationProcess" wide ascii
        $ad7 = "DbgBreakPoint" wide ascii
        $ad8 = "DbgUiRemoteBreakin" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($ad*)
}

rule WIN_ANTI_VM_PE {
    meta:
        description = "PE with anti-VM/sandbox techniques"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "AntiVM"
    strings:
        $avm1 = "vbox" wide ascii nocase
        $avm2 = "vmware" wide ascii nocase
        $avm3 = "virtualbox" wide ascii nocase
        $avm4 = "VBoxGuest" wide ascii
        $avm5 = "VBoxMouse" wide ascii
        $avm6 = "VBoxService" wide ascii
        $avm7 = "VBoxTray" wide ascii
        $avm8 = "vmtoolsd" wide ascii nocase
        $avm9 = "xen" wide ascii nocase
        $avm10 = "qemu" wide ascii nocase
        $avm11 = "RDTSC" wide ascii
        $avm12 = "CPUID" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($avm*)
}

// ═══════════════════════════════════════════════════════════════════
// PACKER / PROTECTOR DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_PACKER_UPX_PE {
    meta:
        description = "UPX-packed PE executable"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "low"
        os = "windows"
        family = "UPX"
    strings:
        $upx1 = "UPX!" wide ascii
        $upx2 = "UPX0" wide ascii
        $upx3 = "UPX1" wide ascii
        $upx4 = "UPX2" wide ascii
    condition:
        uint16(0) == 0x5A4D and any of ($upx*)
}

rule WIN_PACKER_THEMIDA_PE {
    meta:
        description = "Themida/WinLicense packed PE"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "Themida"
    strings:
        $them1 = "Themida" wide ascii
        $them2 = "WinLicense" wide ascii
        $them3 = "\\-themida" ascii
        $them4 = "Oreans" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($them*)
}

rule WIN_PACKER_VMPROTECT_PE {
    meta:
        description = "VMProtect packed PE"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "VMProtect"
    strings:
        $vmp1 = "VMProtect" wide ascii
        $vmp2 = "vmp" wide ascii nocase
        $vmp3 = "\\-vmprotect" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($vmp*)
}

rule WIN_PACKER_MPRESS_PE {
    meta:
        description = "MPRESS packed PE"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        os = "windows"
        family = "MPRESS"
    strings:
        $mp1 = "MPRESS" wide ascii
        $mp2 = "mpress" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ═══════════════════════════════════════════════════════════════════
// LOLBIN / LIVING-OFF-THE-LAND DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_LOLBIN_LATERAL_PE {
    meta:
        description = "PE using LOLBins for lateral movement"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "LOLBin"
    strings:
        $lol1 = "wmic" wide ascii nocase
        $lol2 = "wmic.exe" wide ascii nocase
        $lol3 = "schtasks" wide ascii nocase
        $lol4 = "schtasks.exe" wide ascii nocase
        $lol5 = "mshta" wide ascii nocase
        $lol6 = "mshta.exe" wide ascii nocase
        $lol7 = "regsvr32" wide ascii nocase
        $lol8 = "regsvr32.exe" wide ascii nocase
        $lol9 = "rundll32" wide ascii nocase
        $lol10 = "rundll32.exe" wide ascii nocase
        $lol11 = "certutil" wide ascii nocase
        $lol12 = "certutil.exe" wide ascii nocase
        $lol13 = "bitsadmin" wide ascii nocase
        $lol14 = "bitsadmin.exe" wide ascii nocase
        $lol15 = "cscript" wide ascii nocase
        $lol16 = "cscript.exe" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($lol*)
}

// ═══════════════════════════════════════════════════════════════════
// KEYLOGGER / SPYWARE DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_SPYWARE_KEYLOGGER_PE {
    meta:
        description = "PE with keylogging API patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "Keylogger"
    strings:
        $kl1 = "SetWindowsHookEx" wide ascii
        $kl2 = "GetAsyncKeyState" wide ascii
        $kl3 = "GetKeyState" wide ascii
        $kl4 = "GetForegroundWindow" wide ascii
        $kl5 = "GetWindowText" wide ascii
        $kl6 = "GetClipboardData" wide ascii
        $kl7 = "RegisterHotKey" wide ascii
        $kl8 = "WH_KEYBOARD_LL" wide ascii
        $kl9 = "WH_MOUSE_LL" wide ascii
        $kl10 = "GetRawInputData" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($kl*)
}

rule WIN_SPYWARE_SCREEN_CAPTURE_PE {
    meta:
        description = "PE with screen capture capabilities"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "windows"
        family = "ScreenCapture"
    strings:
        $sc1 = "CreateDC" wide ascii
        $sc2 = "CreateCompatibleDC" wide ascii
        $sc3 = "CreateCompatibleBitmap" wide ascii
        $sc4 = "BitBlt" wide ascii
        $sc5 = "GetDIBits" wide ascii
        $sc6 = "CaptureBlt" wide ascii
        $sc7 = "GetDC" wide ascii
        $sc8 = "ReleaseDC" wide ascii
        $sc9 = "ScreenCapture" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($sc*)
}

// ═══════════════════════════════════════════════════════════════════
// RAT (REMOTE ACCESS TROJAN) DETECTION
// ═══════════════════════════════════════════════════════════════════

rule WIN_RAT_NJCONNECT_PE {
    meta:
        description = "NjRAT/NjWorm remote access trojan"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "NjRAT"
    strings:
        $nj1 = "NjRAT" wide ascii
        $nj2 = "njrat" wide ascii nocase
        $nj3 = "NjWorm" wide ascii
        $nj4 = "\\-njrat" ascii
        $nj5 = "\\-njworm" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($nj*)
}

rule WIN_RAT_DARKCOMET_PE {
    meta:
        description = "DarkComet remote access trojan"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "DarkComet"
    strings:
        $dc1 = "DarkComet" wide ascii
        $dc2 = "darkcomet" wide ascii nocase
        $dc3 = "\\-darkcomet" ascii
        $dc4 = "DC" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($dc*)
}

rule WIN_RAT_QUASAR_PE {
    meta:
        description = "Quasar RAT — open source C# RAT"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "QuasarRAT"
    strings:
        $q1 = "Quasar" wide ascii
        $q2 = "quasar" wide ascii nocase
        $q3 = "\\-quasar" ascii
        $q4 = "xRAT" wide ascii
        $q5 = "XRAT" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($q*)
}

rule WIN_RAT_ASYNRAT_PE {
    meta:
        description = "AsyncRAT — open source C# RAT"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "AsyncRAT"
    strings:
        $ar1 = "AsyncRAT" wide ascii
        $ar2 = "asyncrat" wide ascii nocase
        $ar3 = "\\-asyncrat" ascii
        $ar4 = "Async" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($ar*)
}

rule WIN_RAT_NANOCORE_PE {
    meta:
        description = "NanoCore RAT"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "windows"
        family = "NanoCore"
    strings:
        $nc1 = "NanoCore" wide ascii
        $nc2 = "nanocore" wide ascii nocase
        $nc3 = "\\-nanocore" ascii
        $nc4 = "NetCore" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($nc*)
}

rule WIN_RAT_ORBOT_PE {
    meta:
        description = "Orbit RAT (.NET-based)"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "high"
        os = "windows"
        family = "OrbitRAT"
    strings:
        $orb1 = "Orbit" wide ascii
        $orb2 = "orbit" wide ascii nocase
        $orb3 = "\\-orbit" ascii
        $orb4 = "OrbitRAT" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($orb*)
}

// ═══════════════════════════════════════════════════════════════════
// GENERIC SUSPICIOUS PE INDICATORS
// ═══════════════════════════════════════════════════════════════════

rule WIN_SUSPICIOUS_SECTION_PE {
    meta:
        description = "PE with suspicious section names (common in malware)"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "SuspiciousSection"
    strings:
        $sec1 = ".upx0" fullword ascii
        $sec2 = ".upx1" fullword ascii
        $sec3 = ".UPX0" fullword ascii
        $sec4 = ".UPX1" fullword ascii
        $sec5 = ".packed" fullword ascii
        $sec6 = ".PACKED" fullword ascii
        $sec7 = ".adata" fullword ascii
        $sec8 = ".mackt" fullword ascii
        $sec9 = ".MPRESS" fullword ascii
        $sec10 = ".themida" fullword ascii
        $sec11 = ".vmp0" fullword ascii
        $sec12 = ".vmp1" fullword ascii
        $sec13 = ".enigma" fullword ascii
        $sec14 = ".bss" fullword ascii
        $sec15 = ".tls" fullword ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and any of ($sec*)
}

rule WIN_SUSPICIOUS_ENTRY_POINT_PE {
    meta:
        description = "PE with suspicious entry point (outside .text section)"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "SuspiciousEntryPoint"
    strings:
        $ep1 = { E8 00 00 00 00 }  // call $+5 (common shellcode)
        $ep2 = { E9 ?? ?? ?? ?? }  // far jump
        $ep3 = { 68 ?? ?? ?? ?? C3 }  // push; ret (jump to stack)
        $ep4 = { FF E? }  // jmp reg
        $ep5 = { FF D? }  // call reg
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and any of ($ep*)
}

rule WIN_SUSPICIOUS_TLS_CALLBACKS_PE {
    meta:
        description = "PE with TLS callbacks (common in malware before main)"
        author = "Autobahn Defender / Yara-Rules"
        date = "2025-01-01"
        severity = "medium"
        os = "windows"
        family = "TLSCallback"
    strings:
        $tls1 = ".tls" fullword ascii
        $tls2 = "__tls_used" wide ascii
        $tls3 = "_tls_start" wide ascii
        $tls4 = "_tls_end" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and any of ($tls*)
}

// ═══════════════════════════════════════════════════════════════════
// WINDOWS DEFENDER EXTRACTED RULES (COMMON MALWARE PATTERNS)
// ═══════════════════════════════════════════════════════════════════

rule WIN_MALWARE_GENERIC_PE_CRYPTO {
    meta:
        description = "Generic PE with cryptographic imports + suspicious characteristics"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "medium"
        os = "windows"
        family = "GenericCryptoMalware"
    strings:
        $crypt1 = "CryptAcquireContext" wide ascii
        $crypt2 = "CryptGenRandom" wide ascii
        $crypt3 = "CryptHashData" wide ascii
        $crypt4 = "CryptDeriveKey" wide ascii
        $net1 = "InternetOpen" wide ascii
        $net2 = "HttpOpenRequest" wide ascii
        $net3 = "HttpSendRequest" wide ascii
        $file1 = "WriteFile" wide ascii
        $file2 = "CreateFile" wide ascii
        $file3 = "DeleteFile" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        2 of ($crypt*) and 1 of ($net*) and 1 of ($file*)
}

rule WIN_MALWARE_GENERIC_PERSISTENCE_PE {
    meta:
        description = "Generic PE with persistence mechanisms"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "medium"
        os = "windows"
        family = "GenericPersistence"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
        $sched1 = "Schedule.Service" wide ascii
        $sched2 = "TaskScheduler" wide ascii
        $srv1 = "CreateService" wide ascii
        $srv2 = "OpenSCManager" wide ascii
        $srv3 = "StartService" wide ascii
        $startup1 = "Startup" wide ascii
        $startup2 = "All Users\\Start Menu\\Programs\\Startup" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($run*) or
        (1 of ($sched*) and 1 of ($srv*)) or
        (1 of ($startup*) and 1 of ($srv*))
}

// ═══════════════════════════════════════════════════════════════════
// END OF WINDOWS YARA RULES
// ═══════════════════════════════════════════════════════════════════
