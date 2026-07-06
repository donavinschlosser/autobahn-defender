/*
 * Autobahn Defender — macOS Malware YARA Rules
 *
 * Comprehensive rules for detecting malicious macOS software (Mach-O binaries,
 * AppleScript, shell scripts, and other macOS-specific threats).
 *
 * These rules are designed to be used when scanning:
 *   - macOS drives mounted on Linux (external drives, DMG files)
 *   - Files shared from macOS systems over SMB/NFS
 *   - Downloads that may contain macOS malware
 *   - Cross-platform files that may target macOS
 *
 * Sources:
 *   - Objective-See malware collection
 *   - Elastic Security protections-artifacts (macOS rules)
 *   - Florian Roth signature-base (macOS rules)
 *   - SentinelOne macOS threat research
 *   - ReversingLabs macOS YARA evaluation
 *   - Apple XProtect YARA rules (reversed/adapted)
 *   - Airbnb BinaryAlert macOS rules
 *   - Yara-Rules/rules community repository
 *   - Custom rules for emerging threats
 *
 * IMPORTANT: All Mach-O rules include magic byte checks
 * (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
 *  uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
 *  uint32(0) == 0xBEBAFECA) to prevent false positives on non-Mach-O files.
 *
 * This file is DISABLED by default and must be enabled in Settings.
 *
 * Last updated: July 2026
 */

// ═══════════════════════════════════════════════════════════════════
// ADWARE / PUP DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_ADWARE_BUNDLORE_GEN {
    meta:
        description = "Bundlore adware — installer bundler malware family"
        author = "Autobahn Defender / Objective-See / ReversingLabs"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "Bundlore"
    strings:
        $bundle1 = "Bundlore" wide ascii
        $bundle2 = "bundlore" wide ascii nocase
        $bundle3 = "\\-bundlore" ascii
        $bundle4 = "installer" wide ascii nocase
        $bundle5 = "adware" wide ascii nocase
        $bundle6 = "sponsored" wide ascii nocase
        $bundle7 = "installmac" wide ascii nocase
        $bundle8 = "InstallMac" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 20MB and 2 of ($bundle*)
}

rule MAC_ADWARE_SHLYER_GEN {
    meta:
        description = "Shlayer adware — dropper/downloader malware"
        author = "Autobahn Defender / Objective-See / Uptycs"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "Shlayer"
    strings:
        $sh1 = "Shlayer" wide ascii
        $sh2 = "shlayer" wide ascii nocase
        $sh3 = "\\-shlayer" ascii
        $sh4 = "shl" wide ascii nocase
        $sh5 = "adware" wide ascii nocase
        $sh6 = "download" wide ascii nocase
        $sh7 = "install" wide ascii nocase
        $sh8 = "DMG" wide ascii
        $sh9 = "dmg" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 20MB and 2 of ($sh*)
}

rule MAC_ADWARE_PIRRIT_GEN {
    meta:
        description = "Pirrit adware — persistent adware family"
        author = "Autobahn Defender / Apple XProtect / Cybereason"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "Pirrit"
    strings:
        $pir1 = "Pirrit" wide ascii
        $pir2 = "pirrit" wide ascii nocase
        $pir3 = "\\-pirrit" ascii
        $pir4 = "VSearch" wide ascii
        $pir5 = "vsearch" wide ascii nocase
        $pir6 = "adload" wide ascii nocase
        $pir7 = "AdLoad" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 20MB and 2 of ($pir*)
}

rule MAC_ADWARE_ADLOAD_GEN {
    meta:
        description = "AdLoad adware — widespread macOS adware family"
        author = "Autobahn Defender / Objective-See"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "AdLoad"
    strings:
        $al1 = "AdLoad" wide ascii
        $al2 = "adload" wide ascii nocase
        $al3 = "\\-adload" ascii
        $al4 = "adware" wide ascii nocase
        $al5 = "Adware" wide ascii
        $al6 = "genieo" wide ascii nocase
        $al7 = "Genieo" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 20MB and 2 of ($al*)
}

rule MAC_ADWARE_GENIEO_GEN {
    meta:
        description = "Genieo adware — browser hijacker"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "Genieo"
    strings:
        $gen1 = "Genieo" wide ascii
        $gen2 = "genieo" wide ascii nocase
        $gen3 = "\\-genieo" ascii
        $gen4 = "browser" wide ascii nocase
        $gen5 = "homepage" wide ascii nocase
        $gen6 = "search" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 20MB and 2 of ($gen*)
}

rule MAC_ADWARE_MACKEEPER_PUA {
    meta:
        description = "MacKeeper PUP — potentially unwanted program"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        os = "macos"
        family = "MacKeeper"
    strings:
        $mk1 = "MacKeeper" wide ascii
        $mk2 = "mackeeper" wide ascii nocase
        $mk3 = "\\-mackeeper" ascii
        $mk4 = "Keeper" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 50MB and 2 of ($mk*)
}

rule MAC_ADWARE_ADWARE_ANALYTICS_GEN {
    meta:
        description = "Generic adware analytics/tracking library"
        author = "Autobahn Defender"
        date = "2025-06-01"
        severity = "low"
        os = "macos"
        family = "AdwareAnalytics"
    strings:
        $aa1 = "adware" wide ascii nocase
        $aa2 = "Adware" wide ascii
        $aa3 = "tracking" wide ascii nocase
        $aa4 = "analytics" wide ascii nocase
        $aa5 = "sponsored" wide ascii nocase
        $aa6 = "adnetwork" wide ascii nocase
        $aa7 = "advertising" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 3 of ($aa*)
}

// ═══════════════════════════════════════════════════════════════════
// BACKDOOR / RAT DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_BACKDOOR_PROTON_RAT_GEN {
    meta:
        description = "Proton RAT — macOS remote access trojan"
        author = "Autobahn Defender / Airbnb BinaryAlert"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "ProtonRAT"
    strings:
        $pro1 = "Proton" wide ascii
        $pro2 = "proton" wide ascii nocase
        $pro3 = "\\-proton" ascii
        $pro4 = "RAT" wide ascii
        $pro5 = "rat" wide ascii nocase
        $pro6 = "backdoor" wide ascii nocase
        $pro7 = "remote" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($pro*)
}

rule MAC_BACKDOOR_OSACRIPT_RAT {
    meta:
        description = "macOS backdoor using AppleScript for persistence"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "AppleScriptBackdoor"
    strings:
        $as1 = "osascript" wide ascii nocase
        $as2 = "AppleScript" wide ascii
        $as3 = "applescript" wide ascii nocase
        $as4 = "do shell script" wide ascii nocase
        $as5 = "tell application" wide ascii nocase
        $as6 = "System Events" wide ascii
        $as7 = "launchd" wide ascii nocase
        $as8 = "LaunchAgents" wide ascii
        $as9 = "LaunchDaemons" wide ascii
        $as10 = "plist" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($as*)
}

rule MAC_BACKDOOR_EMPYRE_GEN {
    meta:
        description = "Empyre macOS backdoor — Python-based post-exploitation"
        author = "Autobahn Defender / Florian Roth"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "Empyre"
    strings:
        $emp1 = "Empyre" wide ascii
        $emp2 = "empyre" wide ascii nocase
        $emp3 = "\\-empyre" ascii
        $emp4 = "python" wide ascii nocase
        $emp5 = "agent" wide ascii nocase
        $emp6 = "implant" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($emp*)
}

rule MAC_BACKDOOR_AVAST_GEN {
    meta:
        description = "Avast/AV backdoor impersonation malware"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "FakeAV"
    strings:
        $fav1 = "Avast" wide ascii
        $fav2 = "avast" wide ascii nocase
        $fav3 = "antivirus" wide ascii nocase
        $fav4 = "security" wide ascii nocase
        $fav5 = "scan" wide ascii nocase
        $fav6 = "threat" wide ascii nocase
        $fav7 = "malware" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 3 of ($fav*)
}

rule MAC_BACKDOOR_GASLIGHT_GEN {
    meta:
        description = "Gaslight macOS backdoor — Rust-based with prompt injection"
        author = "Autobahn Defender / SentinelOne"
        date = "2026-06-01"
        severity = "critical"
        os = "macos"
        family = "Gaslight"
    strings:
        $gas1 = "Gaslight" wide ascii
        $gas2 = "gaslight" wide ascii nocase
        $gas3 = "\\-gaslight" ascii
        $gas4 = "rust" wide ascii nocase
        $gas5 = "rust_std" ascii
        $gas6 = "rust_panic" ascii
        $gas7 = "prompt" wide ascii nocase
        $gas8 = "injection" wide ascii nocase
        $gas9 = "implant" wide ascii nocase
        $gas10 = "infostealer" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($gas*)
}

// ═══════════════════════════════════════════════════════════════════
// TROJAN / DOWNLOADER DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_TROJAN_DOWNLOADER_GEN {
    meta:
        description = "Generic macOS trojan downloader"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "TrojanDownloader"
    strings:
        $dl1 = "curl" wide ascii nocase
        $dl2 = "wget" wide ascii nocase
        $dl3 = "download" wide ascii nocase
        $dl4 = "URL" wide ascii
        $dl5 = "http" wide ascii nocase
        $dl6 = "https" wide ascii nocase
        $dl7 = "chmod" wide ascii nocase
        $dl8 = "+x" wide ascii
        $dl9 = "exec" wide ascii nocase
        $dl10 = "open" wide ascii nocase
        $dl11 = "sudo" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($dl*)
}

rule MAC_TROJAN_WIZARDUPDATE_GEN {
    meta:
        description = "WizardUpdate macOS trojan — fake Flash updater"
        author = "Autobahn Defender / Intego"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "WizardUpdate"
    strings:
        $wiz1 = "WizardUpdate" wide ascii
        $wiz2 = "wizardupdate" wide ascii nocase
        $wiz3 = "\\-wizardupdate" ascii
        $wiz4 = "Flash" wide ascii
        $wiz5 = "flash" wide ascii nocase
        $wiz6 = "update" wide ascii nocase
        $wiz7 = "player" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($wiz*)
}

rule MAC_TROJAN_LAZARUS_GEN {
    meta:
        description = "Lazarus Group macOS malware — Dacls/UnionCrypto"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "LazarusMacOS"
    strings:
        $laz1 = "Lazarus" wide ascii
        $laz2 = "lazarus" wide ascii nocase
        $laz3 = "\\-lazarus" ascii
        $laz4 = "Dacls" wide ascii
        $laz5 = "dacls" wide ascii nocase
        $laz6 = "UnionCrypto" wide ascii
        $laz7 = "unioncrypto" wide ascii nocase
        $laz8 = "macOS" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($laz*)
}

rule MAC_TROJAN_XCSSET_GEN {
    meta:
        description = "XCSSET macOS trojan — Xcode project infector"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "XCSSET"
    strings:
        $xc1 = "XCSSET" wide ascii
        $xc2 = "xcsset" wide ascii nocase
        $xc3 = "\\-xcsset" ascii
        $xc4 = "Xcode" wide ascii
        $xc5 = "xcode" wide ascii nocase
        $xc6 = "project" wide ascii nocase
        $xc7 = "swift" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($xc*)
}

rule MAC_TROJAN_SILVER_SPARROW_GEN {
    meta:
        description = "Silver Sparrow macOS malware — M1-native payload"
        author = "Autobahn Defender / SentinelOne / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "SilverSparrow"
    strings:
        $ss1 = "Silver" wide ascii
        $ss2 = "silver" wide ascii nocase
        $ss3 = "Sparrow" wide ascii
        $ss4 = "sparrow" wide ascii nocase
        $ss5 = "\\-silversparrow" ascii
        $ss6 = "M1" wide ascii
        $ss7 = "arm64" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($ss*)
}

// ═══════════════════════════════════════════════════════════════════
// CRYPTOMINER DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_MINER_XMRIG_GEN {
    meta:
        description = "XMRig cryptocurrency miner (macOS variant)"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "XMRigMacOS"
    strings:
        $xmrig1 = "xmrig" wide ascii nocase
        $xmrig2 = "stratum+tcp://" wide ascii
        $xmrig3 = "stratum+ssl://" wide ascii
        $xmrig4 = "--donate-level" wide ascii
        $xmrig5 = "randomx" wide ascii nocase
        $xmrig6 = "cryptonight" wide ascii nocase
        $xmrig7 = "rx/0" wide ascii
        $xmrig8 = "cn/0" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 2 of ($xmrig*)
}

rule MAC_MINER_GENERIC_STRATUM_GEN {
    meta:
        description = "Mach-O containing stratum mining protocol indicators"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "GenericMinerMacOS"
    strings:
        $pool1 = "stratum+tcp://" wide ascii
        $pool2 = "stratum+ssl://" wide ascii
        $pool3 = "mining." wide ascii nocase
        $pool4 = "nicehash" wide ascii nocase
        $pool5 = "--algo" wide ascii
        $pool6 = "--pool" wide ascii
        $pool7 = "--user" wide ascii
        $pool8 = "--rig-id" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($pool*)
}

// ═══════════════════════════════════════════════════════════════════
// PERSISTENCE / LAUNCH AGENT DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_PERSISTENCE_LAUNCH_AGENT_GEN {
    meta:
        description = "Mach-O with LaunchAgent/LaunchDaemon persistence"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "LaunchAgentPersistence"
    strings:
        $la1 = "LaunchAgents" wide ascii
        $la2 = "LaunchDaemons" wide ascii
        $la3 = "launchctl" wide ascii nocase
        $la4 = "plist" wide ascii nocase
        $la5 = "KeepAlive" wide ascii
        $la6 = "RunAtLoad" wide ascii
        $la7 = "ProgramArguments" wide ascii
        $la8 = "Label" wide ascii
        $la9 = "com.apple" wide ascii nocase
        $la10 = "com.startup" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($la*)
}

rule MAC_PERSISTENCE_CRONJOB_GEN {
    meta:
        description = "Mach-O with cron-based persistence"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "CronPersistence"
    strings:
        $cron1 = "crontab" wide ascii nocase
        $cron2 = "cron" wide ascii nocase
        $cron3 = "*/" wide ascii
        $cron4 = "* * * *" wide ascii
        $cron5 = "anacron" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 2 of ($cron*)
}

rule MAC_PERSISTENCE_LOGIN_ITEM_GEN {
    meta:
        description = "Mach-O with Login Item persistence"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "LoginItemPersistence"
    strings:
        $li1 = "LoginItems" wide ascii
        $li2 = "login item" wide ascii nocase
        $li3 = "LSSharedFileList" wide ascii
        $li4 = "LoginWindow" wide ascii
        $li5 = "com.apple.loginitems" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 2 of ($li*)
}

// ═══════════════════════════════════════════════════════════════════
// INFO STEALER DETECTION
// ═══════════════════════════════════════════════════════════════════

rule MAC_STEALER_KEYCHAIN_GEN {
    meta:
        description = "Mach-O with Keychain access patterns (info stealer)"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "critical"
        os = "macos"
        family = "KeychainStealer"
    strings:
        $kc1 = "SecKeychain" wide ascii
        $kc2 = "SecKeychainFindGenericPassword" wide ascii
        $kc3 = "SecKeychainItemCopyContent" wide ascii
        $kc4 = "SecKeychainUnlock" wide ascii
        $kc5 = "kSecMatchLimit" wide ascii
        $kc6 = "kSecClass" wide ascii
        $kc7 = "kSecReturnData" wide ascii
        $kc8 = "keychain" wide ascii nocase
        $kc9 = "password" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($kc*)
}

rule MAC_STEALER_BROWSER_DATA_GEN {
    meta:
        description = "Mach-O with browser data theft patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "BrowserStealer"
    strings:
        $br1 = "Cookies" wide ascii
        $br2 = "cookies" wide ascii nocase
        $br3 = "Login Data" wide ascii
        $br4 = "Web Data" wide ascii
        $br5 = "Bookmarks" wide ascii
        $br6 = "History" wide ascii
        $br7 = "Safari" wide ascii
        $br8 = "Chrome" wide ascii
        $br9 = "Firefox" wide ascii
        $br10 = "profiles" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($br*)
}

rule MAC_STEALER_SCREEN_CAPTURE_GEN {
    meta:
        description = "Mach-O with screen capture capabilities"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "ScreenCaptureMacOS"
    strings:
        $sc1 = "CGDisplay" wide ascii
        $sc2 = "CGImage" wide ascii
        $sc3 = "CGScreen" wide ascii
        $sc4 = "screencapture" wide ascii nocase
        $sc5 = "SCREENSHOT" wide ascii
        $sc6 = "screenshot" wide ascii nocase
        $sc7 = "display" wide ascii nocase
        $sc8 = "capture" wide ascii nocase
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 5MB and 3 of ($sc*)
}

// ═══════════════════════════════════════════════════════════════════
// SHELL SCRIPT / PYTHON MALWARE
// ═══════════════════════════════════════════════════════════════════

rule MAC_SCRIPT_SHELL_BACKDOOR {
    meta:
        description = "Shell script with backdoor/persistence patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "ShellBackdoor"
    strings:
        $sh1 = "#!/bin/bash" ascii
        $sh2 = "#!/bin/sh" ascii
        $sh3 = "curl" wide ascii nocase
        $sh4 = "wget" wide ascii nocase
        $sh5 = "chmod +x" wide ascii
        $sh6 = "sudo" wide ascii nocase
        $sh7 = "launchctl" wide ascii nocase
        $sh8 = "plist" wide ascii nocase
        $sh9 = "crontab" wide ascii nocase
        $sh10 = "nohup" wide ascii nocase
        $sh11 = "disown" wide ascii nocase
        $sh12 = "&>" wide ascii
        $sh13 = ">/dev/null" wide ascii
        $sh14 = "2>&1" wide ascii
    condition:
        ($sh1 or $sh2) and filesize < 1MB and 3 of ($sh3,$sh4,$sh5,$sh6,$sh7,$sh8,$sh9,$sh10,$sh11,$sh12,$sh13,$sh14)
}

rule MAC_SCRIPT_PYTHON_BACKDOOR {
    meta:
        description = "Python script with macOS backdoor patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        os = "macos"
        family = "PythonBackdoor"
    strings:
        $py1 = "#!/usr/bin/python" ascii
        $py2 = "#!/usr/bin/env python" ascii
        $py3 = "os.system" wide ascii
        $py4 = "subprocess" wide ascii
        $py5 = "urllib" wide ascii
        $py6 = "requests" wide ascii
        $py7 = "socket" wide ascii
        $py8 = "base64" wide ascii
        $py9 = "b64decode" wide ascii
        $py10 = "eval" wide ascii
        $py11 = "exec" wide ascii
        $py12 = "compile" wide ascii
        $py13 = "__import__" wide ascii
    condition:
        ($py1 or $py2) and filesize < 1MB and 3 of ($py3,$py4,$py5,$py6,$py7,$py8,$py9,$py10,$py11,$py12,$py13)
}

// ═══════════════════════════════════════════════════════════════════
// DMG / INSTALLER MALWARE
// ═══════════════════════════════════════════════════════════════════

rule MAC_DMG_SUSPICIOUS_INSTALLER {
    meta:
        description = "Suspicious DMG installer with malware patterns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "SuspiciousDMG"
    strings:
        $dmg1 = "koly" ascii  // DMG signature
        $dmg2 = "Install" wide ascii nocase
        $dmg3 = "Setup" wide ascii nocase
        $dmg4 = "Application" wide ascii
        $dmg5 = "Drag" wide ascii
        $dmg6 = "copy" wide ascii nocase
        $dmg7 = "Applications" wide ascii
    condition:
        $dmg1 and filesize < 500MB and 2 of ($dmg2,$dmg3,$dmg4,$dmg5,$dmg6,$dmg7)
}

// ═══════════════════════════════════════════════════════════════════
// GENERIC SUSPICIOUS MACH-O INDICATORS
// ═══════════════════════════════════════════════════════════════════

rule MAC_SUSPICIOUS_ENTITLEMENTS_GEN {
    meta:
        description = "Mach-O with suspicious entitlements (privacy violation)"
        author = "Autobahn Defender / Elastic Security"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "SuspiciousEntitlements"
    strings:
        $ent1 = "com.apple.security.cs.disable-library-validation" wide ascii
        $ent2 = "com.apple.security.cs.allow-dyld-environment-variables" wide ascii
        $ent3 = "com.apple.security.cs.allow-unsigned-executable-memory" wide ascii
        $ent4 = "com.apple.security.device.audio-input" wide ascii
        $ent5 = "com.apple.security.device.camera" wide ascii
        $ent6 = "com.apple.private.tcc.allow" wide ascii
        $ent7 = "kTCCService" wide ascii
        $ent8 = "kTCCServiceAll" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and 2 of ($ent*)
}

rule MAC_SUSPICIOUS_UPX_PACKED_GEN {
    meta:
        description = "UPX-packed Mach-O executable"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        os = "macos"
        family = "UPXPackedMacOS"
    strings:
        $upx1 = "UPX!" wide ascii
        $upx2 = "UPX0" wide ascii
        $upx3 = "UPX1" wide ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and any of ($upx*)
}

rule MAC_SUSPICIOUS_OBFUSCATED_STRINGS_GEN {
    meta:
        description = "Mach-O with obfuscated string patterns (common in malware)"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        os = "macos"
        family = "ObfuscatedStrings"
    strings:
        $obs1 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii  // Base64 long strings
        $obs2 = /\\$[0-9a-fA-F]{8,}/ ascii  // Hex-encoded strings
        $obs3 = /%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}/ ascii  // URL-encoded
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or
         uint32(0) == 0xBEBAFECA) and filesize < 10MB and
        (#obs1 > 5 or #obs2 > 5 or #obs3 > 5)
}

// ═══════════════════════════════════════════════════════════════════
// END OF MACOS YARA RULES
// ═══════════════════════════════════════════════════════════════════
