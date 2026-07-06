/*
 * Autobahn Defender — PUP (Potentially Unwanted Programs) Detection Rules
 *
 * Cross-platform rules for detecting potentially unwanted applications.
 * These are programs that users typically don't want on their systems:
 *   - Subpar/unwanted antivirus software (often pre-bundled on new PCs)
 *   - Adware and browser hijackers
 *   - Cryptominers (cross-platform)
 *   - Scamware and fake system optimizers
 *   - Bundled junkware and toolbars
 *   - Aggressive tracking software
 *   - Fake cleaners and registry cleaners
 *
 * These rules are PLATFORM AGNOSTIC — they look for application names,
 * executable names, file paths, and other identifiers that are common
 * across Windows, Linux, and macOS.
 *
 * IMPORTANT: This file is ENABLED BY DEFAULT on first install/launch.
 * Users can disable it in Settings > YARA Rules if they wish.
 * The goal is to protect new and inexperienced users from unwanted
 * software that may be bundled or pre-installed on their systems.
 *
 * Sources:
 *   - Malwarebytes PUP classification database
 *   - Common bloatware lists from PC manufacturers
 *   - Known PUP/adware family names
 *   - Industry-standard PUP detection criteria
 *   - Community-reported unwanted software
 *
 * Last updated: July 2026
 */

// ═══════════════════════════════════════════════════════════════════
// UNWANTED / SUBPAR ANTIVIRUS SOFTWARE
// These are antivirus programs that are commonly pre-bundled on new
// PCs, difficult to remove, provide poor protection, or are known
// for aggressive advertising and upsell tactics.
// ═══════════════════════════════════════════════════════════════════

rule PUP_AV_MCAFEE {
    meta:
        description = "McAfee antivirus — commonly pre-bundled, difficult to remove, aggressive upsell"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $mc1 = "McAfee" wide ascii nocase
        $mc2 = "mcafee" wide ascii nocase
        $mc3 = "MCAFEE" wide ascii
        $mc4 = "mcafee. com" wide ascii nocase
        $mc5 = "mcafee.com" wide ascii nocase
        $mc6 = "McAfee Total Protection" wide ascii nocase
        $mc7 = "McAfee LiveSafe" wide ascii nocase
        $mc8 = "McAfee Security" wide ascii nocase
        $mc9 = "McAfee AntiVirus" wide ascii nocase
        $mc10 = "McAfee Internet Security" wide ascii nocase
        $mc11 = "McAfee WebAdvisor" wide ascii nocase
        $mc12 = "McAfee TrueKey" wide ascii nocase
        $mc13 = "MCLIENT" wide ascii
        $mc14 = "McSvHost" wide ascii
        $mc15 = "McAP.exe" wide ascii nocase
        $mc16 = "McTray.exe" wide ascii nocase
        $mc17 = "McPlat.exe" wide ascii nocase
        $mc18 = "FrameworkService.exe" wide ascii nocase
        $mc19 = "mfevtps.exe" wide ascii nocase
        $mc20 = "mfehidin" ascii
        $mc21 = "mfeaskm" ascii
        $mc22 = "mfewc" ascii
        $mc23 = "mfe" wide ascii
    condition:
        any of ($mc*)
}

rule PUP_AV_NORTON {
    meta:
        description = "Norton 360/AntiVirus — pre-bundled, resource-heavy, aggressive renewal tactics"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $n1 = "Norton" wide ascii nocase
        $n2 = "norton" wide ascii nocase
        $n3 = "NORTON" wide ascii
        $n4 = "Norton 360" wide ascii nocase
        $n5 = "Norton AntiVirus" wide ascii nocase
        $n6 = "Norton Internet Security" wide ascii nocase
        $n7 = "Norton Security" wide ascii nocase
        $n8 = "NortonLifeLock" wide ascii nocase
        $n9 = "Norton Power Eraser" wide ascii nocase
        $n10 = "Norton Safe Web" wide ascii nocase
        $n11 = "Norton Secure VPN" wide ascii nocase
        $n12 = "Symantec" wide ascii nocase
        $n13 = "symantec" wide ascii nocase
        $n14 = "NSBU" wide ascii
        $n15 = "N360" wide ascii
        $n16 = "nav.exe" wide ascii nocase
        $n17 = "norton.exe" wide ascii nocase
        $n18 = "ccSvcHst.exe" wide ascii nocase
        $n19 = "ccSetMgr.exe" wide ascii nocase
        $n20 = "ccApp.exe" wide ascii nocase
        $n21 = "NortonSecurity.exe" wide ascii nocase
    condition:
        any of ($n*)
}

rule PUP_AV_AVAST {
    meta:
        description = "Avast antivirus — aggressive ads, data collection concerns, bundled installs"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $a1 = "Avast" wide ascii nocase
        $a2 = "avast" wide ascii nocase
        $a3 = "AVAST" wide ascii
        $a4 = "Avast Free Antivirus" wide ascii nocase
        $a5 = "Avast Premium Security" wide ascii nocase
        $a6 = "Avast Internet Security" wide ascii nocase
        $a7 = "Avast SecureLine VPN" wide ascii nocase
        $a8 = "Avast Cleanup" wide ascii nocase
        $a9 = "Avast Secure Browser" wide ascii nocase
        $a10 = "Avast Passwords" wide ascii nocase
        $a11 = "AvastSvc.exe" wide ascii nocase
        $a12 = "AvastUI.exe" wide ascii nocase
        $a13 = "AvastBrowser.exe" wide ascii nocase
        $a14 = "asw" wide ascii
        $a15 = "aswSP" wide ascii
        $a16 = "aswEng" wide ascii
        $a17 = "aswArPot" wide ascii
        $a18 = "Avast Software" wide ascii nocase
    condition:
        any of ($a*)
}

rule PUP_AV_AVG {
    meta:
        description = "AVG antivirus — owned by Avast, similar aggressive tactics"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $avg1 = "AVG" wide ascii
        $avg2 = "avg" wide ascii nocase
        $avg3 = "AVG AntiVirus" wide ascii nocase
        $avg4 = "AVG Internet Security" wide ascii nocase
        $avg5 = "AVG Secure VPN" wide ascii nocase
        $avg6 = "AVG TuneUp" wide ascii nocase
        $avg7 = "AVG Driver Updater" wide ascii nocase
        $avg8 = "AVG PC TuneUp" wide ascii nocase
        $avg9 = "AVG Zen" wide ascii nocase
        $avg10 = "AVG Cleaner" wide ascii nocase
        $avg11 = "AVG AntiTrack" wide ascii nocase
        $avg12 = "AVG Secure Browser" wide ascii nocase
        $avg13 = "avg.exe" wide ascii nocase
        $avg14 = "avgui.exe" wide ascii nocase
        $avg15 = "avgsvc.exe" wide ascii nocase
        $avg16 = "avgwdsvc.exe" wide ascii nocase
        $avg17 = "avgrsa.exe" wide ascii nocase
        $avg18 = "avgnt.exe" wide ascii nocase
    condition:
        any of ($avg*)
}

rule PUP_AV_AVIRA {
    meta:
        description = "Avira antivirus — aggressive ads, upsell popups, system slowdown"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $av1 = "Avira" wide ascii nocase
        $av2 = "avira" wide ascii nocase
        $av3 = "AVIRA" wide ascii
        $av4 = "Avira Antivirus" wide ascii nocase
        $av5 = "Avira Free Security" wide ascii nocase
        $av6 = "Avira Prime" wide ascii nocase
        $av7 = "Avira Phantom VPN" wide ascii nocase
        $av8 = "Avira System Speedup" wide ascii nocase
        $av9 = "Avira Password Manager" wide ascii nocase
        $av10 = "Avira Browser Safety" wide ascii nocase
        $av11 = "Avira Software Updater" wide ascii nocase
        $av12 = "avira.exe" wide ascii nocase
        $av13 = "avcenter.exe" wide ascii nocase
        $av14 = "avguard.exe" wide ascii nocase
        $av15 = "avnotify.exe" wide ascii nocase
        $av16 = "avconfig.exe" wide ascii nocase
    condition:
        any of ($av*)
}

rule PUP_AV_COMODO {
    meta:
        description = "Comodo antivirus — aggressive popups, difficult to uninstall, bundled extras"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $c1 = "Comodo" wide ascii nocase
        $c2 = "comodo" wide ascii nocase
        $c3 = "COMODO" wide ascii
        $c4 = "Comodo Antivirus" wide ascii nocase
        $c5 = "Comodo Internet Security" wide ascii nocase
        $c6 = "Comodo Firewall" wide ascii nocase
        $c7 = "Comodo Dragon" wide ascii nocase
        $c8 = "Comodo Secure DNS" wide ascii nocase
        $c9 = "Comodo GeekBuddy" wide ascii nocase
        $c10 = "Comodo Cleaning Essentials" wide ascii nocase
        $c11 = "Comodo Backup" wide ascii nocase
        $c12 = "Comodo IceSword" wide ascii nocase
        $c13 = "cmdagent.exe" wide ascii nocase
        $c14 = "cis.exe" wide ascii nocase
        $c15 = "cavwp.exe" wide ascii nocase
        $c16 = "cavshell.exe" wide ascii nocase
    condition:
        any of ($c*)
}

rule PUP_AV_OTHER_UNWANTED {
    meta:
        description = "Other unwanted/subpar antivirus software — commonly pre-bundled or aggressive"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "info"
        category = "PUP"
        family = "UnwantedAV"
    strings:
        $o1 = "Webroot" wide ascii nocase
        $o2 = "webroot" wide ascii nocase
        $o3 = "Webroot SecureAnywhere" wide ascii nocase
        $o4 = "Trend Micro" wide ascii nocase
        $o5 = "trend micro" wide ascii nocase
        $o6 = "TrendMicro" wide ascii nocase
        $o7 = "PC-cillin" wide ascii nocase
        $o8 = "BullGuard" wide ascii nocase
        $o9 = "bullguard" wide ascii nocase
        $o10 = "VIPRE" wide ascii
        $o11 = "vipre" wide ascii nocase
        $o12 = "VIPRE Antivirus" wide ascii nocase
        $o13 = "ZoneAlarm" wide ascii nocase
        $o14 = "zonealarm" wide ascii nocase
        $o15 = "Zone Labs" wide ascii nocase
        $o16 = "Panda Security" wide ascii nocase
        $o17 = "panda security" wide ascii nocase
        $o18 = "Panda Antivirus" wide ascii nocase
        $o19 = "Panda Dome" wide ascii nocase
        $o20 = "TotalAV" wide ascii nocase
        $o21 = "totalav" wide ascii nocase
        $o22 = "Total AV" wide ascii nocase
        $o23 = "PCProtect" wide ascii nocase
        $o24 = "pcprotect" wide ascii nocase
        $o25 = "MacKeeper" wide ascii nocase
        $o26 = "mackeeper" wide ascii nocase
        $o27 = "MacBooster" wide ascii nocase
        $o28 = "macbooster" wide ascii nocase
        $o29 = "System Mechanic" wide ascii nocase
        $o30 = "system mechanic" wide ascii nocase
        $o31 = "iolo" wide ascii nocase
        $o32 = "IObit" wide ascii nocase
        $o33 = "iobit" wide ascii nocase
        $o34 = "Advanced SystemCare" wide ascii nocase
        $o35 = "advanced systemcare" wide ascii nocase
        $o36 = "SpyHunter" wide ascii nocase
        $o37 = "spyhunter" wide ascii nocase
        $o38 = "Enigma Software" wide ascii nocase
        $o39 = "Spyware Doctor" wide ascii nocase
        $o40 = "spyware doctor" wide ascii nocase
        $o41 = "PC Tools" wide ascii nocase
        $o42 = "pctools" wide ascii nocase
        $o43 = "StopZilla" wide ascii nocase
        $o44 = "stopzilla" wide ascii nocase
        $o45 = "XoftSpy" wide ascii nocase
        $o46 = "xoftspy" wide ascii nocase
        $o47 = "Paretologic" wide ascii nocase
        $o48 = "paretologic" wide ascii nocase
    condition:
        any of ($o*)
}

// ═══════════════════════════════════════════════════════════════════
// ADWARE / BROWSER HIJACKERS
// ═══════════════════════════════════════════════════════════════════

rule PUP_ADWARE_BROWSER_HIJACKER {
    meta:
        description = "Browser hijacker — changes search engine, homepage, shows intrusive ads"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Adware"
    strings:
        $bh1 = "SearchProtect" wide ascii nocase
        $bh2 = "searchprotect" wide ascii nocase
        $bh3 = "Conduit" wide ascii nocase
        $bh4 = "conduit" wide ascii nocase
        $bh5 = "SearchAssistant" wide ascii nocase
        $bh6 = "searchassistant" wide ascii nocase
        $bh7 = "SearchHelper" wide ascii nocase
        $bh8 = "searchhelper" wide ascii nocase
        $bh9 = "BrowserProtect" wide ascii nocase
        $bh10 = "browserprotect" wide ascii nocase
        $bh11 = "BrowserHelper" wide ascii nocase
        $bh12 = "browserhelper" wide ascii nocase
        $bh13 = "SearchAwesome" wide ascii nocase
        $bh14 = "searchawesome" wide ascii nocase
        $bh15 = "SearchNewTab" wide ascii nocase
        $bh16 = "searchnewtab" wide ascii nocase
        $bh17 = "SearchTab" wide ascii nocase
        $bh18 = "searchtab" wide ascii nocase
        $bh19 = "SearchSuite" wide ascii nocase
        $bh20 = "searchsuite" wide ascii nocase
        $bh21 = "SearchWeb" wide ascii nocase
        $bh22 = "searchweb" wide ascii nocase
        $bh23 = "SearchResults" wide ascii nocase
        $bh24 = "searchresults" wide ascii nocase
        $bh25 = "MySearchDial" wide ascii nocase
        $bh26 = "mysearchdial" wide ascii nocase
        $bh27 = "MySearch" wide ascii nocase
        $bh28 = "mysearch" wide ascii nocase
        $bh29 = "SearchDial" wide ascii nocase
        $bh30 = "searchdial" wide ascii nocase
        $bh31 = "SearchQuery" wide ascii nocase
        $bh32 = "searchquery" wide ascii nocase
        $bh33 = "SearchProtect" wide ascii nocase
        $bh34 = "SweetIM" wide ascii nocase
        $bh35 = "sweetim" wide ascii nocase
        $bh36 = "SweetPacks" wide ascii nocase
        $bh37 = "sweetpacks" wide ascii nocase
        $bh38 = "Wajam" wide ascii nocase
        $bh39 = "wajam" wide ascii nocase
        $bh40 = "BrowseFox" wide ascii nocase
        $bh41 = "browsefox" wide ascii nocase
        $bh42 = "BrowseForChange" wide ascii nocase
        $bh43 = "browseforchange" wide ascii nocase
        $bh44 = "CouponDropDown" wide ascii nocase
        $bh45 = "coupondropdown" wide ascii nocase
        $bh46 = "CouponBuddy" wide ascii nocase
        $bh47 = "couponbuddy" wide ascii nocase
        $bh48 = "DealPly" wide ascii nocase
        $bh49 = "dealply" wide ascii nocase
        $bh50 = "PriceGong" wide ascii nocase
        $bh51 = "pricegong" wide ascii nocase
        $bh52 = "ShopperPro" wide ascii nocase
        $bh53 = "shopperpro" wide ascii nocase
        $bh54 = "ShopToWin" wide ascii nocase
        $bh55 = "shoptowin" wide ascii nocase
        $bh56 = "Yontoo" wide ascii nocase
        $bh57 = "yontoo" wide ascii nocase
        $bh58 = "BrowseToSave" wide ascii nocase
        $bh59 = "browsetosave" wide ascii nocase
        $bh60 = "SearchMine" wide ascii nocase
        $bh61 = "searchmine" wide ascii nocase
        $bh62 = "SearchIt" wide ascii nocase
        $bh63 = "searchit" wide ascii nocase
        $bh64 = "SearchGo" wide ascii nocase
        $bh65 = "searchgo" wide ascii nocase
        $bh66 = "SearchFun" wide ascii nocase
        $bh67 = "searchfun" wide ascii nocase
        $bh68 = "SearchEasy" wide ascii nocase
        $bh69 = "searcheasy" wide ascii nocase
        $bh70 = "SearchBest" wide ascii nocase
        $bh71 = "searchbest" wide ascii nocase
        $bh72 = "SearchAwesome" wide ascii nocase
        $bh73 = "DeltaSearch" wide ascii nocase
        $bh74 = "deltasearch" wide ascii nocase
        $bh75 = "Delta-Home" wide ascii nocase
        $bh76 = "deltahome" wide ascii nocase
        $bh77 = "Trovi" wide ascii nocase
        $bh78 = "trovi" wide ascii nocase
        $bh79 = "TroviSearch" wide ascii nocase
        $bh80 = "trovisearch" wide ascii nocase
        $bh81 = "AskSearch" wide ascii nocase
        $bh82 = "asksearch" wide ascii nocase
        $bh83 = "Ask Toolbar" wide ascii nocase
        $bh84 = "ask toolbar" wide ascii nocase
        $bh85 = "Ask.com" wide ascii nocase
        $bh86 = "Babylon" wide ascii nocase
        $bh87 = "babylon" wide ascii nocase
        $bh88 = "Babylon Search" wide ascii nocase
        $bh89 = "babylon search" wide ascii nocase
        $bh90 = "Babylon Toolbar" wide ascii nocase
        $bh91 = "babylon toolbar" wide ascii nocase
        $bh92 = "CoolSearch" wide ascii nocase
        $bh93 = "coolsearch" wide ascii nocase
        $bh94 = "CoolWebSearch" wide ascii nocase
        $bh95 = "coolwebsearch" wide ascii nocase
        $bh96 = "Claro" wide ascii nocase
        $bh97 = "claro" wide ascii nocase
        $bh98 = "ClaroSearch" wide ascii nocase
        $bh99 = "clarosearch" wide ascii nocase
        $bh100 = "SearchAwesome" wide ascii nocase
    condition:
        any of ($bh*)
}

rule PUP_ADWARE_TOOLBAR {
    meta:
        description = "Unwanted browser toolbar — commonly bundled with free software"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        category = "PUP"
        family = "Adware"
    strings:
        $tb1 = "Toolbar" wide ascii nocase
        $tb2 = "toolbar" wide ascii nocase
        $tb3 = "BingBar" wide ascii nocase
        $tb4 = "bingbar" wide ascii nocase
        $tb5 = "Bing Bar" wide ascii nocase
        $tb6 = "Google Toolbar" wide ascii nocase
        $tb7 = "google toolbar" wide ascii nocase
        $tb8 = "Yahoo Toolbar" wide ascii nocase
        $tb9 = "yahoo toolbar" wide ascii nocase
        $tb10 = "AOL Toolbar" wide ascii nocase
        $tb11 = "aol toolbar" wide ascii nocase
        $tb12 = "Alexa Toolbar" wide ascii nocase
        $tb13 = "alexa toolbar" wide ascii nocase
        $tb14 = "Skype Toolbar" wide ascii nocase
        $tb15 = "skype toolbar" wide ascii nocase
        $tb16 = "BingBar" wide ascii nocase
        $tb17 = "Bing Bar" wide ascii nocase
        $tb18 = "BingBar" wide ascii nocase
        $tb19 = "BingBar" wide ascii nocase
        $tb20 = "BingBar" wide ascii nocase
    condition:
        any of ($tb*)
}

rule PUP_ADWARE_ADWARE_GENERIC {
    meta:
        description = "Generic adware indicators — popup ads, injected ads, ad-serving modules"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Adware"
    strings:
        $ad1 = "adware" wide ascii nocase
        $ad2 = "Adware" wide ascii
        $ad3 = "adserv" wide ascii nocase
        $ad4 = "adserver" wide ascii nocase
        $ad5 = "adservice" wide ascii nocase
        $ad6 = "adnetwork" wide ascii nocase
        $ad7 = "adnet" wide ascii nocase
        $ad8 = "advert" wide ascii nocase
        $ad9 = "popup" wide ascii nocase
        $ad10 = "pop-up" wide ascii nocase
        $ad11 = "popunder" wide ascii nocase
        $ad12 = "pop_under" wide ascii nocase
        $ad13 = "sponsor" wide ascii nocase
        $ad14 = "sponsored" wide ascii nocase
        $ad15 = "sponsor" wide ascii nocase
        $ad16 = "adInject" wide ascii nocase
        $ad17 = "adinject" wide ascii nocase
        $ad18 = "ad-inject" wide ascii nocase
        $ad19 = "adInjector" wide ascii nocase
        $ad20 = "ad_inject" wide ascii nocase
        $ad21 = "advertise" wide ascii nocase
        $ad22 = "advertising" wide ascii nocase
        $ad23 = "advertisement" wide ascii nocase
        $ad24 = "adblock" wide ascii nocase
        $ad25 = "ad_block" wide ascii nocase
        $ad26 = "adblocker" wide ascii nocase
        $ad27 = "ad_blocker" wide ascii nocase
    condition:
        3 of ($ad*)
}

// ═══════════════════════════════════════════════════════════════════
// CRYPTOMINERS (Cross-Platform)
// ═══════════════════════════════════════════════════════════════════

rule PUP_MINER_XMRIG_CROSS {
    meta:
        description = "XMRig cryptominer — cross-platform detection (Windows/Linux/macOS)"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        category = "PUP"
        family = "Cryptominer"
    strings:
        $x1 = "xmrig" wide ascii nocase
        $x2 = "XMRig" wide ascii
        $x3 = "stratum+tcp://" wide ascii
        $x4 = "stratum+ssl://" wide ascii
        $x5 = "--donate-level" wide ascii
        $x6 = "randomx" wide ascii nocase
        $x7 = "cryptonight" wide ascii nocase
        $x8 = "rx/0" wide ascii
        $x9 = "rx/wow" wide ascii
        $x10 = "cn/0" wide ascii
        $x11 = "cn-heavy" wide ascii
        $x12 = "cn-lite" wide ascii
        $x13 = "cn-pico" wide ascii
        $x14 = "argon2" wide ascii nocase
        $x15 = "astrobwt" wide ascii nocase
        $x16 = "ghostrider" wide ascii nocase
    condition:
        2 of ($x*)
}

rule PUP_MINER_STRATUM_CROSS {
    meta:
        description = "Stratum mining protocol — cross-platform cryptominer indicator"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        category = "PUP"
        family = "Cryptominer"
    strings:
        $s1 = "stratum+tcp://" wide ascii
        $s2 = "stratum+ssl://" wide ascii
        $s3 = "mining" wide ascii nocase
        $s4 = "miner" wide ascii nocase
        $s5 = "nicehash" wide ascii nocase
        $s6 = "--algo" wide ascii
        $s7 = "--pool" wide ascii
        $s8 = "--user" wide ascii
        $s9 = "--rig-id" wide ascii
        $s10 = "--keepalive" wide ascii
        $s11 = "--tls" wide ascii
        $s12 = "--cpu-affinity" wide ascii
        $s13 = "--cpu-priority" wide ascii
        $s14 = "--max-cpu-usage" wide ascii
        $s15 = "--threads" wide ascii
        $s16 = "--background" wide ascii
        $s17 = "--no-color" wide ascii
        $s18 = "--donate" wide ascii
        $s19 = "--donation" wide ascii
        $s20 = "--coin" wide ascii
    condition:
        3 of ($s*)
}

rule PUP_MINER_ETH_WALLET_CROSS {
    meta:
        description = "Ethereum wallet address — common in cryptominers"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Cryptominer"
    strings:
        $eth1 = /0x[a-fA-F0-9]{40}/ ascii
        $eth2 = "eth" wide ascii nocase
        $eth3 = "ethereum" wide ascii nocase
        $eth4 = "ethash" wide ascii nocase
        $eth5 = "dagger" wide ascii nocase
        $eth6 = "hashimoto" wide ascii nocase
        $eth7 = "gpu" wide ascii nocase
        $eth8 = "GPU" wide ascii
        $eth9 = "cuda" wide ascii nocase
        $eth10 = "CUDA" wide ascii
        $eth11 = "opencl" wide ascii nocase
        $eth12 = "OpenCL" wide ascii
    condition:
        #eth1 > 0 and 2 of ($eth2,$eth3,$eth4,$eth5,$eth6,$eth7,$eth8,$eth9,$eth10,$eth11,$eth12)
}

rule PUP_MINER_GENERIC_CROSS {
    meta:
        description = "Generic cryptominer — cross-platform detection"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Cryptominer"
    strings:
        $g1 = "cryptominer" wide ascii nocase
        $g2 = "crypto-miner" wide ascii nocase
        $g3 = "crypto_miner" wide ascii nocase
        $g4 = "cryptocurrency" wide ascii nocase
        $g5 = "crypto-currency" wide ascii nocase
        $g6 = "monero" wide ascii nocase
        $g7 = "Monero" wide ascii
        $g8 = "XMR" wide ascii
        $g9 = "xmr" wide ascii nocase
        $g10 = "bitcoin" wide ascii nocase
        $g11 = "Bitcoin" wide ascii
        $g12 = "BTC" wide ascii
        $g13 = "btc" wide ascii nocase
        $g14 = "wallet" wide ascii nocase
        $g15 = "pool" wide ascii nocase
        $g16 = "hashrate" wide ascii nocase
        $g17 = "hash_rate" wide ascii nocase
        $g18 = "hash rate" wide ascii nocase
        $g19 = "nonce" wide ascii nocase
        $g20 = "difficulty" wide ascii nocase
    condition:
        3 of ($g*)
}

// ═══════════════════════════════════════════════════════════════════
// FAKE SYSTEM OPTIMIZERS / SCAMWARE
// ═══════════════════════════════════════════════════════════════════

rule PUP_SCAM_OPTIMIZER {
    meta:
        description = "Fake system optimizer — claims to fix problems, shows fake errors, upsells"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        category = "PUP"
        family = "Scamware"
    strings:
        $so1 = "PC Optimizer" wide ascii nocase
        $so2 = "pc optimizer" wide ascii nocase
        $so3 = "System Optimizer" wide ascii nocase
        $so4 = "system optimizer" wide ascii nocase
        $so5 = "Registry Cleaner" wide ascii nocase
        $so6 = "registry cleaner" wide ascii nocase
        $so7 = "Registry Booster" wide ascii nocase
        $so8 = "registry booster" wide ascii nocase
        $so9 = "Registry Repair" wide ascii nocase
        $so10 = "registry repair" wide ascii nocase
        $so11 = "Registry Fix" wide ascii nocase
        $so12 = "registry fix" wide ascii nocase
        $so13 = "PC Cleaner" wide ascii nocase
        $so14 = "pc cleaner" wide ascii nocase
        $so15 = "PC Booster" wide ascii nocase
        $so16 = "pc booster" wide ascii nocase
        $so17 = "PC Repair" wide ascii nocase
        $so18 = "pc repair" wide ascii nocase
        $so19 = "SpeedUp" wide ascii nocase
        $so20 = "speedup" wide ascii nocase
        $so21 = "Speed Up" wide ascii nocase
        $so22 = "speed up" wide ascii nocase
        $so23 = "TuneUp" wide ascii nocase
        $so24 = "tuneup" wide ascii nocase
        $so25 = "Tune Up" wide ascii nocase
        $so26 = "tune up" wide ascii nocase
        $so27 = "Driver Booster" wide ascii nocase
        $so28 = "driver booster" wide ascii nocase
        $so29 = "Driver Updater" wide ascii nocase
        $so30 = "driver updater" wide ascii nocase
        $so31 = "DriverFix" wide ascii nocase
        $so32 = "driverfix" wide ascii nocase
        $so33 = "DriverFixer" wide ascii nocase
        $so34 = "driverfixer" wide ascii nocase
        $so35 = "DriverUpdate" wide ascii nocase
        $so36 = "driverupdate" wide ascii nocase
        $so37 = "DriverUpdate" wide ascii nocase
        $so38 = "DriverUpdate" wide ascii nocase
        $so39 = "DriverUpdate" wide ascii nocase
        $so40 = "DriverUpdate" wide ascii nocase
    condition:
        any of ($so*)
}

rule PUP_SCAM_FAKE_ALERTS {
    meta:
        description = "Fake alert / scareware — claims infections, fake system warnings"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        category = "PUP"
        family = "Scamware"
    strings:
        $fa1 = "Your computer is infected" wide ascii nocase
        $fa2 = "your computer is infected" wide ascii nocase
        $fa3 = "Your system is infected" wide ascii nocase
        $fa4 = "your system is infected" wide ascii nocase
        $fa5 = "viruses detected" wide ascii nocase
        $fa6 = "Viruses Detected" wide ascii
        $fa7 = "threats detected" wide ascii nocase
        $fa8 = "Threats Detected" wide ascii
        $fa9 = "malware detected" wide ascii nocase
        $fa10 = "Malware Detected" wide ascii
        $fa11 = "call this number" wide ascii nocase
        $fa12 = "call this toll-free" wide ascii nocase
        $fa13 = "call toll free" wide ascii nocase
        $fa14 = "call 1-" wide ascii nocase
        $fa15 = "call 1-8" wide ascii nocase
        $fa16 = "call 1-8" wide ascii nocase
        $fa17 = "Windows has detected" wide ascii nocase
        $fa18 = "windows has detected" wide ascii nocase
        $fa19 = "critical error" wide ascii nocase
        $fa20 = "Critical Error" wide ascii
        $fa21 = "system alert" wide ascii nocase
        $fa22 = "System Alert" wide ascii
        $fa23 = "security alert" wide ascii nocase
        $fa24 = "Security Alert" wide ascii
        $fa25 = "immediate action" wide ascii nocase
        $fa26 = "Immediate Action" wide ascii
        $fa27 = "act now" wide ascii nocase
        $fa28 = "Act Now" wide ascii
        $fa29 = "renew your subscription" wide ascii nocase
        $fa30 = "subscription expired" wide ascii nocase
        $fa31 = "your subscription has expired" wide ascii nocase
        $fa32 = "your license has expired" wide ascii nocase
        $fa33 = "renew now" wide ascii nocase
        $fa34 = "Renew Now" wide ascii
        $fa35 = "buy now" wide ascii nocase
        $fa36 = "Buy Now" wide ascii
        $fa37 = "purchase now" wide ascii nocase
        $fa38 = "Purchase Now" wide ascii
        $fa39 = "activate now" wide ascii nocase
        $fa40 = "Activate Now" wide ascii
    condition:
        2 of ($fa*)
}

// ═══════════════════════════════════════════════════════════════════
// BUNDLED JUNKWARE / BLOATWARE
// ═══════════════════════════════════════════════════════════════════

rule PUP_BLOATWARE_PC_MANUFACTURER {
    meta:
        description = "PC manufacturer bloatware — pre-installed trialware and junk"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        category = "PUP"
        family = "Bloatware"
    strings:
        $b1 = "WildTangent" wide ascii nocase
        $b2 = "wildtangent" wide ascii nocase
        $b3 = "WildTangent Games" wide ascii nocase
        $b4 = "wildtangent games" wide ascii nocase
        $b5 = "CyberLink" wide ascii nocase
        $b6 = "cyberlink" wide ascii nocase
        $b7 = "PowerDVD" wide ascii nocase
        $b8 = "powerdvd" wide ascii nocase
        $b9 = "PowerDirector" wide ascii nocase
        $b10 = "powerdirector" wide ascii nocase
        $b11 = "PhotoDirector" wide ascii nocase
        $b12 = "photodirector" wide ascii nocase
        $b13 = "YouCam" wide ascii nocase
        $b14 = "youcam" wide ascii nocase
        $b15 = "PerfectStroke" wide ascii nocase
        $b16 = "perfectstroke" wide ascii nocase
        $b17 = "Corel" wide ascii nocase
        $b18 = "corel" wide ascii nocase
        $b19 = "WinZip" wide ascii nocase
        $b20 = "winzip" wide ascii nocase
        $b21 = "WinRAR" wide ascii nocase
        $b22 = "winrar" wide ascii nocase
        $b23 = "Nero" wide ascii nocase
        $b24 = "nero" wide ascii nocase
        $b25 = "Nero Burning ROM" wide ascii nocase
        $b26 = "nero burning rom" wide ascii nocase
        $b27 = "Roxio" wide ascii nocase
        $b28 = "roxio" wide ascii nocase
        $b29 = "Roxio Creator" wide ascii nocase
        $b30 = "roxio creator" wide ascii nocase
        $b31 = "Dell" wide ascii nocase
        $b32 = "dell" wide ascii nocase
        $b33 = "Dell SupportAssist" wide ascii nocase
        $b34 = "dell supportassist" wide ascii nocase
        $b35 = "Dell Update" wide ascii nocase
        $b36 = "dell update" wide ascii nocase
        $b37 = "Dell Digital Delivery" wide ascii nocase
        $b38 = "dell digital delivery" wide ascii nocase
        $b39 = "HP" wide ascii
        $b40 = "hp" wide ascii nocase
        $b41 = "HP Support Assistant" wide ascii nocase
        $b42 = "hp support assistant" wide ascii nocase
        $b43 = "HP JumpStart" wide ascii nocase
        $b44 = "hp jumpstart" wide ascii nocase
        $b45 = "HP Connection Manager" wide ascii nocase
        $b46 = "hp connection manager" wide ascii nocase
        $b47 = "Lenovo" wide ascii nocase
        $b48 = "lenovo" wide ascii nocase
        $b49 = "Lenovo Vantage" wide ascii nocase
        $b50 = "lenovo vantage" wide ascii nocase
        $b51 = "Lenovo Companion" wide ascii nocase
        $b52 = "lenovo companion" wide ascii nocase
        $b53 = "Acer" wide ascii nocase
        $b54 = "acer" wide ascii nocase
        $b55 = "Acer Care Center" wide ascii nocase
        $b56 = "acer care center" wide ascii nocase
        $b57 = "Acer Collection" wide ascii nocase
        $b58 = "acer collection" wide ascii nocase
        $b59 = "ASUS" wide ascii
        $b60 = "asus" wide ascii nocase
        $b61 = "ASUS Giftbox" wide ascii nocase
        $b62 = "asus giftbox" wide ascii nocase
        $b63 = "ASUS Live Update" wide ascii nocase
        $b64 = "asus live update" wide ascii nocase
        $b65 = "Toshiba" wide ascii nocase
        $b66 = "toshiba" wide ascii nocase
        $b67 = "Toshiba Service Station" wide ascii nocase
        $b68 = "toshiba service station" wide ascii nocase
        $b69 = "Samsung" wide ascii nocase
        $b70 = "samsung" wide ascii nocase
        $b71 = "Samsung Update" wide ascii nocase
        $b72 = "samsung update" wide ascii nocase
        $b73 = "Samsung Settings" wide ascii nocase
        $b74 = "samsung settings" wide ascii nocase
        $b75 = "McAfee" wide ascii nocase
        $b76 = "mcafee" wide ascii nocase
        $b77 = "Norton" wide ascii nocase
        $b78 = "norton" wide ascii nocase
        $b79 = "Dropbox" wide ascii nocase
        $b80 = "dropbox" wide ascii nocase
        $b81 = "Evernote" wide ascii nocase
        $b82 = "evernote" wide ascii nocase
        $b83 = "Spotify" wide ascii nocase
        $b84 = "spotify" wide ascii nocase
        $b85 = "Netflix" wide ascii nocase
        $b86 = "netflix" wide ascii nocase
        $b87 = "Candy Crush" wide ascii nocase
        $b88 = "candy crush" wide ascii nocase
        $b89 = "CandyCrush" wide ascii nocase
        $b90 = "candycrush" wide ascii nocase
        $b91 = "Facebook" wide ascii nocase
        $b92 = "facebook" wide ascii nocase
        $b93 = "Instagram" wide ascii nocase
        $b94 = "instagram" wide ascii nocase
        $b95 = "Twitter" wide ascii nocase
        $b96 = "twitter" wide ascii nocase
        $b97 = "Skype" wide ascii nocase
        $b98 = "skype" wide ascii nocase
        $b99 = "OneDrive" wide ascii nocase
        $b100 = "onedrive" wide ascii nocase
    condition:
        3 of ($b*)
}

// ═══════════════════════════════════════════════════════════════════
// TRACKING / SPYWARE
// ═══════════════════════════════════════════════════════════════════

rule PUP_TRACKER_ADOBE_ANALYTICS {
    meta:
        description = "Aggressive tracking/analytics software — privacy concerns"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "low"
        category = "PUP"
        family = "Tracking"
    strings:
        $t1 = "tracking" wide ascii nocase
        $t2 = "Tracking" wide ascii
        $t3 = "analytics" wide ascii nocase
        $t4 = "Analytics" wide ascii
        $t5 = "telemetry" wide ascii nocase
        $t6 = "Telemetry" wide ascii
        $t7 = "spyware" wide ascii nocase
        $t8 = "Spyware" wide ascii
        $t9 = "keylogger" wide ascii nocase
        $t10 = "Keylogger" wide ascii
        $t11 = "keystroke" wide ascii nocase
        $t12 = "Keystroke" wide ascii
        $t13 = "screen capture" wide ascii nocase
        $t14 = "Screen Capture" wide ascii
        $t15 = "screenshot" wide ascii nocase
        $t16 = "Screenshot" wide ascii
        $t17 = "monitor" wide ascii nocase
        $t18 = "Monitor" wide ascii
        $t19 = "surveillance" wide ascii nocase
        $t20 = "Surveillance" wide ascii
        $t21 = "parental control" wide ascii nocase
        $t22 = "Parental Control" wide ascii
        $t23 = "spy" wide ascii nocase
        $t24 = "Spy" wide ascii
        $t25 = "monitoring" wide ascii nocase
        $t26 = "Monitoring" wide ascii
    condition:
        3 of ($t*)
}

// ═══════════════════════════════════════════════════════════════════
// FAKE / UNWANTED BROWSER EXTENSIONS
// ═══════════════════════════════════════════════════════════════════

rule PUP_EXTENSION_AD_INJECTOR {
    meta:
        description = "Browser extension that injects ads or tracks browsing"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Adware"
    strings:
        $ext1 = "extension" wide ascii nocase
        $ext2 = "Extension" wide ascii
        $ext3 = "addon" wide ascii nocase
        $ext4 = "Addon" wide ascii
        $ext5 = "add-on" wide ascii nocase
        $ext6 = "Add-On" wide ascii
        $ext7 = "plugin" wide ascii nocase
        $ext8 = "Plugin" wide ascii
        $ext9 = "coupon" wide ascii nocase
        $ext10 = "Coupon" wide ascii
        $ext11 = "deal" wide ascii nocase
        $ext12 = "Deal" wide ascii
        $ext13 = "shopping" wide ascii nocase
        $ext14 = "Shopping" wide ascii
        $ext15 = "price" wide ascii nocase
        $ext16 = "Price" wide ascii
        $ext17 = "compare" wide ascii nocase
        $ext18 = "Compare" wide ascii
        $ext19 = "save" wide ascii nocase
        $ext20 = "Save" wide ascii
        $ext21 = "cashback" wide ascii nocase
        $ext22 = "Cashback" wide ascii
        $ext23 = "cash back" wide ascii nocase
        $ext24 = "Cash Back" wide ascii
        $ext25 = "reward" wide ascii nocase
        $ext26 = "Reward" wide ascii
    condition:
        3 of ($ext*)
}

// ═══════════════════════════════════════════════════════════════════
// CRACKS / KEYGENS / PIRATED SOFTWARE
// ═══════════════════════════════════════════════════════════════════

rule PUP_CRACK_KEYGEN {
    meta:
        description = "Crack/keygen/patch — often bundled with malware, considered PUP"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "high"
        category = "PUP"
        family = "HackTool"
    strings:
        $ck1 = "crack" wide ascii nocase
        $ck2 = "Crack" wide ascii
        $ck3 = "keygen" wide ascii nocase
        $ck4 = "Keygen" wide ascii
        $ck5 = "key-gen" wide ascii nocase
        $ck6 = "Key-Gen" wide ascii
        $ck7 = "key generator" wide ascii nocase
        $ck8 = "Key Generator" wide ascii
        $ck9 = "serial" wide ascii nocase
        $ck10 = "Serial" wide ascii
        $ck11 = "patch" wide ascii nocase
        $ck12 = "Patch" wide ascii
        $ck13 = "loader" wide ascii nocase
        $ck14 = "Loader" wide ascii
        $ck15 = "activator" wide ascii nocase
        $ck16 = "Activator" wide ascii
        $ck17 = "license" wide ascii nocase
        $ck18 = "License" wide ascii
        $ck19 = "unlock" wide ascii nocase
        $ck20 = "Unlock" wide ascii
        $ck21 = "hack" wide ascii nocase
        $ck22 = "Hack" wide ascii
        $ck23 = "cheat" wide ascii nocase
        $ck24 = "Cheat" wide ascii
        $ck25 = "trainer" wide ascii nocase
        $ck26 = "Trainer" wide ascii
    condition:
        2 of ($ck*)
}

// ═══════════════════════════════════════════════════════════════════
// MINING POOL / CRYPTO POOL CONFIGURATIONS
// ═══════════════════════════════════════════════════════════════════

rule PUP_MINER_POOL_CONFIG {
    meta:
        description = "Cryptocurrency mining pool configuration — indicates miner software"
        author = "Autobahn Defender"
        date = "2025-01-01"
        severity = "medium"
        category = "PUP"
        family = "Cryptominer"
    strings:
        $pool1 = "pool" wide ascii nocase
        $pool2 = "Pool" wide ascii
        $pool3 = "miningpool" wide ascii nocase
        $pool4 = "MiningPool" wide ascii
        $pool5 = "mining-pool" wide ascii nocase
        $pool6 = "Mining-Pool" wide ascii
        $pool7 = "pool_address" wide ascii nocase
        $pool8 = "pool_host" wide ascii nocase
        $pool9 = "pool_url" wide ascii nocase
        $pool10 = "pool. support" wide ascii nocase
        $pool11 = "pool.support" wide ascii nocase
        $pool12 = "mine" wide ascii nocase
        $pool13 = "Mine" wide ascii
        $pool14 = "miner" wide ascii nocase
        $pool15 = "Miner" wide ascii
        $pool16 = "mining" wide ascii nocase
        $pool17 = "Mining" wide ascii
        $pool18 = "hash" wide ascii nocase
        $pool19 = "Hash" wide ascii
        $pool20 = "nonce" wide ascii nocase
        $pool21 = "Nonce" wide ascii
    condition:
        3 of ($pool*)
}

// ═══════════════════════════════════════════════════════════════════
// END OF PUP YARA RULES
// ═══════════════════════════════════════════════════════════════════
