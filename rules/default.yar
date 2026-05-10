rule suspicious_packed_file {
    meta:
        description = "Detects common packed/obfuscated executable patterns"
        author = "Autobahn Defender"
        version = "1.0"

    strings:
        $upx = "UPX!" ascii wide
        $aspack = ".aspack" ascii wide
        $themida = "Themida" ascii wide
        $vmprotect = "VMProtect" ascii wide

    condition:
        any of them
}

rule suspicious_script_download {
    meta:
        description = "Detects suspicious shell script download patterns"
        author = "Autobahn Defender"
        version = "1.0"

    strings:
        $curl = "curl" ascii
        $wget = "wget" ascii
        $pipe_shell = "| sh" ascii
        $pipe_bash = "| bash" ascii
        $exec_eval = "eval $" ascii

    condition:
        filesize < 1MB and
        any of ($curl, $wget) and
        any of ($pipe_shell, $pipe_bash, $exec_eval)
}

rule hidden_executable {
    meta:
        description = "Detects executables with hidden or suspicious names"
        author = "Autobahn Defender"
        version = "1.0"

    strings:
        $dot_prefix = ".." ascii
        $elf = { 7f 45 4c 46 }

    condition:
        $elf at 0 and
        filesize < 10MB
}