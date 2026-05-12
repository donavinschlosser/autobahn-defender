/* Autobahn Defender - Test YARA Rules
   These rules detect harmless test strings for verifying YARA integration.
   They will NOT trigger any antivirus scanner. */

rule AutobahnTestString {
    meta:
        description = "Autobahn Defender test rule - detects a harmless marker string"
        author = "Digital Autobahn"
        severity = "informational"
    strings:
        $test_marker = "AUTBAHN_DEFENDER_YARA_TEST_2025"
    condition:
        $test_marker
}

rule AutobahnTestFilename {
    meta:
        description = "Autobahn Defender test rule - detects test files by name"
        author = "Digital Autobahn"
        severity = "informational"
    strings:
        $test_name = "autobahn_yara_test" nocase
    condition:
        $test_name
}

rule AutobahnTestPattern {
    meta:
        description = "Autobahn Defender test rule - detects a numeric pattern for testing"
        author = "Digital Autobahn"
        severity = "informational"
    strings:
        $test_pattern = { 41 55 54 42 41 48 4E 5F 54 45 53 54 }
    condition:
        $test_pattern
}