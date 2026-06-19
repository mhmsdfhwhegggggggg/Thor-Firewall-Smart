/*
 * EICAR Test Signature — Thor Production Testing
 * ================================================
 * The EICAR test file is the industry-standard way to validate AV/YARA scanning
 * without using real malware. It is completely safe to scan and test with.
 *
 * EICAR test string: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
 *
 * Usage: Place a file containing the EICAR test string at any path,
 *        then verify Thor YARA engine detects it.
 *
 * Test command:
 *   echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test
 *   cargo test -- detection::yara::tests
 */

rule EICAR_Test_File {
    meta:
        description    = "EICAR Anti-Malware Test File — validates YARA scanning is working"
        author         = "Thor Security Team"
        date           = "2024-01-01"
        version        = "1.0"
        severity       = "informational"
        category       = "test"
        mitre_attack   = "T0000"  // Test — not a real technique

    strings:
        $eicar_magic = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $eicar_full  = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar_magic or $eicar_full
}


/*
 * Reverse Shell Detection
 * ========================
 * Detects common reverse shell patterns in process memory or files.
 * Covers bash, python, perl, and netcat based shells.
 */
rule Reverse_Shell_Patterns {
    meta:
        description  = "Detects reverse shell command patterns"
        author       = "Thor Security Team"
        severity     = "critical"
        mitre_attack = "T1059.004"
        category     = "execution"

    strings:
        $bash_tcp  = "/dev/tcp/"                        // bash TCP shell
        $bash_udp  = "/dev/udp/"                        // bash UDP shell
        $py_socket = "import socket,subprocess"         // python shell
        $py_b64    = "exec(base64.b64decode"            // encoded payload
        $nc_exec   = "nc -e /bin/bash"                  // netcat shell
        $nc_exec2  = "nc -e /bin/sh"
        $socat     = "socat exec:/bin/bash"             // socat shell
        $mkfifo    = "mkfifo /tmp/"                     // fifo pipe trick

    condition:
        any of them
}


/*
 * Credential Dumping Artifacts
 * =============================
 * Detects common patterns from mimikatz, secretsdump, and credential extraction tools.
 */
rule Credential_Dumping_Artifacts {
    meta:
        description  = "Detects credential dumping tool artifacts in memory/files"
        author       = "Thor Security Team"
        severity     = "critical"
        mitre_attack = "T1003"
        category     = "credential-access"

    strings:
        $mimikatz1 = "mimikatz"          nocase
        $mimikatz2 = "sekurlsa::logon"   nocase
        $mimikatz3 = "lsadump::sam"      nocase
        $dump_lsa  = "privilege::debug"  nocase
        $procdump  = "Out-Minidump"      nocase
        $sam_hive  = "\\SAM\\SAM\\Domains\\Account\\Users"

    condition:
        any of them
}


/*
 * Container Escape Artifacts
 * ===========================
 * Detects patterns associated with container escape techniques.
 */
rule Container_Escape_Artifacts {
    meta:
        description  = "Detects container escape artifacts and techniques"
        author       = "Thor Security Team"
        severity     = "critical"
        mitre_attack = "T1611"
        category     = "privilege-escalation"

    strings:
        $docker_sock    = "/var/run/docker.sock"
        $cgroup_release = "/release_agent"          // cgroup escape
        $proc_self_fd   = "/proc/self/fd/"
        $docker_runc    = "runc --root"
        $nsenter        = "nsenter --target 1 --mount --uts --ipc --net --pid"

    condition:
        any of them
}


/*
 * Webshell Signatures
 * ====================
 * Detects common PHP/JSP webshell patterns.
 */
rule Webshell_PHP {
    meta:
        description  = "Detects PHP webshell patterns"
        author       = "Thor Security Team"
        severity     = "critical"
        mitre_attack = "T1505.003"
        category     = "persistence"

    strings:
        $eval_base64  = /eval\s*\(\s*base64_decode/
        $system_get   = /system\s*\(\s*\$_GET/
        $passthru     = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/
        $shell_exec   = /shell_exec\s*\(\s*\$_(GET|POST)/
        $assert_b64   = /assert\s*\(\s*base64_decode/
        $c99          = "c99shell"
        $r57          = "r57shell"

    condition:
        any of them
}
