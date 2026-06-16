// ThorScript Example: Custom C2 Detection Rules
// ===================================================
// Loaded automatically from: rules/thor_scripts/
// Run with: thor-agent --scripts-dir ./scripts
//
// Format: rule "Name" { on EVENT if { COND } then { ACTION } }

// ─── Rule 1: Meterpreter Reverse Shell (common ports) ──────────────────────
rule "Meterpreter Reverse TCP" {
    on network
    if {
        dst_port in [4444, 4445, 4446, 4447, 4448]
        and payload match /METERP|metsrv|mettle/i
    }
    then {
        alert(severity: "critical", msg: "Meterpreter reverse shell detected")
        log("Meterpreter: src=${src_ip} → dst=${dst_ip}:${dst_port}")
    }
}

// ─── Rule 2: Cobalt Strike HTTP Beacon ────────────────────────────────────
rule "Cobalt Strike HTTP Beacon" {
    on http
    if {
        payload match /(?:submit\.php|updates\.rss|jquery\.js|microsoft\.com\/pkiops)/i
        and payload match /MSIE 9\.0.*Windows Phone/i
    }
    then {
        alert(severity: "critical", msg: "Cobalt Strike malleable C2 beacon")
        log("CS beacon: src=${src_ip}")
    }
}

// ─── Rule 3: DNS Tunneling (high-entropy subdomains) ───────────────────────
rule "DNS Tunnel Detection" {
    on dns
    if {
        dst_port == 53
        and payload match /[a-z0-9]{40,}/i
    }
    then {
        alert(severity: "high", msg: "Possible DNS tunneling — high-entropy subdomain")
        log("DNS tunnel query from ${src_ip}")
    }
}

// ─── Rule 4: SSRF to Cloud Metadata ────────────────────────────────────────
rule "SSRF AWS IMDS Abuse" {
    on http
    if {
        payload match /169\.254\.169\.254/
    }
    then {
        alert(severity: "critical", msg: "SSRF targeting AWS IMDS — credential theft risk")
        drop()
    }
}

// ─── Rule 5: Crypto Mining Detection ───────────────────────────────────────
rule "Crypto Mining Stratum Protocol" {
    on network
    if {
        dst_port in [3333, 4444, 5555, 14444, 45560]
        and payload match /stratum\+tcp|mining\.subscribe|mining\.authorize/i
    }
    then {
        alert(severity: "high", msg: "Cryptocurrency mining — Stratum protocol detected")
        log("Mining connection: ${src_ip} → ${dst_ip}:${dst_port}")
    }
}

// ─── Rule 6: Ransomware File Encryption Activity ───────────────────────────
rule "Ransomware Network Propagation" {
    on network
    if {
        dst_port in [445, 135, 139]
        and payload match /WNCRY|RyukRead|ContiLocker|lockbit/i
    }
    then {
        alert(severity: "critical", msg: "Ransomware network propagation detected")
        drop()
    }
}

// ─── Rule 7: Log4Shell in ANY header ────────────────────────────────────────
rule "Log4Shell JNDI Any Header" {
    on http
    if {
        payload match /\$\{jndi:(ldap|rmi|dns|corba|iiop|dnsrmi):/i
    }
    then {
        alert(severity: "critical", msg: "Log4Shell CVE-2021-44228 JNDI injection attempt")
        drop()
    }
}

// ─── Rule 8: Python Requests C2 Beacon ────────────────────────────────────
rule "Python Requests Suspicious C2" {
    on http
    if {
        payload match /user-agent: python-requests\//i
        and dst_port in [80, 443, 8080, 8443]
    }
    then {
        alert(severity: "medium", msg: "Python requests user-agent — possible automated C2 or dropper")
        log("Python UA from ${src_ip} to ${dst_ip}:${dst_port}")
    }
}

// ─── Rule 9: Tor Hidden Service Access ─────────────────────────────────────
rule "Tor Hidden Service DNS" {
    on dns
    if {
        payload match /\.onion($|[\s\r\n])/i
    }
    then {
        alert(severity: "high", msg: "Tor hidden service DNS resolution attempt")
    }
}

// ─── Rule 10: Exfiltration via Pastebin/Transfer.sh ────────────────────────
rule "Data Exfiltration via Public Service" {
    on http
    if {
        payload match /(?:pastebin\.com|transfer\.sh|mega\.nz|webhook\.site|requestbin\.net)/i
    }
    then {
        alert(severity: "high", msg: "Possible data exfiltration to public file sharing service")
        log("Exfil attempt from ${src_ip} to public service")
    }
}
