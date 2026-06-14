MITRE_MAP = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "recommended_action": "Review successful logins after failures, lock affected account if needed, block source IP, and enforce MFA."
    },
    "suspicious_powershell": {
        "tactic": "Execution",
        "technique": "T1059.001 - PowerShell",
        "recommended_action": "Collect command line, parent process, user context, and network destination. Isolate host if malicious execution is confirmed."
    },
    "malware_detected": {
        "tactic": "Execution",
        "technique": "T1204 - User Execution",
        "recommended_action": "Confirm quarantine status, identify source of file, isolate affected endpoint, and hunt for the same hash across endpoints."
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "recommended_action": "Validate source, review firewall/IDS history, identify targeted services, and block or contain scanning host."
    },
    "vpn_anomaly": {
        "tactic": "Initial Access",
        "technique": "T1133 - External Remote Services",
        "recommended_action": "Verify user activity, check impossible travel, revoke active sessions, and require MFA reset if suspicious."
    },
    "web_attack": {
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "recommended_action": "Review request payloads, inspect web server logs, check for successful exploitation, and tune WAF rules."
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "recommended_action": "Identify destination, quantify data transferred, block destination, preserve logs, and determine data sensitivity."
    },
    "easter_egg_living_off_land": {
        "tactic": "Defense Evasion / Execution",
        "technique": "T1218 - System Binary Proxy Execution",
        "recommended_action": "Correlate proxy, DNS, EDR process, and firewall logs. Look for signed binaries launching unusual child processes or external connections."
    },
    "easter_egg_slow_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1048 - Exfiltration Over Alternative Protocol",
        "recommended_action": "Correlate small repeated uploads over time, DNS anomalies, proxy activity, and sensitive server access."
    },
    "easter_egg_identity_pivot": {
        "tactic": "Lateral Movement / Credential Access",
        "technique": "T1021 - Remote Services",
        "recommended_action": "Correlate VPN, IAM, endpoint logon, admin share, and server access events for the same account across different assets."
    },
}

THREAT_TAXONOMY = {
    "Credential Attack": ["brute_force", "vpn_anomaly", "easter_egg_identity_pivot"],
    "Endpoint Compromise": ["suspicious_powershell", "malware_detected", "easter_egg_living_off_land"],
    "Network Reconnaissance": ["port_scan"],
    "Web Application Attack": ["web_attack"],
    "Data Loss / Exfiltration": ["data_exfiltration", "easter_egg_slow_exfiltration"],
    "Stealth / Easter Egg": ["easter_egg_living_off_land", "easter_egg_slow_exfiltration", "easter_egg_identity_pivot"],
}
