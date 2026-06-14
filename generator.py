import json
import random
import uuid
from datetime import datetime
from ipaddress import IPv4Address

from database import execute, query_df, query_one
from mitre import MITRE_MAP, THREAT_TAXONOMY

FIRST_NAMES = ["ana", "ben", "carlo", "dina", "eric", "faye", "gina", "hugo", "ivan", "jane", "kim", "leo", "maya", "nina", "omar", "pia"]
LAST_NAMES = ["santos", "reyes", "cruz", "garcia", "dela_cruz", "lim", "tan", "ramos", "torres", "flores"]
PUBLIC_IPS = ["45.83.64.11", "103.21.244.9", "185.220.101.42", "203.0.113.50", "198.51.100.22", "91.219.236.15"]
COUNTRIES = ["PH", "SG", "US", "DE", "NL", "RU", "CN", "VN"]


def taxonomy_for(kind):
    for tax, kinds in THREAT_TAXONOMY.items():
        if kind in kinds and tax != "Stealth / Easter Egg":
            return tax
    return "Unclassified"


def username():
    return f"{random.choice(FIRST_NAMES)}.{random.choice(LAST_NAMES)}"


def private_ip(branch_index: int, host_index: int) -> str:
    return str(IPv4Address(f"10.{branch_index}.0.1") + host_index)


def save_org(config: dict):
    tools = ",".join(config.get("tools", []))
    execute(
        """
        INSERT OR REPLACE INTO organization
        (id, name, industry, branches, employees, windows_endpoints, linux_endpoints, mac_endpoints, onprem_servers, cloud_servers, tools)
        VALUES (1,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            config["name"], config["industry"], config["branches"], config["employees"],
            config["windows_endpoints"], config["linux_endpoints"], config["mac_endpoints"],
            config["onprem_servers"], config["cloud_servers"], tools
        )
    )


def generate_assets(config: dict):
    execute("DELETE FROM assets")
    branch_count = config["branches"]
    asset_id = 1

    def add_asset(hostname, asset_type, os_name, branch_num, owner, criticality):
        nonlocal asset_id
        execute(
            "INSERT INTO assets (hostname, asset_type, os, branch, ip_address, owner, criticality) VALUES (?,?,?,?,?,?,?)",
            (hostname, asset_type, os_name, f"Branch-{branch_num}", private_ip(branch_num, asset_id), owner, criticality)
        )
        asset_id += 1

    for i in range(config["windows_endpoints"]):
        b = (i % branch_count) + 1
        add_asset(f"WIN-{b:02d}-{i+1:03d}", "Endpoint", "Windows", b, username(), random.choice(["Low", "Medium", "Medium", "High"]))
    for i in range(config["linux_endpoints"]):
        b = (i % branch_count) + 1
        add_asset(f"LNX-{b:02d}-{i+1:03d}", "Endpoint", "Linux", b, username(), random.choice(["Low", "Medium", "High"]))
    for i in range(config["mac_endpoints"]):
        b = (i % branch_count) + 1
        add_asset(f"MAC-{b:02d}-{i+1:03d}", "Endpoint", "macOS", b, username(), random.choice(["Low", "Medium"]))
    for i in range(config["onprem_servers"]):
        b = (i % branch_count) + 1
        add_asset(f"SRV-{b:02d}-{i+1:03d}", "Server", random.choice(["Windows Server", "Linux"]), b, "IT Operations", random.choice(["High", "Critical"]))
    for i in range(config["cloud_servers"]):
        add_asset(f"CLD-APP-{i+1:03d}", "Cloud Server", random.choice(["Linux", "Windows Server"]), 1, "Cloud Team", random.choice(["High", "Critical"]))


def get_org_tools():
    row = query_one("SELECT tools FROM organization WHERE id=1")
    if not row or not row["tools"]:
        return ["Firewall", "EDR", "IDS", "VPN"]
    return [t.strip() for t in row["tools"].split(",") if t.strip()]


def insert_log(source_tool, log_type, severity, asset, user, src_ip, dst_ip, event_id, message, correlation_id=None, scenario_key=None, taxonomy=None, stealth=0):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw = json.dumps({
        "timestamp": timestamp, "source_tool": source_tool, "log_type": log_type, "severity": severity,
        "asset": asset, "username": user, "src_ip": src_ip, "dst_ip": dst_ip, "event_id": event_id,
        "message": message, "correlation_id": correlation_id, "scenario_key": scenario_key, "taxonomy": taxonomy,
        "stealth": bool(stealth)
    })
    return execute(
        """
        INSERT INTO logs (timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message, raw, correlation_id, scenario_key, taxonomy, stealth)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (timestamp, source_tool, log_type, severity, asset, user, src_ip, dst_ip, event_id, message, raw, correlation_id, scenario_key, taxonomy, stealth)
    )


def choose_analyst():
    df = query_df("SELECT id FROM analysts WHERE active=1")
    if df.empty:
        return None
    return int(df.sample(1).iloc[0]["id"])


def insert_alert(kind, severity, source_tool, asset, user, description, related_log_id, correlation_id=None, hidden=0):
    mitre = MITRE_MAP[kind]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    titles = {
        "brute_force": "Multiple failed login attempts detected",
        "suspicious_powershell": "Suspicious PowerShell activity",
        "malware_detected": "Malware detection on endpoint",
        "port_scan": "Possible internal or external port scan",
        "vpn_anomaly": "Unusual VPN login pattern",
        "web_attack": "Possible web application attack",
        "data_exfiltration": "Possible data exfiltration attempt",
        "easter_egg_living_off_land": "Analyst-discovered living-off-the-land pattern",
        "easter_egg_slow_exfiltration": "Analyst-discovered slow data exfiltration pattern",
        "easter_egg_identity_pivot": "Analyst-discovered identity pivot across assets",
    }
    return execute(
        """
        INSERT INTO alerts (timestamp, title, severity, status, source_tool, asset, username, tactic, technique, description, recommended_action, related_log_id, assigned_to, correlation_id, scenario_key, taxonomy, hidden_from_siem)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (timestamp, titles[kind], severity, "New", source_tool, asset, user, mitre["tactic"], mitre["technique"], description, mitre["recommended_action"], related_log_id, choose_analyst(), correlation_id, kind, taxonomy_for(kind), hidden)
    )


def normal_log():
    assets = query_df("SELECT * FROM assets")
    if assets.empty:
        return
    a = assets.sample(1).iloc[0]
    tools = get_org_tools()
    tool = random.choice(tools)
    user = a["owner"] if a["owner"] != "IT Operations" else username()
    src_ip = a["ip_address"]
    dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "10.0.0.10", "10.0.0.20", "172.16.10.5"])
    event = random.choice([
        ("Authentication", "Info", "4624", f"Successful login for {user}"),
        ("Network", "Info", "ALLOW", f"Allowed outbound connection from {src_ip} to {dst_ip}"),
        ("Endpoint", "Info", "HEALTH", f"Endpoint health check completed for {a['hostname']}"),
        ("DNS", "Info", "QUERY", "DNS query allowed for software-update.example.com"),
        ("Web", "Info", "200", "HTTP request completed successfully"),
    ])
    insert_log(tool, *event, a["hostname"], user, src_ip, dst_ip)


def scenario_log():
    assets = query_df("SELECT * FROM assets")
    if assets.empty:
        return
    a = assets.sample(1).iloc[0]
    tools = get_org_tools()
    kind = random.choice(["brute_force", "suspicious_powershell", "malware_detected", "port_scan", "vpn_anomaly", "web_attack", "data_exfiltration"])
    user = a["owner"] if a["owner"] not in ["IT Operations", "Cloud Team"] else username()
    src_ip = random.choice(PUBLIC_IPS)
    dst_ip = a["ip_address"]
    corr = f"CORR-{uuid.uuid4().hex[:8].upper()}"
    tax = taxonomy_for(kind)

    if kind == "brute_force":
        tool = "EDR" if "EDR" in tools else "Windows Event Log"
        msg = f"12 failed login attempts for {user} from {src_ip} within 5 minutes"
        log_id = insert_log(tool, "Authentication", "Medium", a["hostname"], user, src_ip, dst_ip, "4625", msg, corr, kind, tax)
        insert_alert(kind, "Medium", tool, a["hostname"], user, msg, log_id, corr)
    elif kind == "suspicious_powershell":
        tool = "EDR" if "EDR" in tools else "Windows Event Log"
        msg = "Encoded PowerShell command with outbound network connection observed"
        log_id = insert_log(tool, "Process", "High", a["hostname"], user, a["ip_address"], src_ip, "POWERSHELL_ENCODED", msg, corr, kind, tax)
        insert_alert(kind, "High", tool, a["hostname"], user, msg, log_id, corr)
    elif kind == "malware_detected":
        tool = "EDR" if "EDR" in tools else "Antivirus"
        msg = "Malware signature detected: Trojan.Generic.Simulated on downloaded file"
        log_id = insert_log(tool, "Malware", "High", a["hostname"], user, a["ip_address"], "N/A", "MALWARE_BLOCKED", msg, corr, kind, tax)
        insert_alert(kind, "High", tool, a["hostname"], user, msg, log_id, corr)
    elif kind == "port_scan":
        tool = "IDS" if "IDS" in tools else "Firewall"
        msg = f"High number of denied connection attempts from {src_ip} to multiple ports"
        log_id = insert_log(tool, "Network", "Medium", a["hostname"], "N/A", src_ip, dst_ip, "PORT_SCAN", msg, corr, kind, tax)
        insert_alert(kind, "Medium", tool, a["hostname"], "N/A", msg, log_id, corr)
    elif kind == "vpn_anomaly":
        tool = "VPN" if "VPN" in tools else "IAM"
        country = random.choice(COUNTRIES)
        msg = f"VPN login for {user} from unusual country={country}, source_ip={src_ip}"
        log_id = insert_log(tool, "Remote Access", "Medium", "VPN-Gateway", user, src_ip, "10.0.0.1", "VPN_LOGIN_ANOMALY", msg, corr, kind, tax)
        insert_alert(kind, "Medium", tool, "VPN-Gateway", user, msg, log_id, corr)
    elif kind == "web_attack":
        tool = "WAF" if "WAF" in tools else "Web Server"
        payload = random.choice(["' OR '1'='1", "../../../../etc/passwd", "<script>alert(1)</script>"])
        msg = f"Suspicious web request blocked. URI=/login payload={payload}"
        log_id = insert_log(tool, "Web", "Medium", a["hostname"], "anonymous", src_ip, dst_ip, "WEB_ATTACK", msg, corr, kind, tax)
        insert_alert(kind, "Medium", tool, a["hostname"], "anonymous", msg, log_id, corr)
    else:
        tool = "Firewall" if "Firewall" in tools else random.choice(tools)
        mb = random.randint(500, 2000)
        msg = f"Unusual outbound transfer volume {mb}MB from {a['hostname']} to {src_ip}"
        log_id = insert_log(tool, "Network", "High", a["hostname"], user, a["ip_address"], src_ip, "LARGE_UPLOAD", msg, corr, kind, tax)
        insert_alert(kind, "High", tool, a["hostname"], user, msg, log_id, corr)


def easter_egg_attack():
    assets = query_df("SELECT * FROM assets")
    if len(assets) < 2:
        return
    tools = get_org_tools()
    scenario = random.choice(["easter_egg_living_off_land", "easter_egg_slow_exfiltration", "easter_egg_identity_pivot"])
    corr = f"EGG-{uuid.uuid4().hex[:8].upper()}"
    tax = taxonomy_for(scenario)
    sample = assets.sample(min(3, len(assets)))
    user = sample.iloc[0]["owner"] if sample.iloc[0]["owner"] not in ["IT Operations", "Cloud Team"] else username()
    c2 = random.choice(["cdn-update-check.net", "storage-sync-cdn.com", "graph-api-login.com"])

    if scenario == "easter_egg_living_off_land":
        a = sample.iloc[0]
        # Low/medium logs only. No automatic alert. Students must correlate.
        insert_log("EDR" if "EDR" in tools else "Windows Event Log", "Process", "Low", a["hostname"], user, a["ip_address"], "N/A", "PROC_CREATE", "rundll32.exe launched with unusual DLL export from user temp path", corr, scenario, tax, 1)
        insert_log("DNS", "DNS", "Info", a["hostname"], user, a["ip_address"], "8.8.8.8", "QUERY", f"DNS query for {c2}", corr, scenario, tax, 1)
        insert_log("Firewall" if "Firewall" in tools else "Proxy", "Network", "Low", a["hostname"], user, a["ip_address"], random.choice(PUBLIC_IPS), "ALLOW", "Allowed outbound TLS connection to low-reputation newly observed domain", corr, scenario, tax, 1)
    elif scenario == "easter_egg_slow_exfiltration":
        for _, a in sample.iterrows():
            insert_log("DLP" if "DLP" in tools else "Proxy", "Web Upload", "Low", a["hostname"], user, a["ip_address"], random.choice(PUBLIC_IPS), "UPLOAD_SMALL", "Repeated small encrypted uploads below DLP threshold", corr, scenario, tax, 1)
        insert_log("DNS", "DNS", "Info", sample.iloc[0]["hostname"], user, sample.iloc[0]["ip_address"], "8.8.8.8", "TXT_QUERY", "Unusual TXT lookup length observed", corr, scenario, tax, 1)
    else:
        src = sample.iloc[0]
        dst = sample.iloc[1]
        insert_log("VPN" if "VPN" in tools else "IAM", "Remote Access", "Info", "VPN-Gateway", user, random.choice(PUBLIC_IPS), "10.0.0.1", "VPN_LOGIN", "Successful VPN login using valid credentials", corr, scenario, tax, 1)
        insert_log("Windows Event Log", "Authentication", "Info", src["hostname"], user, src["ip_address"], src["ip_address"], "4624", "Interactive login shortly after VPN access", corr, scenario, tax, 1)
        insert_log("Windows Event Log", "Lateral Movement", "Low", dst["hostname"], user, src["ip_address"], dst["ip_address"], "ADMIN_SHARE", "Admin share access observed from workstation to server", corr, scenario, tax, 1)


def reveal_easter_egg(correlation_id):
    logs = query_df("SELECT * FROM logs WHERE correlation_id=? ORDER BY id", [correlation_id])
    if logs.empty:
        return None
    first = logs.iloc[0]
    kind = first["scenario_key"]
    msg = f"Manual analyst correlation revealed hidden scenario {kind}. Related logs: {len(logs)}, assets: {logs['asset'].nunique()}, tools: {logs['source_tool'].nunique()}."
    return insert_alert(kind, "Critical", "Analyst Correlation", first["asset"], first["username"], msg, int(first["id"]), correlation_id, hidden=1)


def generate_tick(alert_probability: float = 0.08, easter_egg_probability: float = 0.02):
    for _ in range(random.randint(1, 4)):
        normal_log()
    if random.random() < alert_probability:
        scenario_log()
    if random.random() < easter_egg_probability:
        easter_egg_attack()


def seed_demo_data():
    config = {
        "name": "Demo Finance Cooperative", "industry": "Finance", "branches": 3, "employees": 120,
        "windows_endpoints": 45, "linux_endpoints": 8, "mac_endpoints": 4, "onprem_servers": 6, "cloud_servers": 3,
        "tools": ["Firewall", "EDR", "IDS", "VPN", "WAF", "Email Gateway", "DLP"]
    }
    save_org(config)
    generate_assets(config)
    for analyst in [("SOC Analyst 1", "L1 Analyst", "Blue Team", "Day", "Beginner"), ("Incident Handler", "L2 Analyst", "Blue Team", "Day", "Intermediate"), ("SOC Lead", "Lead", "Blue Team", "Day", "Advanced")]:
        execute("INSERT INTO analysts (name, role, team, shift, skill_level) VALUES (?,?,?,?,?)", analyst)
    for _ in range(50):
        normal_log()
    for _ in range(5):
        scenario_log()
    for _ in range(2):
        easter_egg_attack()
