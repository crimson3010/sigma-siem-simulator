import time
import random
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from database import execute, init_db, query_df, query_one, reset_db
from generator import generate_assets, generate_tick, reveal_easter_egg, save_org, seed_demo_data
from mitre import THREAT_TAXONOMY



# -----------------------------
# Banking Class Demo Dataset
# -----------------------------
def insert_row(table, values):
    """Insert only the columns that exist in the current SQLite table.
    This keeps the demo compatible even if the database schema changes slightly.
    """
    table_info = query_df(f"PRAGMA table_info({table})")
    if table_info.empty:
        return
    available = set(table_info["name"].tolist())
    filtered = {k: v for k, v in values.items() if k in available}
    if not filtered:
        return
    cols = list(filtered.keys())
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    execute(sql, [filtered[c] for c in cols])


def load_banking_class_demo():
    """Create a beginner-friendly banking SOC exercise dataset.

    Scenario: Digital bank with 500 endpoints, hybrid infrastructure, noisy low/info
    alerts, and several hidden attack chains for student correlation work.
    """
    reset_db()
    random.seed(20260614)

    config = {
        "name": "Aureus Digital Bank",
        "industry": "Finance",
        "branches": 8,
        "employees": 850,
        "windows_endpoints": 430,
        "linux_endpoints": 45,
        "mac_endpoints": 25,
        "onprem_servers": 35,
        "cloud_servers": 65,
        "tools": ["Firewall", "EDR", "IDS", "IPS", "WAF", "VPN", "Email Gateway", "Proxy", "IAM", "CloudTrail", "DLP"],
    }
    save_org(config)
    generate_assets(config)

    analysts = [
        ("Group 1 - L1 SOC", "L1 Analyst", "Blue Team Group 1", "Class Group", "Beginner"),
        ("Group 2 - L1 SOC", "L1 Analyst", "Blue Team Group 2", "Class Group", "Beginner"),
        ("Group 3 - L1 SOC", "L1 Analyst", "Blue Team Group 3", "Class Group", "Beginner"),
        ("Group 4 - L1 SOC", "L1 Analyst", "Blue Team Group 4", "Class Group", "Beginner"),
        ("Group 5 - L1 SOC", "L1 Analyst", "Blue Team Group 5", "Class Group", "Beginner"),
        ("SOC Lead - Instructor", "SOC Lead", "Instructor", "Class Group", "Advanced"),
        ("L2 Escalation Desk", "L2 Analyst", "Instructor", "Class Group", "Intermediate"),
        ("Incident Handler", "Incident Handler", "Instructor", "Class Group", "Advanced"),
    ]
    for analyst in analysts:
        execute("INSERT INTO analysts (name, role, team, shift, skill_level) VALUES (?,?,?,?,?)", list(analyst))

    analyst_ids_df = query_df("SELECT id FROM analysts WHERE active=1 ORDER BY id")
    analyst_ids = analyst_ids_df["id"].tolist() if not analyst_ids_df.empty else [None]

    endpoint_assets = [f"HQ-WIN-{i:03d}" for i in range(1, 181)]
    endpoint_assets += [f"BRANCH-TELLER-{i:03d}" for i in range(1, 201)]
    endpoint_assets += [f"LAPTOP-EXEC-{i:03d}" for i in range(1, 31)]
    endpoint_assets += [f"DEV-LINUX-{i:03d}" for i in range(1, 46)]
    endpoint_assets += [f"MAC-FINANCE-{i:03d}" for i in range(1, 26)]
    infra_assets = [
        "AD-DC-01", "AD-DC-02", "CORE-BANKING-DB-01", "CORE-BANKING-APP-01",
        "PAYMENT-GATEWAY-01", "ONLINE-BANKING-WEB-01", "ONLINE-BANKING-WEB-02",
        "VPN-GW-01", "WAF-01", "DLP-01", "SWIFT-JUMPHOST-01", "SIEM-COLLECTOR-01",
        "AWS-IAM", "AWS-CLOUDTRAIL", "AWS-S3-CUSTOMER-DATA", "AZURE-AD", "M365-EXCHANGE",
    ]
    assets_pool = endpoint_assets + infra_assets
    users = [
        "j.santos", "m.cruz", "a.reyes", "r.garcia", "p.dela_cerna", "l.tan",
        "c.yap", "teller01", "teller02", "branch.manager", "admin.ops", "svc_backup", "svc_payments",
    ]
    src_ips = [
        "10.10.5.21", "10.20.8.44", "10.30.12.9", "172.16.1.50", "192.168.50.77",
        "185.220.101.45", "45.155.204.88", "103.155.217.18", "91.240.118.172",
    ]
    dst_ips = ["10.1.1.10", "10.2.2.25", "10.3.3.30", "10.5.5.15", "52.95.110.1", "20.190.128.1"]

    alert_distribution = ["Info"] * 350 + ["Low"] * 400 + ["Medium"] * 150 + ["High"] * 80 + ["Critical"] * 20
    templates = [
        ("Firewall", "Firewall Deny", "Network Security", "network_noise", "Reconnaissance", "T1595", "Active Scanning", "Blocked inbound connection attempt"),
        ("EDR", "Endpoint Policy Violation", "Endpoint Security", "endpoint_noise", "Defense Evasion", "T1562", "Impair Defenses", "Endpoint policy violation detected"),
        ("VPN", "Failed VPN Login", "Credential Attack", "credential_attack", "Credential Access", "T1110", "Brute Force", "Multiple failed VPN authentication attempts"),
        ("Email Gateway", "Suspicious Email Attachment", "Phishing", "phishing", "Initial Access", "T1566", "Phishing", "Suspicious attachment quarantined"),
        ("WAF", "Blocked SQL Injection Attempt", "Web Attack", "web_attack", "Initial Access", "T1190", "Exploit Public-Facing Application", "WAF blocked suspicious SQL-like payload"),
        ("IAM", "Unusual Login Location", "Identity Security", "identity_anomaly", "Initial Access", "T1078", "Valid Accounts", "Login from unusual geography"),
        ("CloudTrail", "Cloud API Enumeration", "Cloud Security", "cloud_activity", "Discovery", "T1580", "Cloud Infrastructure Discovery", "Cloud API enumeration activity"),
        ("DLP", "Possible Sensitive Data Movement", "Data Protection", "data_movement", "Exfiltration", "T1041", "Exfiltration Over C2 Channel", "Low confidence DLP match"),
        ("Proxy", "Blocked Category Access", "User Activity", "policy_noise", "Command and Control", "T1102", "Web Service", "Proxy blocked suspicious category"),
        ("IDS", "Port Scan Detected", "Reconnaissance", "network_scan", "Reconnaissance", "T1046", "Network Service Discovery", "IDS detected horizontal scanning"),
    ]

    base = datetime.now() - timedelta(days=3)

    def add_log(ts, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message, correlation_id, taxonomy, scenario_key, stealth):
        insert_row("logs", {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_tool": source_tool,
            "log_type": log_type,
            "severity": severity,
            "asset": asset,
            "username": username,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "event_id": event_id,
            "message": message,
            "correlation_id": correlation_id,
            "taxonomy": taxonomy,
            "scenario_key": scenario_key,
            "stealth": int(stealth),
        })

    def add_alert(ts, title, severity, asset, username, src_ip, dst_ip, correlation_id, taxonomy, scenario_key, tactic, technique, description, recommended_action):
        insert_row("alerts", {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "title": title,
            "severity": severity,
            "status": "New",
            "assigned_to": random.choice(analyst_ids) if analyst_ids else None,
            "taxonomy": taxonomy,
            "scenario_key": scenario_key,
            "asset": asset,
            "username": username,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "tactic": tactic,
            "technique": technique,
            "description": description,
            "recommended_action": recommended_action,
            "correlation_id": correlation_id,
            "related_log_id": None,
            "analyst_severity": "",
            "analyst_classification": "",
            "disposition": "",
        })

    # Background logs and alerts. Low and Info are intentionally predominant.
    for i in range(1000):
        severity = alert_distribution[i]
        source_tool, title, taxonomy, scenario_key, tactic, technique_id, technique, message = random.choice(templates)
        asset = random.choice(assets_pool)
        username = random.choice(users)
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        ts = base + timedelta(minutes=random.randint(1, 4320))
        corr = f"BANK-NOISE-{i+1:04d}"
        add_log(ts, source_tool, title, severity, asset, username, src_ip, dst_ip, technique_id, message, corr, taxonomy, scenario_key, 0)
        add_alert(
            ts, title, severity, asset, username, src_ip, dst_ip, corr, taxonomy, scenario_key,
            tactic, f"{technique_id} - {technique}",
            f"Banking demo alert: {message}. This may be routine noise or may require triage based on context.",
            "Review related logs, validate asset criticality, check user behavior, and document analyst assessment.",
        )

    hidden_chains = [
        {
            "name": "Credential Compromise / Account Takeover",
            "taxonomy": "Credential Attack",
            "scenario_key": "banking_credential_takeover",
            "tactic": "Credential Access",
            "technique": "T1110 / T1078 - Brute Force followed by Valid Accounts",
            "severity": "Critical",
            "user": "m.cruz",
            "asset": "VPN-GW-01",
            "src_ip": "185.220.101.45",
            "events": [
                ("VPN", "Failed VPN Login Burst", "Low", "Multiple failed VPN logins from foreign IP"),
                ("VPN", "Successful VPN Login After Failures", "Medium", "Successful VPN login after repeated failures"),
                ("IAM", "Impossible Travel Login", "High", "Same user authenticated from distant locations within an impossible time window"),
                ("IAM", "New MFA Device Registered", "Medium", "New MFA device registered shortly after suspicious login"),
                ("SIEM", "Privileged Banking App Access", "High", "Privileged online banking access by compromised user"),
                ("DLP", "Customer Transaction Export", "Critical", "Large transaction export initiated by suspicious session"),
            ],
            "action": "Disable the account, revoke sessions, reset credentials, validate MFA enrollment, and review transaction activity.",
        },
        {
            "name": "Insider Data Exfiltration",
            "taxonomy": "Insider Threat",
            "scenario_key": "banking_insider_exfiltration",
            "tactic": "Exfiltration",
            "technique": "T1020 / T1052 - Automated Exfiltration and Removable Media",
            "severity": "High",
            "user": "branch.manager",
            "asset": "BRANCH-TELLER-044",
            "src_ip": "10.20.8.44",
            "events": [
                ("SIEM", "After-Hours Customer Record Access", "Low", "Employee accessed customer records outside normal schedule"),
                ("EDR", "USB Mass Storage Detected", "Low", "USB storage device connected to banking workstation"),
                ("EDR", "Large File Compression", "Medium", "Large archive file created in user profile"),
                ("Proxy", "Upload to Personal Cloud Storage", "Medium", "Outbound upload to personal cloud storage service"),
                ("DLP", "Low Confidence DLP Match", "High", "Possible customer information in outbound transfer"),
            ],
            "action": "Preserve endpoint evidence, review access authorization, validate DLP content, and escalate to incident handler.",
        },
        {
            "name": "Ransomware Precursor / Lateral Movement",
            "taxonomy": "Ransomware",
            "scenario_key": "banking_ransomware_precursor",
            "tactic": "Lateral Movement",
            "technique": "T1059 / T1021 - PowerShell and Remote Services",
            "severity": "Critical",
            "user": "admin.ops",
            "asset": "AD-DC-01",
            "src_ip": "10.10.5.21",
            "events": [
                ("EDR", "Encoded PowerShell Command", "Medium", "Encoded PowerShell command executed on endpoint"),
                ("IDS", "SMB Scanning Detected", "Medium", "Host scanned multiple SMB services"),
                ("SIEM", "Failed Admin Share Access", "Low", "Repeated failed access to administrative shares"),
                ("EDR", "Process Injection Alert", "High", "Suspicious process injection into trusted process"),
                ("EDR", "Shadow Copy Deletion Attempt", "Critical", "Attempt to delete volume shadow copies"),
            ],
            "action": "Isolate host, disable suspect admin credentials, search for lateral movement, and start ransomware containment procedure.",
        },
        {
            "name": "Cloud Misconfiguration Abuse",
            "taxonomy": "Cloud Security",
            "scenario_key": "banking_cloud_abuse",
            "tactic": "Collection",
            "technique": "T1530 / T1580 - Data from Cloud Storage and Cloud Discovery",
            "severity": "High",
            "user": "svc_backup",
            "asset": "AWS-S3-CUSTOMER-DATA",
            "src_ip": "91.240.118.172",
            "events": [
                ("CloudTrail", "New IAM Access Key Created", "Medium", "New IAM access key created for service account"),
                ("CloudTrail", "Unusual S3 Bucket Enumeration", "Low", "Multiple S3 bucket list operations observed"),
                ("CloudTrail", "Public Bucket Access Detected", "Medium", "Public access pattern detected against customer data bucket"),
                ("DLP", "Large Cloud Data Download", "High", "Large data download from cloud storage"),
                ("IAM", "Access from Unusual ASN", "High", "Cloud access observed from unusual ASN"),
            ],
            "action": "Revoke IAM key, review bucket policy, check CloudTrail, and validate customer data exposure.",
        },
        {
            "name": "Online Banking WAF Bypass",
            "taxonomy": "Web Attack",
            "scenario_key": "banking_waf_bypass",
            "tactic": "Initial Access",
            "technique": "T1190 - Exploit Public-Facing Application",
            "severity": "High",
            "user": "anonymous",
            "asset": "ONLINE-BANKING-WEB-01",
            "src_ip": "45.155.204.88",
            "events": [
                ("WAF", "Repeated SQL Injection Blocked", "Low", "WAF blocked repeated SQL injection attempts"),
                ("WAF", "Suspicious Parameter Tampering", "Low", "Suspicious parameter manipulation detected"),
                ("WAF", "HTTP 403 Spike", "Info", "Increase in forbidden responses from same source"),
                ("WAF", "HTTP 200 After Attack Pattern", "Medium", "Successful response observed after repeated blocked attempts"),
                ("SIEM", "Possible Authentication Bypass", "High", "Application behavior suggests possible authentication bypass"),
            ],
            "action": "Review web logs, validate application response, block source IP, and escalate to application security team.",
        },
    ]

    for idx, chain in enumerate(hidden_chains, start=1):
        corr = f"BANK-EASTER-{idx:02d}"
        chain_start = base + timedelta(hours=12 + idx * 5)
        for offset, (source_tool, log_type, severity, message) in enumerate(chain["events"]):
            ts = chain_start + timedelta(minutes=offset * random.randint(9, 24))
            add_log(
                ts, source_tool, log_type, severity, chain["asset"], chain["user"], chain["src_ip"],
                random.choice(dst_ips), chain["technique"].split()[0], message, corr,
                chain["taxonomy"], chain["scenario_key"], 1,
            )
        # Add a few system alerts, but the complete story is only obvious in correlation.
        add_alert(
            chain_start + timedelta(minutes=30), f"Possible {chain['name']}", chain["severity"],
            chain["asset"], chain["user"], chain["src_ip"], random.choice(dst_ips), corr,
            chain["taxonomy"], chain["scenario_key"], chain["tactic"], chain["technique"],
            f"Potential hidden attack chain in the banking demo: {chain['name']}. Students should correlate related logs before final classification.",
            chain["action"],
        )

    execute("INSERT INTO notes (alert_id, analyst, note) VALUES (?,?,?)", [1, "Instructor", "Banking class demo loaded. Students should identify noisy alerts, prioritize severe alerts, and hunt for hidden correlated attack chains."])


st.set_page_config(page_title="SIGMA SIEM Simulator", layout="wide")
init_db()

st.title("SIGMA SIEM Simulator")
st.caption("Synthetic SIEM lab with live logs, alert triage, analyst assignment, hidden attacks, and correlation analysis.")

st.info("""
**Class Activity Mode:** Load the **Banking Class Demo** from the sidebar. Students act as SOC analyst groups for a digital bank with 500 endpoints and hybrid infrastructure. Their goal is to triage alerts, document findings, identify false positives, correlate related logs, and discover hidden attack chains.
""")

with st.sidebar:
    st.header("Simulation Controls")
    auto_refresh = st.toggle("Run live simulation", value=False)
    alert_rate = st.slider("Recognized alert frequency", min_value=1, max_value=30, value=8)
    easter_rate = st.slider("Hidden easter egg frequency", min_value=0, max_value=20, value=3, help="These generate correlated suspicious logs but no automatic SIEM alert.")
    tick_delay = st.slider("Refresh delay in seconds", min_value=2, max_value=30, value=5)

    if st.button("Generate one tick now"):
        generate_tick(alert_probability=alert_rate / 100, easter_egg_probability=easter_rate / 100)
        st.success("Generated new logs.")

    if st.button("Load demo data"):
        reset_db()
        seed_demo_data()
        st.success("Demo organization, analysts, logs, alerts, and hidden attacks loaded.")

    if st.button("Load Banking Class Demo"):
        load_banking_class_demo()
        st.success("Banking class demo loaded: 500 endpoints, hybrid infrastructure, noisy alerts, and hidden attack chains.")

    if st.button("Reset all data", type="secondary"):
        reset_db()
        st.warning("All simulator data has been reset.")

if auto_refresh:
    generate_tick(alert_probability=alert_rate / 100, easter_egg_probability=easter_rate / 100)

org = query_one("SELECT * FROM organization WHERE id=1")

tabs = st.tabs([
    "1. Organization Setup", "2. Analysts", "3. SOC Dashboard", "4. Live Logs",
    "5. Alert Triage", "6. Threat Taxonomy", "7. Hidden Easter Eggs", "8. Assets", "9. Export"
])
setup_tab, analysts_tab, dashboard_tab, logs_tab, alerts_tab, taxonomy_tab, easter_tab, assets_tab, report_tab = tabs

with setup_tab:
    st.subheader("Create the Simulated Organization")
    with st.form("org_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            name = st.text_input("Organization name", value="Sample Organization")
            industry = st.selectbox("Industry", ["Finance", "Business", "Academe", "Education", "Government", "Healthcare", "Retail"])
            branches = st.number_input("Number of branches", min_value=1, max_value=10, value=3)
            employees = st.number_input("Number of employees", min_value=10, max_value=10000, value=120)
        with col2:
            windows_endpoints = st.number_input("Windows endpoints", min_value=0, max_value=5000, value=50)
            linux_endpoints = st.number_input("Linux endpoints", min_value=0, max_value=5000, value=10)
            mac_endpoints = st.number_input("macOS endpoints", min_value=0, max_value=5000, value=5)
        with col3:
            onprem_servers = st.number_input("On-prem servers", min_value=0, max_value=500, value=6)
            cloud_servers = st.number_input("Cloud servers", min_value=0, max_value=500, value=3)
            tools = st.multiselect(
                "Security tools available",
                ["Firewall", "EDR", "IDS", "IPS", "WAF", "VPN", "Email Gateway", "Proxy", "IAM", "CloudTrail", "DLP"],
                default=["Firewall", "EDR", "IDS", "VPN", "WAF"]
            )
        submitted = st.form_submit_button("Create / Regenerate Environment")

    if submitted:
        config = {
            "name": name, "industry": industry, "branches": int(branches), "employees": int(employees),
            "windows_endpoints": int(windows_endpoints), "linux_endpoints": int(linux_endpoints), "mac_endpoints": int(mac_endpoints),
            "onprem_servers": int(onprem_servers), "cloud_servers": int(cloud_servers), "tools": tools,
        }
        save_org(config)
        generate_assets(config)
        st.success("Environment generated. Add analysts next, then run the simulation.")

    if org:
        st.info(f"Current environment: {org['name']} | {org['industry']} | Branches: {org['branches']} | Employees: {org['employees']} | Tools: {org['tools']}")
    else:
        st.warning("No organization configured yet. Create one or load demo data from the sidebar.")

with analysts_tab:
    st.subheader("Analysts and Ticket Assignment")
    st.write("Create classroom SOC analysts. New alerts are auto-assigned randomly to active analysts, but you can reassign them during triage.")
    with st.form("analyst_form"):
        c1, c2, c3, c4, c5 = st.columns(5)
        name = c1.text_input("Name", value="Student Analyst")
        role = c2.selectbox("Role", ["L1 Analyst", "L2 Analyst", "Incident Handler", "SOC Lead", "Threat Hunter"])
        team = c3.text_input("Team", value="Blue Team")
        shift = c4.selectbox("Shift", ["Day", "Mid", "Night", "Class Group"])
        skill = c5.selectbox("Skill level", ["Beginner", "Intermediate", "Advanced"])
        if st.form_submit_button("Add analyst"):
            execute("INSERT INTO analysts (name, role, team, shift, skill_level) VALUES (?,?,?,?,?)", [name, role, team, shift, skill])
            st.success("Analyst added.")
    analysts = query_df("SELECT id, name, role, team, shift, skill_level, active FROM analysts ORDER BY id")
    st.dataframe(analysts, use_container_width=True)

with dashboard_tab:
    st.subheader("SOC Overview")
    logs = query_df("SELECT * FROM logs ORDER BY id DESC LIMIT 500")
    alerts = query_df("SELECT a.*, an.name AS assigned_name FROM alerts a LEFT JOIN analysts an ON a.assigned_to=an.id ORDER BY a.id DESC LIMIT 500")
    assets = query_df("SELECT * FROM assets")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Assets", len(assets))
    c2.metric("Logs", len(logs))
    c3.metric("Open Alerts", int((alerts["status"] != "Closed").sum()) if not alerts.empty else 0)
    c4.metric("High/Critical", int(alerts["severity"].isin(["High", "Critical"]).sum()) if not alerts.empty else 0)
    c5.metric("Hidden Logs", int((logs["stealth"] == 1).sum()) if not logs.empty and "stealth" in logs else 0)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("#### Alerts by Severity")
        if not alerts.empty:
            st.bar_chart(alerts["severity"].value_counts())
        else:
            st.write("No alerts yet.")
    with col_b:
        st.markdown("#### Logs by Source Tool")
        if not logs.empty:
            st.bar_chart(logs["source_tool"].value_counts())
        else:
            st.write("No logs yet.")

    st.markdown("#### Latest Alerts")
    cols = ["id", "timestamp", "title", "severity", "analyst_severity", "status", "assigned_name", "taxonomy", "asset", "username", "technique"]
    st.dataframe(alerts[cols] if not alerts.empty else alerts, use_container_width=True)

with logs_tab:
    st.subheader("Live Log Feed")
    col1, col2, col3 = st.columns(3)
    severity_filter = col1.multiselect("Severity", ["Info", "Low", "Medium", "High", "Critical"], default=[])
    tool_filter = col2.multiselect("Source tool", query_df("SELECT DISTINCT source_tool FROM logs ORDER BY source_tool")["source_tool"].dropna().tolist() if not query_df("SELECT DISTINCT source_tool FROM logs").empty else [], default=[])
    show_stealth = col3.checkbox("Show only possible hidden/easter egg logs", value=False)

    q = "SELECT id, timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message, correlation_id, taxonomy, stealth FROM logs"
    where, params = [], []
    if severity_filter:
        where.append("severity IN (%s)" % ",".join(["?"] * len(severity_filter)))
        params.extend(severity_filter)
    if tool_filter:
        where.append("source_tool IN (%s)" % ",".join(["?"] * len(tool_filter)))
        params.extend(tool_filter)
    if show_stealth:
        where.append("stealth=1")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY id DESC LIMIT 500"
    st.dataframe(query_df(q, params), use_container_width=True, height=550)

with alerts_tab:
    st.subheader("Alert Triage and Investigation")
    alerts = query_df("SELECT a.*, an.name AS assigned_name FROM alerts a LEFT JOIN analysts an ON a.assigned_to=an.id ORDER BY a.id DESC LIMIT 300")
    analysts = query_df("SELECT id, name FROM analysts WHERE active=1 ORDER BY name")
    if alerts.empty:
        st.info("No alerts yet. Generate logs or load demo data.")
    else:
        selected = st.selectbox("Select alert ID", alerts["id"].tolist(), format_func=lambda x: f"Alert #{x}")
        alert = query_df("SELECT a.*, an.name AS assigned_name FROM alerts a LEFT JOIN analysts an ON a.assigned_to=an.id WHERE a.id=?", [selected]).iloc[0]
        st.markdown(f"### {alert['title']}")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("System Severity", alert["severity"])
        c2.metric("Status", alert["status"])
        c3.metric("Assigned", alert["assigned_name"] if pd.notna(alert["assigned_name"]) else "Unassigned")
        c4.metric("Taxonomy", alert["taxonomy"] or "Unclassified")
        c5.metric("Analyst Severity", alert["analyst_severity"] if pd.notna(alert.get("analyst_severity", None)) and alert.get("analyst_severity", "") else "Not set")
        st.caption(f"Correlation: {alert['correlation_id'] or 'None'}")

        st.write("**Description:**", alert["description"])
        st.write("**MITRE ATT&CK:**", f"{alert['tactic']} | {alert['technique']}")
        st.write("**Recommended action:**", alert["recommended_action"])

        if alert["correlation_id"]:
            related = query_df("SELECT id, timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message FROM logs WHERE correlation_id=? ORDER BY id", [alert["correlation_id"]])
        else:
            related = query_df("SELECT id, timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message FROM logs WHERE id=?", [int(alert["related_log_id"])])
        with st.expander("Related/correlated logs", expanded=True):
            st.dataframe(related, use_container_width=True)

        with st.form("triage_form"):
            st.markdown("#### Update Ticket")
            ca, cb, cc, cd = st.columns(4)
            new_status = ca.selectbox("Status", ["New", "Investigating", "Escalated", "Closed"], index=["New", "Investigating", "Escalated", "Closed"].index(alert["status"]) if alert["status"] in ["New", "Investigating", "Escalated", "Closed"] else 0)
            analyst_options = {"Unassigned": None}
            analyst_options.update({r["name"]: int(r["id"]) for _, r in analysts.iterrows()})
            current_name = alert["assigned_name"] if pd.notna(alert["assigned_name"]) else "Unassigned"
            assigned_name = cb.selectbox("Assign to", list(analyst_options.keys()), index=list(analyst_options.keys()).index(current_name) if current_name in analyst_options else 0)
            analyst_severity_options = ["", "Critical", "High", "Medium", "Low", "Info", "False Positive"]
            current_analyst_severity = alert["analyst_severity"] if "analyst_severity" in alert.index and pd.notna(alert["analyst_severity"]) else ""
            analyst_severity = cc.selectbox(
                "Analyst Severity",
                analyst_severity_options,
                index=analyst_severity_options.index(current_analyst_severity) if current_analyst_severity in analyst_severity_options else 0,
                help="Analyst-assigned severity after triage. This may upgrade, downgrade, or mark the alert as False Positive."
            )
            disposition = cd.selectbox("Disposition", ["", "Confirmed Malicious", "Suspicious", "Benign", "Policy Violation", "Resolved"])
            classification = st.selectbox("Analyst classification", ["", "True Positive", "False Positive", "Benign True Positive", "Needs More Evidence", "Duplicate"])
            analyst_name = st.text_input("Note analyst name", value=current_name if current_name != "Unassigned" else "Student Analyst")
            note = st.text_area("Investigation note")
            if st.form_submit_button("Save triage update"):
                execute("UPDATE alerts SET status=?, assigned_to=?, analyst_severity=?, analyst_classification=?, disposition=? WHERE id=?", [new_status, analyst_options[assigned_name], analyst_severity, classification, disposition, int(selected)])
                if note.strip():
                    execute("INSERT INTO notes (alert_id, analyst, note) VALUES (?,?,?)", [int(selected), analyst_name, note.strip()])
                st.success("Ticket updated.")

        notes = query_df("SELECT analyst, note, created_at FROM notes WHERE alert_id=? ORDER BY id DESC", [int(selected)])
        st.markdown("#### Investigation Notes")
        st.dataframe(notes, use_container_width=True)

with taxonomy_tab:
    st.subheader("Threat Taxonomy and Cross-Device Correlation")
    st.write("This view groups logs and alerts by threat category, scenario key, and correlation ID. It helps students identify attacks touching multiple devices or security tools.")
    logs = query_df("SELECT * FROM logs WHERE correlation_id IS NOT NULL ORDER BY id DESC LIMIT 1000")
    if logs.empty:
        st.info("No correlated logs yet.")
    else:
        summary = logs.groupby(["taxonomy", "scenario_key", "correlation_id"]).agg(
            log_count=("id", "count"),
            devices=("asset", "nunique"),
            tools=("source_tool", "nunique"),
            users=("username", "nunique"),
            latest=("timestamp", "max"),
            stealth_logs=("stealth", "sum")
        ).reset_index().sort_values(["stealth_logs", "log_count"], ascending=False)
        st.dataframe(summary, use_container_width=True)

        corr_ids = summary["correlation_id"].tolist()
        selected_corr = st.selectbox("Inspect correlation ID", corr_ids)
        detail = query_df("SELECT id, timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message, stealth FROM logs WHERE correlation_id=? ORDER BY id", [selected_corr])
        st.markdown("#### Correlated Event Timeline")
        st.dataframe(detail, use_container_width=True)

    st.markdown("#### Taxonomy Reference")
    ref = pd.DataFrame([{"Threat Taxonomy": k, "Scenario Keys": ", ".join(v)} for k, v in THREAT_TAXONOMY.items()])
    st.dataframe(ref, use_container_width=True)

with easter_tab:
    st.subheader("Hidden Easter Eggs / Analyst Discovery")
    st.write("These are correlated suspicious logs that the SIEM does not automatically alert on. Students must hunt, correlate, classify, and manually reveal/create the incident.")
    hidden = query_df("""
        SELECT correlation_id, scenario_key, taxonomy, COUNT(*) AS log_count,
               COUNT(DISTINCT asset) AS devices, COUNT(DISTINCT source_tool) AS tools,
               MAX(timestamp) AS latest
        FROM logs
        WHERE stealth=1 AND correlation_id IS NOT NULL
        GROUP BY correlation_id, scenario_key, taxonomy
        ORDER BY latest DESC
    """)
    if hidden.empty:
        st.info("No hidden easter egg activity yet. Increase hidden frequency or load demo data.")
    else:
        st.dataframe(hidden, use_container_width=True)
        selected_corr = st.selectbox("Select suspected hidden correlation", hidden["correlation_id"].tolist())
        detail = query_df("SELECT id, timestamp, source_tool, log_type, severity, asset, username, src_ip, dst_ip, event_id, message FROM logs WHERE correlation_id=? ORDER BY id", [selected_corr])
        st.dataframe(detail, use_container_width=True)
        if st.button("Reveal / Create Manual Critical Alert"):
            alert_id = reveal_easter_egg(selected_corr)
            st.success(f"Manual critical alert created: #{alert_id}")

with assets_tab:
    st.subheader("Asset Inventory")
    assets = query_df("SELECT * FROM assets ORDER BY branch, asset_type, hostname")
    st.dataframe(assets, use_container_width=True, height=600)

with report_tab:
    st.subheader("Export Data")
    logs = query_df("SELECT * FROM logs ORDER BY id")
    alerts = query_df("SELECT * FROM alerts ORDER BY id")
    notes = query_df("SELECT * FROM notes ORDER BY id")
    analysts = query_df("SELECT * FROM analysts ORDER BY id")
    c1, c2, c3, c4 = st.columns(4)
    c1.download_button("Download logs CSV", logs.to_csv(index=False).encode("utf-8"), "siem_logs.csv", "text/csv")
    c2.download_button("Download alerts CSV", alerts.to_csv(index=False).encode("utf-8"), "siem_alerts.csv", "text/csv")
    c3.download_button("Download notes CSV", notes.to_csv(index=False).encode("utf-8"), "siem_notes.csv", "text/csv")
    c4.download_button("Download analysts CSV", analysts.to_csv(index=False).encode("utf-8"), "siem_analysts.csv", "text/csv")

if auto_refresh:
    time.sleep(tick_delay)
    st.rerun()
