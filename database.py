import sqlite3
from pathlib import Path
from typing import Iterable, Optional

DB_PATH = Path(__file__).parent / "siem_simulator.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS organization (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            name TEXT,
            industry TEXT,
            branches INTEGER,
            employees INTEGER,
            windows_endpoints INTEGER,
            linux_endpoints INTEGER,
            mac_endpoints INTEGER,
            onprem_servers INTEGER,
            cloud_servers INTEGER,
            tools TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            asset_type TEXT,
            os TEXT,
            branch TEXT,
            ip_address TEXT,
            owner TEXT,
            criticality TEXT
        );

        CREATE TABLE IF NOT EXISTS analysts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT,
            team TEXT,
            shift TEXT,
            skill_level TEXT,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_tool TEXT,
            log_type TEXT,
            severity TEXT,
            asset TEXT,
            username TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            event_id TEXT,
            message TEXT,
            raw TEXT,
            correlation_id TEXT,
            scenario_key TEXT,
            taxonomy TEXT,
            stealth INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            title TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New',
            source_tool TEXT,
            asset TEXT,
            username TEXT,
            tactic TEXT,
            technique TEXT,
            description TEXT,
            recommended_action TEXT,
            related_log_id INTEGER,
            assigned_to INTEGER,
            correlation_id TEXT,
            scenario_key TEXT,
            taxonomy TEXT,
            hidden_from_siem INTEGER DEFAULT 0,
            analyst_classification TEXT,
            analyst_severity TEXT,
            disposition TEXT
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            analyst TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # Lightweight migrations for users who already ran v1.
    migrations = [
        ("logs", "correlation_id", "ALTER TABLE logs ADD COLUMN correlation_id TEXT"),
        ("logs", "scenario_key", "ALTER TABLE logs ADD COLUMN scenario_key TEXT"),
        ("logs", "taxonomy", "ALTER TABLE logs ADD COLUMN taxonomy TEXT"),
        ("logs", "stealth", "ALTER TABLE logs ADD COLUMN stealth INTEGER DEFAULT 0"),
        ("alerts", "assigned_to", "ALTER TABLE alerts ADD COLUMN assigned_to INTEGER"),
        ("alerts", "correlation_id", "ALTER TABLE alerts ADD COLUMN correlation_id TEXT"),
        ("alerts", "scenario_key", "ALTER TABLE alerts ADD COLUMN scenario_key TEXT"),
        ("alerts", "taxonomy", "ALTER TABLE alerts ADD COLUMN taxonomy TEXT"),
        ("alerts", "hidden_from_siem", "ALTER TABLE alerts ADD COLUMN hidden_from_siem INTEGER DEFAULT 0"),
        ("alerts", "analyst_classification", "ALTER TABLE alerts ADD COLUMN analyst_classification TEXT"),
        ("alerts", "analyst_severity", "ALTER TABLE alerts ADD COLUMN analyst_severity TEXT"),
        ("alerts", "disposition", "ALTER TABLE alerts ADD COLUMN disposition TEXT"),
    ]
    for table, column, sql in migrations:
        cols = [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
        if column not in cols:
            cur.execute(sql)

    conn.commit()
    conn.close()


def reset_db():
    conn = get_conn()
    cur = conn.cursor()
    for table in ["organization", "assets", "logs", "alerts", "notes", "analysts"]:
        cur.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()


def execute(query: str, params: Iterable = ()): 
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, tuple(params))
    conn.commit()
    lastrowid = cur.lastrowid
    conn.close()
    return lastrowid


def query_df(query: str, params: Iterable = ()): 
    import pandas as pd
    conn = get_conn()
    df = pd.read_sql_query(query, conn, params=tuple(params))
    conn.close()
    return df


def query_one(query: str, params: Iterable = ()) -> Optional[sqlite3.Row]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, tuple(params))
    row = cur.fetchone()
    conn.close()
    return row
