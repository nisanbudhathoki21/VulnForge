#!/usr/bin/env python3
"""
SQLite database for storing scan results and findings.
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = 'vulnforge.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target TEXT,
            timestamp TEXT,
            fingerprint TEXT,
            findings_count INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            template_id TEXT,
            name TEXT,
            severity TEXT,
            impact TEXT,
            chain TEXT,
            evidence TEXT,
            extracted TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(scan_id, target, fingerprint, findings):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO scans (scan_id, target, timestamp, fingerprint, findings_count)
        VALUES (?, ?, ?, ?, ?)
    ''', (scan_id, target, datetime.now().isoformat(),
          json.dumps(fingerprint), len(findings)))
    for f in findings:
        c.execute('''
            INSERT INTO findings (scan_id, template_id, name, severity, impact, chain, evidence, extracted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, f.get('template_id'), f.get('name'), f.get('severity'),
              f.get('impact'), f.get('chain'),
              json.dumps(f.get('evidence')), json.dumps(f.get('extracted', {}))))
    conn.commit()
    conn.close()

def get_scans(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT scan_id, target, timestamp, findings_count FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'scan_id': r[0], 'target': r[1], 'timestamp': r[2], 'findings_count': r[3]} for r in rows]

def get_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
    scan = c.fetchone()
    if not scan:
        return None
    c.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,))
    findings = c.fetchall()
    conn.close()
    return {
        'scan_id': scan[0],
        'target': scan[1],
        'timestamp': scan[2],
        'fingerprint': json.loads(scan[3]),
        'findings_count': scan[4],
        'findings': [
            {
                'id': f[0],
                'template_id': f[2],
                'name': f[3],
                'severity': f[4],
                'impact': f[5],
                'chain': f[6],
                'evidence': json.loads(f[7]),
                'extracted': json.loads(f[8]) if f[8] else {}
            }
            for f in findings
        ]
    }
