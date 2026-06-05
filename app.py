# ==============================================================================
# 🛠️ LAYİHƏ: Automated Log Parser & Threat Analytics Engine
# 👤 MÜƏLLİF: Remikhanov Shamil
# 📅 TARİX: İyun 2026
# 🔒 LİSENZİYA: Copyright © 2026 Remikhanov Shamil. All Rights Reserved.
# ==============================================================================

import re
import sqlite3
import os

LOG_PATTERN = r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)[^"]*"\s+(?P<status>\d+)'
failed_login_tracker = {} 

def init_db():
    conn = sqlite3.connect('security_audit.db')
    cursor = conn.cursor()
    if os.path.exists('database.sql'):
        with open('database.sql', 'r', encoding='utf-8') as f:
            cursor.executescript(f.read())
    conn.commit()
    return conn

def is_ip_whitelisted(cursor, ip):
    cursor.execute("SELECT 1 FROM ip_whitelist WHERE ip_address = ?", (ip,))
    return cursor.fetchone() is not None

def analyze_log_line(line, cursor):
    line = line.strip()
    match = re.match(LOG_PATTERN, line)
    if not match:
        return None
    
    data = match.groupdict()
    ip = data['ip']
    status = int(data['status'])
    url = data['url'].lower()
    
    if is_ip_whitelisted(cursor, ip):
        return None
    
    attack_type = None
    severity = "LOW"
    
    if "select" in url or "union" in url or "'" in url or "or 1=1" in url:
        attack_type = "SQL Injection Attempt"
        severity = "HIGH"
    elif "admin" in url or "config" in url or ".env" in url:
        attack_type = "Suspicious Directory Enumeration"
        severity = "MEDIUM"
    elif status == 401 or (status == 403 and "login" in url):
        failed_login_tracker[ip] = failed_login_tracker.get(ip, 0) + 1
        if failed_login_tracker[ip] >= 2:
            attack_type = "Brute Force Attack (Multi-Failure)"
            severity = "HIGH"
        else:
            attack_type = "Failed Login Attempt"
            severity = "MEDIUM"
    
    if attack_type:
        return {
            'ip': ip, 'time': data['time'], 'method': data['method'],
            'url': data['url'], 'status': status, 'attack_type': attack_type, 'severity': severity
        }
    return None

def main():
    # ŞƏXSİ VİZUAL İMZA (TERMINAL MÖHÜRÜ)
    print("=" * 60)
    print(" 🛡️  AUTOMATED LOG ANALYTICS & THREAT DETECTION ENGINE")
    print(" 👨‍💻  DEVELOPED BY: REMIKHANOV SHAMIL")
    print(" 🔒  STATUS: ENTERPRISE PORTFOLIO PROJECT")
    print("=" * 60)
    
    if not os.path.exists('server_access.log'):
        print("[-] Xəta: 'server_access.log' faylı tapılmadı!")
        return

    print("[*] Log Analiz Prosesi Başladı...")
    conn = init_db()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM suspicious_activities")
    
    detected_count = 0
    with open('server_access.log', 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            result = analyze_log_line(line, cursor) 
            if result:
                cursor.execute('''
                    INSERT INTO suspicious_activities (ip_address, request_timestamp, request_method, requested_url, response_code, attack_type, severity_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (result['ip'], result['time'], result['method'], result['url'], result['status'], result['attack_type'], result['severity']))
                
                print(f"[ALERT] [{result['severity']}] {result['attack_type']} aşkarlandı! IP: {result['ip']}")
                detected_count += 1
                
    conn.commit()
    conn.close()
    print(f"\n[+] Analiz yekunlaşdı. {detected_count} kritik insident bazaya yazıldı.")

if __name__ == "__main__":
    main()