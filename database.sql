-- Təhlükəsizlik insidentlərinin qeydiyyatı üçün verilənlər bazası strukturu
CREATE TABLE IF NOT EXISTS suspicious_activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    request_timestamp TEXT NOT NULL,
    request_method VARCHAR(10),
    requested_url TEXT,
    response_code INTEGER,
    attack_type VARCHAR(50),
    severity_level VARCHAR(10)
);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    ip_address VARCHAR(45) PRIMARY KEY,
    description VARCHAR(100),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO ip_whitelist (ip_address, description) VALUES ('192.168.1.50', 'Daxili Admin Ofisi');
