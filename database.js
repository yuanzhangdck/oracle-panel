const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'data', 'oracle.db');
const db = new sqlite3.Database(dbPath);

function init() {
    db.serialize(() => {
        // API Keys (Oracle Accounts)
        db.run(`CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            user_ocid TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            tenancy_ocid TEXT NOT NULL,
            region TEXT NOT NULL,
            key_file_path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Instances (Cached instances)
        db.run(`CREATE TABLE IF NOT EXISTS instances (
            id TEXT PRIMARY KEY, -- OCID
            key_id INTEGER,
            display_name TEXT,
            shape TEXT,
            public_ip TEXT,
            state TEXT,
            availability_domain TEXT,
            compartment_id TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tasks (Auto-create or IP-change tasks)
        db.run(`CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER,
            type TEXT NOT NULL, -- 'create_instance' or 'change_ip'
            target_config TEXT, -- JSON
            status TEXT DEFAULT 'pending', -- pending, running, success, failed, paused
            logs TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Persistent logs
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT DEFAULT 'info',
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // IP change history
        db.run(`CREATE TABLE IF NOT EXISTS ip_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER,
            instance_id TEXT,
            instance_name TEXT,
            ip_type TEXT DEFAULT 'ipv4', -- ipv4 or ipv6
            old_ip TEXT,
            new_ip TEXT,
            source TEXT DEFAULT 'manual', -- manual or schedule
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Access logs
        db.run(`CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            detail TEXT,
            ip TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Grab tasks (auto-create instance)
        db.run(`CREATE TABLE IF NOT EXISTS grab_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER,
            name TEXT NOT NULL,
            shape TEXT NOT NULL,
            ocpus REAL DEFAULT 1,
            memory_gb REAL DEFAULT 6,
            image_id TEXT,
            subnet_id TEXT,
            availability_domain TEXT,
            ssh_public_key TEXT,
            root_password TEXT DEFAULT '',
            status TEXT DEFAULT 'running', -- running, paused, success, failed
            interval_seconds INTEGER DEFAULT 60,
            last_attempt_at DATETIME,
            last_error TEXT,
            attempt_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        console.log('Database initialized at ' + dbPath);
    });
}

module.exports = { db, init };
