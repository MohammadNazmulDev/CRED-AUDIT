#!/usr/bin/env python3
"""
CRED-AUDIT: Brutalist Password Security Auditor
A terminal-inspired web application for password analysis and compliance checking.
"""

import os
import sys
import subprocess
import sqlite3
import hashlib
import re
import webbrowser
from datetime import datetime
import threading
import time

def setup_environment():
    """Set up virtual environment and install dependencies"""
    venv_path = os.path.join(os.getcwd(), 'venv')
    
    # Check if virtual environment exists
    if not os.path.exists(venv_path):
        print("Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
    
    # Determine activation script path
    if os.name == 'nt':  # Windows
        activate_script = os.path.join(venv_path, 'Scripts', 'activate.bat')
        python_executable = os.path.join(venv_path, 'Scripts', 'python.exe')
        pip_executable = os.path.join(venv_path, 'Scripts', 'pip.exe')
    else:  # Unix/Linux/Mac
        activate_script = os.path.join(venv_path, 'bin', 'activate')
        python_executable = os.path.join(venv_path, 'bin', 'python')
        pip_executable = os.path.join(venv_path, 'bin', 'pip')
    
    # Install Flask if not already installed
    try:
        import flask
    except ImportError:
        print("Installing Flask...")
        subprocess.run([pip_executable, 'install', 'flask'], check=True)
        print("Flask installed successfully!")
    
    return python_executable

# Try to import Flask, if it fails, set up environment
try:
    from flask import Flask, render_template, request, jsonify, redirect, url_for
except ImportError:
    print("Flask not found. Setting up environment...")
    python_executable = setup_environment()
    print(f"Environment ready. Restarting with: {python_executable}")
    subprocess.run([python_executable, __file__] + sys.argv[1:])
    sys.exit(0)

app = Flask(__name__)
app.secret_key = 'cred-audit-security-key'

# Database initialization
def init_db():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            password_length INTEGER,
            strength_score INTEGER,
            policy_violations TEXT,
            breach_status TEXT,
            user_agent TEXT
        )
    ''')
    
    # Simple breach simulation database
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS known_breaches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT UNIQUE,
            breach_source TEXT,
            compromise_date TEXT
        )
    ''')
    
    # Load actual commonly compromised passwords from real breaches
    common_breached = [
        # Most common passwords from actual breach data
        'password', '123456', 'password123', 'admin', 'qwerty', 'letmein', 'welcome', 
        'monkey', '1234567890', 'abc123', 'Password1', 'password1', '123456789', 
        'welcome123', 'admin123', 'qwerty123', 'login', 'guest', 'test', 'user',
        'root', 'pass', 'administrator', 'changeme', 'default', 'password12',
        'p@ssword', 'P@ssw0rd', 'passw0rd', 'Password123', 'Welcome123',
        'iloveyou', 'princess', 'rockyou', 'football', 'baseball', 'master',
        'michael', 'ashley', 'jennifer', 'joshua', 'amanda', 'daniel', 'david',
        '1q2w3e4r', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx',
        'superman', 'batman', 'trustno1', 'hello', 'freedom', 'whatever',
        'computer', 'internet', 'service', 'server', 'oracle', 'mysql',
        'database', 'system', 'network', 'windows', 'microsoft', 'google',
        'facebook', 'twitter', 'linkedin', 'amazon', 'apple', 'samsung',
        'nokia', 'blackberry', 'android', 'iphone', 'secure', 'security',
        'manager', 'supervisor', 'employee', 'student', 'teacher', 'doctor',
        '00000000', '11111111', '12121212', '123123123', 'aaaaaaaa',
        'abcdefgh', 'password!', 'Welcome1', 'admin1234', 'root123',
        'sa', 'sysadmin', 'manager1', 'temp123', 'test123', 'demo',
        'sample', 'example', 'backup', 'mail', 'email', 'web', 'ftp',
        'ssh', 'telnet', 'snmp', 'public', 'private', 'secret', 'hidden',
        'january', 'february', 'march', 'april', 'may', 'june',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
        '2024', '2023', '2022', '2021', '2020', '1234', '4321'
    ]
    
    # Add these to breach database with realistic breach sources
    breach_sources = [
        'RockYou2021', 'Collection1', 'Exploit.in', 'AntiPublic', 'COMB',
        'LinkedIn2012', 'MySpace2008', 'Adobe2013', 'Yahoo2014', 'Equifax2017',
        'Marriott2018', 'Facebook2019', 'Twitter2022', 'LastPass2022'
    ]
    
    import random
    dates = ['2021-01-15', '2021-06-22', '2022-03-10', '2022-08-05', '2022-11-30',
             '2023-02-14', '2023-05-18', '2023-09-25', '2024-01-08']
    
    for pwd in common_breached:
        pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
        source = random.choice(breach_sources)
        date = random.choice(dates)
        cursor.execute('''
            INSERT OR IGNORE INTO known_breaches (password_hash, breach_source, compromise_date)
            VALUES (?, ?, ?)
        ''', (pwd_hash, source, date))
    
    conn.commit()
    conn.close()

class PasswordAnalyzer:
    @staticmethod
    def analyze_strength(password):
        """Analyze password strength and return detailed metrics"""
        score = 0
        feedback = []
        
        # Length scoring
        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
            feedback.append("PASSWORD_LENGTH_WEAK")
        else:
            feedback.append("PASSWORD_LENGTH_CRITICAL")
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        else:
            feedback.append("NO_LOWERCASE")
            
        if re.search(r'[A-Z]', password):
            score += 10
        else:
            feedback.append("NO_UPPERCASE")
            
        if re.search(r'\d', password):
            score += 10
        else:
            feedback.append("NO_DIGITS")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        else:
            feedback.append("NO_SPECIAL_CHARS")
        
        # Pattern detection
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("REPEATED_CHARS")
            
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            score -= 15
            feedback.append("SEQUENTIAL_PATTERN")
        
        # Common patterns
        common_patterns = ['password', 'admin', 'login', 'user', 'test']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 20
            feedback.append("COMMON_WORD_DETECTED")
        
        score = max(0, min(100, score))
        
        return {
            'score': score,
            'length': length,
            'feedback': feedback,
            'grade': PasswordAnalyzer.get_grade(score)
        }
    
    @staticmethod
    def get_grade(score):
        if score >= 80:
            return "SECURE"
        elif score >= 60:
            return "MODERATE"
        elif score >= 40:
            return "WEAK"
        else:
            return "CRITICAL"
    
    @staticmethod
    def check_policy_compliance(password):
        """Check against enterprise security policies"""
        violations = []
        
        # Standard enterprise requirements
        if len(password) < 8:
            violations.append("MINIMUM_LENGTH_8")
        if len(password) < 12:
            violations.append("RECOMMENDED_LENGTH_12")
        if not re.search(r'[A-Z]', password):
            violations.append("UPPERCASE_REQUIRED")
        if not re.search(r'[a-z]', password):
            violations.append("LOWERCASE_REQUIRED")
        if not re.search(r'\d', password):
            violations.append("DIGIT_REQUIRED")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            violations.append("SPECIAL_CHAR_REQUIRED")
        
        return violations
    
    @staticmethod
    def check_breach_status(password):
        """Check if password appears in breach database"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('audit_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT breach_source, compromise_date FROM known_breaches 
            WHERE password_hash = ?
        ''', (password_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'compromised': True,
                'source': result[0],
                'date': result[1]
            }
        return {'compromised': False}

def log_audit(password_length, strength_score, policy_violations, breach_status, user_agent):
    """Log audit to database"""
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO audit_logs 
        (timestamp, password_length, strength_score, policy_violations, breach_status, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        password_length,
        strength_score,
        ','.join(policy_violations),
        'COMPROMISED' if breach_status['compromised'] else 'CLEAN',
        user_agent
    ))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({'error': 'NO_PASSWORD_PROVIDED'})
    
    # Perform analysis
    strength = PasswordAnalyzer.analyze_strength(password)
    policy_violations = PasswordAnalyzer.check_policy_compliance(password)
    breach_status = PasswordAnalyzer.check_breach_status(password)
    
    # Log the audit
    log_audit(
        len(password), 
        strength['score'], 
        policy_violations, 
        breach_status,
        request.headers.get('User-Agent', 'UNKNOWN')
    )
    
    return jsonify({
        'strength': strength,
        'policy_violations': policy_violations,
        'breach_status': breach_status,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    
    # Get recent audits
    cursor.execute('''
        SELECT * FROM audit_logs 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''')
    recent_audits = cursor.fetchall()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM audit_logs')
    total_audits = cursor.fetchone()[0]
    
    cursor.execute('SELECT AVG(strength_score) FROM audit_logs')
    avg_score = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE breach_status = "COMPROMISED"')
    compromised_count = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         recent_audits=recent_audits,
                         total_audits=total_audits,
                         avg_score=round(avg_score, 1),
                         compromised_count=compromised_count)

@app.route('/report')
def report():
    """Generate executive report with real audit data"""
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    
    # Get comprehensive statistics
    cursor.execute('SELECT COUNT(*) FROM audit_logs')
    total_audits = cursor.fetchone()[0]
    
    cursor.execute('SELECT AVG(strength_score) FROM audit_logs WHERE strength_score IS NOT NULL')
    avg_score = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE breach_status = "COMPROMISED"')
    compromised_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE strength_score < 40')
    critical_passwords = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE strength_score >= 80')
    secure_passwords = cursor.fetchone()[0]
    
    cursor.execute('SELECT policy_violations FROM audit_logs WHERE policy_violations != ""')
    violations_data = cursor.fetchall()
    
    # Calculate violation frequency
    all_violations = []
    for row in violations_data:
        if row[0]:
            all_violations.extend(row[0].split(','))
    
    from collections import Counter
    violation_counts = Counter(all_violations)
    
    # Get recent breach findings
    cursor.execute('''
        SELECT password_length, breach_status, timestamp 
        FROM audit_logs 
        WHERE breach_status = "COMPROMISED" 
        ORDER BY timestamp DESC 
        LIMIT 10
    ''')
    recent_breaches = cursor.fetchall()
    
    conn.close()
    
    report_data = {
        'total_audits': total_audits,
        'avg_score': round(avg_score, 1),
        'compromised_count': compromised_count,
        'critical_passwords': critical_passwords,
        'secure_passwords': secure_passwords,
        'violation_counts': dict(violation_counts.most_common(5)),
        'recent_breaches': recent_breaches,
        'clean_rate': round((total_audits - compromised_count) / total_audits * 100, 1) if total_audits > 0 else 0,
        'security_grade': 'CRITICAL' if avg_score < 40 else 'WEAK' if avg_score < 60 else 'MODERATE' if avg_score < 80 else 'SECURE'
    }
    
    return render_template('report.html', **report_data)

@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all audit logs"""
    try:
        conn = sqlite3.connect('audit_logs.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM audit_logs')
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.context_processor
def inject_current_time():
    """Inject current time into templates"""
    return {'current_time': lambda: datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

def open_browser():
    """Open browser after short delay"""
    time.sleep(1.5)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    print("="*50)
    print("CRED-AUDIT: PASSWORD SECURITY AUDITOR")
    print("="*50)
    print("Initializing database...")
    init_db()
    print("Starting Flask application...")
    print("Opening browser in 1.5 seconds...")
    
    # Start browser in background thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run Flask app
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)