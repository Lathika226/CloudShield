# CloudShield 🛡️

A simple, fast, and explainable Web Application Firewall (WAF) project.

## Features
- Detects SQL Injection (e.g., `DROP TABLE`)
- Detects Cross-Site Scripting (XSS)
- Logs all attacks to `logs.txt`
- Explains the reasoning behind the block
- Interactive Web Interface & Security Dashboard

## Installation

1. Make sure you have Python installed.
2. Open terminal in this folder and install Flask:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```

## Usage
1. Open your browser to `http://127.0.0.1:5000`
2. Test a safe payload like `hello` -> This will work fine.
3. Test an attack like `DROP TABLE users` -> CloudShield will block this instantly.
4. Go to `http://127.0.0.1:5000/dashboard` to see the logs of blocked attacks.
