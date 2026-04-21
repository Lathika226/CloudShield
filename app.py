from flask import Flask, request, redirect, url_for
from security import analyze_payload
import os

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CloudShield WAF Simulator</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }
        .container { max-width: 600px; margin: auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        input[type="text"] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 15px; font-size: 16px; border: none; background-color: #007bff; color: white; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .result { margin-top: 20px; font-size: 18px; font-weight: bold; }
        .message-success { color: green; }
        .message-error { color: red; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CloudShield WAF</h1>
        <p>Test the web application firewall by sending a payload.</p>
        <form method="GET">
            <input type="text" name="payload" placeholder="Enter payload (e.g., hello, DROP TABLE users)..." required>
            <button type="submit">Test</button>
        </form>
        <div class="result">
            {result}
        </div>
        <p style="margin-top: 30px;"><a href="/dashboard">View Security Dashboard</a></p>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    payload = request.args.get('payload', '')
    result = ""
    
    if payload:
        # User specified logic
        if payload.lower() == 'hello':
            result = f'<span class="message-success">Safe payload! (hello worked)</span>'
        else:
            is_safe, message = analyze_payload(payload)
            if not is_safe:
                result = f'<span class="message-error">🛑 ACTION BLOCKED: {message}</span>'
            else:
                result = f'<span class="message-success">✅ Allowed: Safe payload</span>'
                
    return HTML_TEMPLATE.replace('{result}', result)

@app.route('/dashboard')
def dashboard():
    logs_exist = os.path.exists("logs.txt")
    logs = ""
    if logs_exist:
        with open("logs.txt", "r") as f:
            logs = f.read()

    log_content = logs if logs else "No attacks logged yet. System is safe."
    
    dashboard_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CloudShield Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
            .container {{ max-width: 800px; margin: auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0,0,0,0.1); }}
            pre {{ background: #eee; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Security Logs Dashboard</h1>
            <pre>{log_content}</pre>
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """
    return dashboard_html

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
