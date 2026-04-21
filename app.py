from flask import Flask, request, jsonify, render_template_string
from security import analyze_payload
from rate_limiter import RateLimiter
from logger import WAFLogger
import os
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')

rate_limiter = RateLimiter(max_requests=20, window_seconds=60)
waf_logger = WAFLogger("logs.txt")

# ── HTML templates ──────────────────────────────────────────────────────────────

HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CloudShield WAF</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: #0a0e1a;
      --surface: #111827;
      --surface2: #1a2236;
      --border: #1e2d45;
      --accent: #00e5ff;
      --accent2: #ff4081;
      --safe: #00e676;
      --warn: #ff5252;
      --text: #e2eaf8;
      --muted: #5a7090;
      --mono: 'Space Mono', monospace;
      --sans: 'DM Sans', sans-serif;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,229,255,0.07) 0%, transparent 60%),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(30,45,69,0.4) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(30,45,69,0.4) 40px);
    }

    /* Header */
    header {
      text-align: center;
      margin-bottom: 40px;
      animation: fadeDown 0.5s ease both;
    }

    .logo {
      font-family: var(--mono);
      font-size: 13px;
      letter-spacing: 4px;
      color: var(--accent);
      text-transform: uppercase;
      margin-bottom: 12px;
      opacity: 0.8;
    }

    h1 {
      font-family: var(--mono);
      font-size: clamp(28px, 5vw, 46px);
      font-weight: 700;
      letter-spacing: -1px;
      background: linear-gradient(135deg, #e2eaf8 30%, var(--accent));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .subtitle {
      color: var(--muted);
      font-size: 14px;
      margin-top: 8px;
      font-weight: 300;
    }

    /* Status bar */
    .status-bar {
      display: flex;
      gap: 24px;
      margin-bottom: 32px;
      flex-wrap: wrap;
      justify-content: center;
      animation: fadeDown 0.5s 0.1s ease both;
    }

    .stat {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 20px;
      text-align: center;
      min-width: 110px;
    }

    .stat-value {
      font-family: var(--mono);
      font-size: 22px;
      font-weight: 700;
      color: var(--accent);
    }

    .stat-label {
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 4px;
    }

    /* Card */
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 660px;
      animation: fadeUp 0.5s 0.15s ease both;
    }

    .card-title {
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 2px;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 20px;
    }

    .input-row {
      display: flex;
      gap: 10px;
    }

    input[type="text"] {
      flex: 1;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      font-family: var(--mono);
      font-size: 14px;
      color: var(--text);
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(0,229,255,0.1);
    }

    input[type="text"]::placeholder { color: var(--muted); }

    button {
      background: var(--accent);
      color: #000;
      border: none;
      border-radius: 8px;
      padding: 12px 22px;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.15s, transform 0.1s;
      white-space: nowrap;
    }

    button:hover { opacity: 0.85; }
    button:active { transform: scale(0.97); }

    /* Result */
    .result {
      margin-top: 24px;
      min-height: 54px;
    }

    .result-box {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      padding: 16px 18px;
      border-radius: 8px;
      font-size: 14px;
      line-height: 1.5;
      animation: resultPop 0.3s ease;
    }

    .result-box.blocked {
      background: rgba(255,82,82,0.08);
      border: 1px solid rgba(255,82,82,0.3);
    }

    .result-box.allowed {
      background: rgba(0,230,118,0.07);
      border: 1px solid rgba(0,230,118,0.3);
    }

    .result-box.rate-limited {
      background: rgba(255,193,7,0.07);
      border: 1px solid rgba(255,193,7,0.3);
    }

    .result-icon { font-size: 20px; flex-shrink: 0; }

    .result-label {
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      margin-bottom: 4px;
    }

    .blocked .result-label { color: var(--warn); }
    .allowed .result-label { color: var(--safe); }
    .rate-limited .result-label { color: #ffc107; }

    .result-detail { color: var(--muted); font-size: 13px; }

    /* Threat tags */
    .threat-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 10px;
    }

    .tag {
      font-family: var(--mono);
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      background: rgba(255,64,129,0.15);
      border: 1px solid rgba(255,64,129,0.4);
      color: #ff80ab;
      letter-spacing: 0.5px;
    }

    /* Nav */
    nav {
      margin-top: 28px;
      display: flex;
      gap: 16px;
      justify-content: center;
      animation: fadeUp 0.5s 0.25s ease both;
    }

    nav a {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--muted);
      text-decoration: none;
      letter-spacing: 1px;
      text-transform: uppercase;
      transition: color 0.2s;
      padding: 6px 0;
      border-bottom: 1px solid transparent;
    }

    nav a:hover { color: var(--accent); border-bottom-color: var(--accent); }

    /* Quick tests */
    .quick-tests {
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    .quick-label {
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 10px;
      font-family: var(--mono);
    }

    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .chip {
      font-family: var(--mono);
      font-size: 11px;
      padding: 5px 10px;
      border: 1px solid var(--border);
      border-radius: 20px;
      background: var(--surface2);
      color: var(--muted);
      cursor: pointer;
      transition: all 0.15s;
    }

    .chip:hover { border-color: var(--accent); color: var(--accent); }

    @keyframes fadeDown { from { opacity:0; transform:translateY(-12px); } to { opacity:1; transform:none; } }
    @keyframes fadeUp   { from { opacity:0; transform:translateY(12px);  } to { opacity:1; transform:none; } }
    @keyframes resultPop { from { opacity:0; transform:scale(0.97); } to { opacity:1; transform:none; } }
  </style>
</head>
<body>
  <header>
    <div class="logo">▣ CloudShield</div>
    <h1>WAF Simulator</h1>
    <p class="subtitle">Web Application Firewall · Threat Detection Engine</p>
  </header>

  <div class="status-bar">
    <div class="stat">
      <div class="stat-value" id="total-stat">{{ stats.total }}</div>
      <div class="stat-label">Total Tested</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="blocked-stat" style="color:#ff5252">{{ stats.blocked }}</div>
      <div class="stat-label">Blocked</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="allowed-stat" style="color:#00e676">{{ stats.allowed }}</div>
      <div class="stat-label">Allowed</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="rate-limited-stat" style="color:#ffc107">{{ stats.rate_limited }}</div>
      <div class="stat-label">Rate Limited</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">// Payload Inspector</div>
    <form id="waf-form" onsubmit="testPayload(event)">
      <div class="input-row">
        <input type="text" id="payload-input" placeholder="Enter payload to test…" autocomplete="off" />
        <button type="submit">ANALYZE</button>
      </div>
    </form>

    <div class="result" id="result-area">{{ result_html }}</div>

    <div class="quick-tests">
      <div class="quick-label">Quick tests</div>
      <div class="chips">
        <span class="chip" onclick="setPayload(this)">hello world</span>
        <span class="chip" onclick="setPayload(this)">SELECT * FROM users</span>
        <span class="chip" onclick="setPayload(this)">&lt;script&gt;alert(1)&lt;/script&gt;</span>
        <span class="chip" onclick="setPayload(this)">../../../etc/passwd</span>
        <span class="chip" onclick="setPayload(this)">ping -c 100 8.8.8.8</span>
        <span class="chip" onclick="setPayload(this)">normal search query</span>
      </div>
    </div>
  </div>

  <nav>
    <a href="/dashboard">Security Dashboard</a>
    <a href="/api/stats">API Stats</a>
    <a href="/health">Health Check</a>
  </nav>

  <script>
    function setPayload(el) {
      document.getElementById('payload-input').value = el.textContent;
      document.getElementById('waf-form').dispatchEvent(new Event('submit'));
    }

    async function testPayload(e) {
      e.preventDefault();
      const payload = document.getElementById('payload-input').value.trim();
      if (!payload) return;

      const area = document.getElementById('result-area');
      area.innerHTML = '<div style="color:var(--muted);font-family:var(--mono);font-size:13px;padding:10px 0">Analyzing…</div>';

      try {
        const res = await fetch('/api/analyze?payload=' + encodeURIComponent(payload));
        const data = await res.json();

        if (data.rate_limited) {
          area.innerHTML = `<div class="result-box rate-limited">
            <div class="result-icon">⚠️</div>
            <div>
              <div class="result-label">Rate Limited</div>
              <div class="result-detail">${data.message} Retry after ${data.retry_after}s.</div>
            </div>
          </div>`;
        } else if (!data.safe) {
          const tags = (data.threats || []).map(t => `<span class="tag">${t}</span>`).join('');
          area.innerHTML = `<div class="result-box blocked">
            <div class="result-icon">🛑</div>
            <div>
              <div class="result-label">Blocked</div>
              <div class="result-detail">${data.message}</div>
              ${tags ? '<div class="threat-tags">' + tags + '</div>' : ''}
            </div>
          </div>`;
        } else {
          area.innerHTML = `<div class="result-box allowed">
            <div class="result-icon">✅</div>
            <div>
              <div class="result-label">Allowed</div>
              <div class="result-detail">Payload passed all security checks. Risk score: <strong>${data.risk_score}/100</strong></div>
            </div>
          </div>`;
        }

        // Update stats
        const sr = await fetch('/api/stats');
        const st = await sr.json();
        document.getElementById('total-stat').textContent = st.total;
        document.getElementById('blocked-stat').textContent = st.blocked;
        document.getElementById('allowed-stat').textContent = st.allowed;
        document.getElementById('rate-limited-stat').textContent = st.rate_limited;
      } catch(err) {
        area.innerHTML = '<div class="result-detail" style="color:var(--warn);padding:10px 0">Error contacting server.</div>';
      }
    }
  </script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CloudShield Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg:#0a0e1a; --surface:#111827; --surface2:#1a2236;
      --border:#1e2d45; --accent:#00e5ff; --safe:#00e676; --warn:#ff5252;
      --text:#e2eaf8; --muted:#5a7090;
      --mono:'Space Mono',monospace; --sans:'DM Sans',sans-serif;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;padding:40px 20px;
      background-image:radial-gradient(ellipse 80% 40% at 50% -10%,rgba(0,229,255,0.06) 0%,transparent 60%)}
    .page{max-width:900px;margin:auto}
    header{margin-bottom:32px}
    .back{font-family:var(--mono);font-size:12px;color:var(--muted);text-decoration:none;letter-spacing:1px;display:inline-flex;align-items:center;gap:6px;margin-bottom:20px;transition:color .2s}
    .back:hover{color:var(--accent)}
    h1{font-family:var(--mono);font-size:28px;background:linear-gradient(135deg,#e2eaf8 30%,var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    .subtitle{color:var(--muted);font-size:13px;margin-top:6px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 20px}
    .sv{font-family:var(--mono);font-size:28px;font-weight:700}
    .sl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px}
    .section{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;margin-bottom:20px}
    .section-title{font-family:var(--mono);font-size:11px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:16px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th{font-family:var(--mono);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)}
    td{padding:10px 12px;border-bottom:1px solid rgba(30,45,69,0.5);vertical-align:top}
    tr:last-child td{border-bottom:none}
    .badge{display:inline-block;font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px}
    .badge-block{background:rgba(255,82,82,.15);border:1px solid rgba(255,82,82,.3);color:#ff8a80}
    .badge-allow{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.3);color:#69f0ae}
    pre{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:var(--mono);font-size:12px;overflow-x:auto;color:var(--muted);max-height:320px;overflow-y:auto}
    .empty{color:var(--muted);font-family:var(--mono);font-size:13px;padding:20px 0;text-align:center}
    .bar-wrap{margin-top:6px;height:6px;background:var(--surface2);border-radius:3px;overflow:hidden}
    .bar-fill{height:100%;border-radius:3px;background:var(--accent)}
  </style>
</head>
<body>
<div class="page">
  <header>
    <a class="back" href="/">← Back</a>
    <h1>Security Dashboard</h1>
    <p class="subtitle">Logged threats and traffic overview</p>
  </header>

  <div class="grid">
    <div class="stat-card"><div class="sv" style="color:var(--accent)">{{ stats.total }}</div><div class="sl">Total Requests</div></div>
    <div class="stat-card"><div class="sv" style="color:var(--warn)">{{ stats.blocked }}</div><div class="sl">Blocked</div></div>
    <div class="stat-card"><div class="sv" style="color:var(--safe)">{{ stats.allowed }}</div><div class="sl">Allowed</div></div>
    <div class="stat-card"><div class="sv" style="color:#ffc107">{{ stats.rate_limited }}</div><div class="sl">Rate Limited</div></div>
    <div class="stat-card">
      <div class="sv" style="color:var(--accent)">{{ block_pct }}%</div>
      <div class="sl">Block Rate</div>
      <div class="bar-wrap"><div class="bar-fill" style="width:{{ block_pct }}%"></div></div>
    </div>
  </div>

  {% if threat_rows %}
  <div class="section">
    <div class="section-title">// Recent Threat Log</div>
    <table>
      <thead>
        <tr><th>Time</th><th>Verdict</th><th>Payload</th><th>Reason</th></tr>
      </thead>
      <tbody>
        {% for row in threat_rows %}
        <tr>
          <td style="color:var(--muted);white-space:nowrap">{{ row.time }}</td>
          <td><span class="badge {{ 'badge-block' if row.verdict=='BLOCKED' else 'badge-allow' }}">{{ row.verdict }}</span></td>
          <td style="font-family:var(--mono);font-size:11px;max-width:280px;word-break:break-all">{{ row.payload }}</td>
          <td style="color:var(--muted);font-size:12px">{{ row.reason }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="section"><div class="empty">No attack logs yet — system is clean.</div></div>
  {% endif %}

  <div class="section">
    <div class="section-title">// Raw Log File</div>
    <pre>{{ raw_log }}</pre>
  </div>
</div>
</body>
</html>"""


# ── Routes ──────────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    stats = waf_logger.get_stats()
    return render_template_string(HOME_HTML, stats=stats, result_html="")


@app.route('/api/analyze')
def api_analyze():
    """JSON endpoint used by the frontend JS."""
    client_ip = request.remote_addr
    payload = request.args.get('payload', '').strip()

    if not payload:
        return jsonify({'error': 'No payload provided'}), 400

    # Rate limiting
    allowed, retry_after = rate_limiter.check(client_ip)
    if not allowed:
        waf_logger.log_event(client_ip, payload, 'RATE_LIMITED', 'Too many requests')
        return jsonify({
            'rate_limited': True,
            'message': 'Too many requests.',
            'retry_after': retry_after,
        }), 429

    # Security analysis
    is_safe, message, threats, risk_score = analyze_payload(payload)
    verdict = 'ALLOWED' if is_safe else 'BLOCKED'
    waf_logger.log_event(client_ip, payload, verdict, message)

    return jsonify({
        'safe': is_safe,
        'message': message,
        'threats': threats,
        'risk_score': risk_score,
        'verdict': verdict,
    })


@app.route('/api/stats')
def api_stats():
    return jsonify(waf_logger.get_stats())


@app.route('/dashboard')
def dashboard():
    stats = waf_logger.get_stats()
    total = stats['total'] or 1
    block_pct = round((stats['blocked'] / total) * 100)
    raw_log, threat_rows = waf_logger.get_recent(50)
    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        block_pct=block_pct,
        raw_log=raw_log or 'No entries yet.',
        threat_rows=threat_rows,
    )


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': int(time.time())})


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
