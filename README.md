# CloudShield WAF Simulator — Enhanced

## Project Structure

```
app.py          — Flask application (routes, templates)
security.py     — Threat detection engine (rules, scoring)
rate_limiter.py — Sliding-window IP rate limiter
logger.py       — Structured event logger + stats
logs.txt        — Auto-created at runtime
```

## Running

```bash
pip install flask
python app.py
```

Open http://127.0.0.1:5000

## What's New vs Original

### Security
- 10 threat categories: SQLi, XSS, Path Traversal, Command Injection, SSRF, XXE, Prototype Pollution, Null Byte, Encoding Abuse, Long Payload
- Severity scoring (1-10 per rule) with a configurable block threshold
- Returns structured threat metadata (names + risk score 0-100)
- Low-severity flags allowed through with a caution note

### Rate Limiting
- Sliding-window limiter (20 req / 60 s per IP, configurable)
- Returns `retry_after` seconds in JSON response
- Thread-safe

### Logging
- Structured TSV format: timestamp, IP, verdict, risk_score, payload, reason
- Stats rebuilt from file on startup (survives restarts)
- `/dashboard` shows parsed table + raw tail

### API
- `GET /api/analyze?payload=...` — JSON response for AJAX use
- `GET /api/stats` — aggregate counters
- `GET /health` — liveness probe

### UI
- Async JS frontend (no full-page reload)
- Quick-test chips for common attack strings
- Live stats bar updates after each test
- Threat tags displayed inline
- Fully dark theme with CSS variables

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` env var | random | Flask secret key |
| `RateLimiter(max_requests=20, window_seconds=60)` | — | Tune in app.py |
| `BLOCK_THRESHOLD` in security.py | 5 | Min severity to block |
