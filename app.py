import sqlite3
import subprocess
import secrets
import re
import platform
import threading
from werkzeug.serving import make_server, is_running_from_reloader
from datetime import datetime
from pathlib import Path
from flask import Flask, request, session, redirect, url_for, render_template_string, Response, abort
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = 'vulnlab-demo-key-change-in-prod'
# Deliberately readable demo cookie; never use this configuration in production.
app.config['SESSION_COOKIE_HTTPONLY'] = False
DB_PATH = Path(__file__).resolve().parent / 'vulnlab.db'
stolen_cookies_log = []
KEYS = {'sqli': 'SQL Injection', 'cmdi': 'Command Injection', 'sxss': 'Stored XSS', 'rxss': 'Reflected XSS', 'csrf': 'CSRF'}


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS secret_data (id INTEGER PRIMARY KEY, label TEXT, value TEXT);''')
        if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            db.executemany('INSERT INTO users VALUES (?, ?, ?, ?)', [(1, 'admin', 'secret123', 'admin'), (2, 'alice', 'password1', 'user'), (3, 'bob', 'hunter2', 'user')])
        if not db.execute('SELECT 1 FROM secret_data LIMIT 1').fetchone():
            db.executemany('INSERT INTO secret_data VALUES (?, ?, ?)', [(1, 'Database Master Password', 'Sup3rS3cr3t!DB'), (2, 'AWS Secret Access Key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY'), (3, 'Internal API Token', 'tok_live_9xQk2mP8nRvL3wT7yKj4hA6dE0')])


BASE_TEMPLATE = '''<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnLab — {{ page_title }}</title><style>
body{font-family:monospace;background:#0d0d0d;color:#e0e0e0;margin:0;padding:0}a{color:#58a6ff}.navbar{background:#161b22;padding:12px 24px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:24px;flex-wrap:wrap}.navbar a{color:#c9d1d9;text-decoration:none;font-size:14px}.navbar a:hover{color:#58a6ff}.container{max-width:900px;margin:32px auto;padding:0 24px}.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:24px}.badge-vuln{background:#3d0000;color:#ff6b6b;border:1px solid #ff6b6b;padding:4px 12px;border-radius:4px;font-size:13px}.badge-safe{background:#003d1a;color:#3fb950;border:1px solid #3fb950;padding:4px 12px;border-radius:4px;font-size:13px}.btn{display:inline-block;padding:8px 18px;border:none;border-radius:6px;cursor:pointer;font-family:monospace;font-size:14px;text-decoration:none}.btn-red{background:#da3633;color:#fff}.btn-green{background:#238636;color:#fff}.btn-blue{background:#1f6feb;color:#fff}.btn-gray{background:#30363d;color:#c9d1d9}input,textarea{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-family:monospace;font-size:14px;width:100%;box-sizing:border-box}input[type=hidden]{display:none}pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:16px;overflow-x:auto;font-size:13px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere}.vuln-code{color:#ff6b6b}.safe-code{color:#3fb950}table{width:100%;border-collapse:collapse}th,td{border:1px solid #30363d;padding:10px 14px;text-align:left;overflow-wrap:anywhere}th{background:#21262d}.log-panel{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;max-height:200px;overflow-y:auto;font-size:13px}details summary{cursor:pointer;color:#58a6ff;padding:8px 0}.alert-red,.alert-green,.alert-blue{border-radius:6px;padding:12px 16px;margin:12px 0}.alert-red{background:#3d0000;border:1px solid #ff6b6b;color:#ff6b6b}.alert-green{background:#003d1a;border:1px solid #3fb950;color:#3fb950}.alert-blue{background:#0d2644;border:1px solid #58a6ff;color:#58a6ff}.stolen-log{background:#0d1117;border:1px solid #ff6b6b;border-radius:6px;padding:12px;max-height:160px;overflow-y:auto}label{display:block;margin:12px 0 6px}button{margin-top:12px}small{color:#8b949e}
</style></head><body><nav class="navbar"><span style="color:#58a6ff;font-weight:bold;font-size:16px">🔬 VulnLab</span><a href="/">Home</a><a href="/sqli">SQL Injection</a><a href="/cmdi">Command Injection</a><a href="/sxss">Stored XSS</a><a href="/rxss">Reflected XSS</a><a href="/csrf">CSRF</a><a href="/reset" style="margin-left:auto;color:#ff6b6b">⟳ Reset All</a></nav><main class="container">
{% if vuln_key %}<div class="{{ 'alert-green' if secure else 'alert-red' }}">{{ '🟢 SECURE MODE — Vulnerability is patched.' if secure else '🔴 VULNERABLE MODE — Exploit is active.' }} <a class="btn {{ 'btn-red' if secure else 'btn-green' }}" href="{{ url_for('toggle', vuln_key=vuln_key) }}">{{ '⚠️ Remove Fix → Switch to Vulnerable Mode' if secure else '✅ Apply Fix → Switch to Secure Mode' }}</a></div>{% endif %}
{{ body|safe }}
{% if theory %}<details><summary>📖 Show Code, Root Cause &amp; Theory</summary><div class="card"><h3 style="color:#ff6b6b">⚠️ Vulnerable Code</h3><pre class="vuln-code">{{ theory[0] }}</pre><h3 style="color:#3fb950">✅ Secure Code</h3><pre class="safe-code">{{ theory[1] }}</pre><h3 style="color:#e3b341">🔍 Root Cause</h3><p>{{ theory[2] }}</p><h3 style="color:#58a6ff">🛡️ Other Mitigations (Theory)</h3><p>{{ theory[3] }}</p></div></details>{% endif %}</main></body></html>'''

THEORY = {
'sqli': ("# ⚠️ VULNERABLE: user input alters SQL syntax\nquery = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\nuser = conn.execute(query).fetchone()", "# ✅ SECURE: bind input as data\nuser = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()", 'User input is concatenated directly into SQL, allowing an attacker to change the query structure.', 'Parameterized queries are the primary defense. Allow-list validation, least-privilege database accounts, and safe error handling provide additional layers. SQLite is an embedded database and does not provide per-user database privileges.'),
'cmdi': ("# ⚠️ VULNERABLE: the shell interprets user input\noutput = subprocess.check_output(f'{ping_cmd} {host}', shell=True, stderr=subprocess.STDOUT, timeout=8)", "# ✅ SECURE: validate input and avoid a shell\nif not re.fullmatch(r'[a-zA-Z0-9.\\-]{1,253}', host) or host.startswith('-'):\n    reject()\noutput = subprocess.check_output(['ping', count_flag, '1', host], shell=False, stderr=subprocess.STDOUT, timeout=8)", 'A shell interprets command separators in user input and runs additional commands with the server’s privileges.', 'Use argument vectors without a shell, validate with an allow-list, run as a restricted user, and consider a network library that never invokes a shell.'),
'sxss': ("# ⚠️ VULNERABLE: stored content is marked as trusted HTML\ncontent = Markup(comment['content'])", "# ✅ SECURE: Jinja escapes ordinary strings\ncontent = comment['content']\n# Template: {{ content }}", 'Stored user content is inserted into HTML without encoding and is interpreted as executable markup.', 'Use context-aware output encoding. For rich HTML use a trusted sanitizer; CSP and HttpOnly cookies add defense in depth.'),
'rxss': ("# ⚠️ VULNERABLE: reflect untrusted HTML\nresult = Markup(q)", "# ✅ SECURE: Jinja escapes plain strings\nresult = q\n# Template: {{ result }}", 'A URL parameter is inserted into an HTML response without encoding.', 'Output encoding is the primary defense. A restrictive Content Security Policy and HttpOnly cookies add defense in depth; input validation alone is insufficient.'),
'csrf': ("# ⚠️ VULNERABLE: accept a state change without a token\nsession['victim_email'] = request.form.get('email', '')", "# ✅ SECURE: require a matching random token\nif not token or not secrets.compare_digest(token, session_token):\n    abort(403)", 'The server accepts state-changing requests based on the session cookie alone.', 'Synchronizer tokens, SameSite cookies, origin checks, re-authentication for sensitive actions, and avoiding state-changing GET requests can reduce CSRF risk. SameSite=Lax is commonly the modern browser default, not Strict.')}


def page(title, template, key=None, **context):
    secure = bool(session.get(f'{key}_secure')) if key else False
    body = render_template_string(template, secure=secure, **context)
    return render_template_string(BASE_TEMPLATE, page_title=title, body=body, vuln_key=key, secure=secure, theory=THEORY.get(key))


@app.route('/')
def home():
    rows = [('Authentication Bypass', 'SQL Inj.', 'M1', 'sqli'), ('In-Band Command Inj.', 'OS Cmd Inj.', 'M2', 'cmdi'), ('Stored XSS', 'XSS', 'M3', 'sxss'), ('Reflected XSS', 'XSS', 'M4', 'rxss'), ('POST-Based CSRF', 'CSRF', 'M5', 'csrf')]
    return page('Web Security Demonstration', '''<h1>VulnLab — Web Security Demonstration</h1><div class="card"><table><tr><th>#</th><th>Vulnerability</th><th>Category</th><th>Member</th><th>Mode</th></tr>{% for name, category, member, key in rows %}<tr><td>{{ loop.index }}</td><td><a href="/{{ key }}">{{ name }}</a></td><td>{{ category }}</td><td>{{ member }}</td><td>{{ '🟢 Secure' if session.get(key ~ '_secure') else '🔴 Vulnerable' }}</td></tr>{% endfor %}</table></div><div class="card"><h2>Quick Exploit Reference</h2><pre>{{ cheats }}</pre></div>''', rows=rows, cheats="SQL: admin'-- / anything\nCommand: 127.0.0.1 & whoami (Windows); 127.0.0.1; whoami (Unix)\nStored XSS: <script>alert(1)</script>\nReflected XSS: <script>alert(1)</script>\nCSRF: open /csrf/attacker after /csrf")


@app.route('/toggle/<vuln_key>')
def toggle(vuln_key):
    if vuln_key not in KEYS:
        abort(404)
    key = f'{vuln_key}_secure'
    session[key] = not session.get(key, False)
    return redirect(url_for(vuln_key))


@app.route('/reset')
def reset():
    session.clear()
    with get_db() as db:
        db.execute('DELETE FROM comments')
    stolen_cookies_log.clear()
    return redirect(url_for('home'))


@app.route('/sqli', methods=['GET', 'POST'])
def sqli():
    user = None
    error = None
    query = ''
    secrets_rows = []
    if request.method == 'POST':
        username, password = request.form.get('username', ''), request.form.get('password', '')
        with get_db() as conn:
            try:
                if not session.get('sqli_secure'):
                    # ⚠️ VULNERABLE: concatenated input changes SQL structure.
                    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                    session['last_sqli_query'] = query
                    user = conn.execute(query).fetchone()
                else:
                    # ✅ SECURE: parameters are data, not SQL syntax.
                    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
                if user:
                    secrets_rows = conn.execute('SELECT * FROM secret_data').fetchall()
            except sqlite3.Error as exc:
                error = str(exc)
    return page('SQL Injection', '''<h1>SQL Injection — Authentication Bypass</h1><p>Member 1 | Category: SQL Injection | Variant: Auth Bypass</p><div class="card"><h2>Login</h2><form method="post"><label>Username<input name="username" required></label><label>Password<input type="password" name="password" required></label><button class="btn btn-blue">Login</button></form>{% if not secure %}<p>💡 Try payload — Username: <code>admin'--</code> Password: anything</p>{% endif %}</div>{% if posted %}{% if user %}<div class="{{ 'alert-green' if secure else 'alert-red' }}">{{ 'Login successful.' if secure else '⚠️ LOGIN SUCCESSFUL — vulnerable query accepted the credentials.' }} Logged in as: <b>{{ user.username }}</b> (role: {{ user.role }}){% if not secure %}<br>Injected query: <code>{{ query }}</code>{% endif %}</div><div class="card"><h2>🔓 Data an attacker can now access:</h2><table><tr><th>ID</th><th>Label</th><th>Value</th></tr>{% for row in secrets_rows %}<tr><td>{{ row.id }}</td><td>{{ row.label }}</td><td>{{ row.value }}</td></tr>{% endfor %}</table></div>{% elif secure %}<div class="alert-green">✅ BLOCKED or invalid credentials — parameterized SQL treats input as literal data.</div>{% else %}<div class="alert-red">❌ Invalid credentials. {% if error %}SQL error: {{ error }}{% endif %}</div>{% endif %}{% endif %}''', 'sqli', posted=request.method == 'POST', user=user, query=query, error=error, secrets_rows=secrets_rows)


@app.route('/cmdi', methods=['GET', 'POST'])
def cmdi():
    result = None
    blocked = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        count_flag = '-n' if platform.system() == 'Windows' else '-c'
        try:
            if not session.get('cmdi_secure'):
                # ⚠️ VULNERABLE: shell interprets injected operators.
                result = subprocess.check_output(f'ping {count_flag} 1 {host}', shell=True, stderr=subprocess.STDOUT, timeout=8).decode('utf-8', errors='replace')
            else:
                # ✅ SECURE: validate the host and pass an argument vector without a shell.
                if not re.fullmatch(r'[a-zA-Z0-9.\-]{1,253}', host) or host.startswith('-'):
                    blocked = '❌ BLOCKED — Invalid hostname. Only alphanumeric characters, dots and hyphens are permitted; option-like hosts are rejected.'
                else:
                    result = subprocess.check_output(['ping', count_flag, '1', host], shell=False, stderr=subprocess.STDOUT, timeout=8).decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            result = 'Request timed out.'
        except subprocess.CalledProcessError as exc:
            result = exc.output.decode('utf-8', errors='replace')
        except OSError as exc:
            result = f'Unable to run ping: {exc}'
    return page('Command Injection', '''<h1>OS Command Injection — In-Band</h1><p>Member 2 | Category: OS Command Injection | Variant: In-Band</p><div class="card"><h2>Network Diagnostic Tool</h2><form method="post"><label>Enter a hostname or IP address to ping:<input name="host" placeholder="e.g. 127.0.0.1" required></label><button class="btn btn-blue">Run Diagnostic</button></form>{% if not secure %}<pre>💡 Try: 127.0.0.1; whoami\n127.0.0.1; cat /etc/passwd\n127.0.0.1; ls -la /\nWindows: 127.0.0.1 &amp; whoami | 127.0.0.1 &amp; dir C:\\</pre>{% endif %}</div>{% if blocked %}<div class="alert-green">{{ blocked }}</div>{% endif %}{% if result is not none %}<div class="card"><h2>📡 Server Response (executing on YOUR machine):</h2><pre>{{ result }}</pre></div>{% endif %}''', 'cmdi', result=result, blocked=blocked)


@app.route('/sxss', methods=['GET', 'POST'])
def sxss():
    if request.method == 'POST':
        with get_db() as db:
            db.execute('INSERT INTO comments (username, content) VALUES (?, ?)', (request.form.get('username', ''), request.form.get('content', '')))
        return redirect(url_for('sxss'))
    with get_db() as db:
        comments = [dict(row) for row in db.execute('SELECT * FROM comments ORDER BY id DESC')]
    for comment in comments:
        if not session.get('sxss_secure'):
            # ⚠️ VULNERABLE: saved user input is trusted as HTML.
            comment['content'] = Markup(comment['content'])
            comment['username'] = Markup(comment['username'])
        else:
            # ✅ SECURE: plain strings are escaped by Jinja.
            pass
    payload = "<script>var i=new Image();i.src='/sxss/steal?cookie='+encodeURIComponent(document.cookie);</script>"
    return page('Stored XSS', '''<h1>Stored XSS — Persistent Comment Injection</h1><p>Member 3 | Category: XSS | Variant: Stored XSS</p><div class="alert-blue">An attacker saves a script in a comment. Each visitor’s browser executes it; the demo sends a JavaScript-readable cookie to the local receiver.</div><div class="card"><h2>Comment board</h2><form method="post"><label>Name<input name="username" required></label><label>Comment<textarea name="content" rows="4" required></textarea></label><button class="btn btn-blue">Post Comment</button></form>{% if not secure %}<p>💡 Try:</p><pre>{{ payload }}</pre>{% endif %}</div><div class="card"><h2>🍪 Stolen Cookies Log</h2><div class="stolen-log">{% for entry in log %}<p>[{{ entry.time }}] {{ entry.ip }}: {{ entry.cookie }}</p>{% else %}No cookies captured yet. Reload after the payload executes.{% endfor %}</div></div><h2>Comments</h2><p><a href="/sxss/clear">Clear comments</a></p>{% for c in comments %}<div class="card"><b>{{ c.username }}</b> <small>{{ c.timestamp }}</small><div style="margin-top:8px">{{ c.content }}</div></div>{% else %}<p>No comments yet.</p>{% endfor %}''', 'sxss', comments=comments, log=stolen_cookies_log, payload=payload)


@app.route('/sxss/steal')
def sxss_steal():
    stolen_cookies_log.append({'time': datetime.now().strftime('%H:%M:%S'), 'cookie': request.args.get('cookie', '')[:120], 'ip': request.remote_addr})
    gif = bytes.fromhex('47494638396101000100800000ffffff00000021f90400000000002c00000000010001000002024401003b')
    return Response(gif, mimetype='image/gif', headers={'Cache-Control': 'no-store'})


@app.route('/sxss/clear')
def sxss_clear():
    with get_db() as db:
        db.execute('DELETE FROM comments')
    return redirect(url_for('sxss'))


@app.route('/rxss')
def rxss():
    q = request.args.get('q', '')
    if not session.get('rxss_secure'):
        # ⚠️ VULNERABLE: URL input is trusted as HTML.
        result = Markup(q)
    else:
        # ✅ SECURE: Jinja escapes the ordinary string.
        result = q
    link = "http://localhost:5000/rxss?q=%3Cscript%3Ealert('Cookie%3A%20'%2Bdocument.cookie)%3C%2Fscript%3E"
    return page('Reflected XSS', '''<h1>Reflected XSS — Search Query Reflection</h1><p>Member 4 | Category: XSS | Variant: Reflected XSS</p><div class="alert-blue">A malicious URL reflects a payload in the response; a victim’s browser can execute it on opening the link. The payload is not saved.</div><div class="card"><h2>Site Search</h2><form method="get"><label>Search<input name="q" value="{{ q }}"></label><button class="btn btn-blue">Search</button></form>{% if q %}<p>You searched for: <b>{{ result }}</b></p><div class="{{ 'alert-green' if secure else 'alert-red' }}">{{ '✅ Query was HTML-escaped before reflection.' if secure else '⚠️ The query was reflected without encoding.' }} <code>{{ q }}</code></div>{% endif %}</div><div class="card"><h2>🎣 Attacker's Phishing Link (how this is delivered)</h2><input id="phish" value="{{ link }}" readonly><button class="btn btn-gray" onclick="navigator.clipboard.writeText(document.getElementById('phish').value)">📋 Copy Link</button> <a class="btn btn-red" href="{{ link }}" target="_blank" rel="noopener">▶ Open in New Tab</a><p>An attacker can send this URL via email or chat; opening it is enough to execute the script in vulnerable mode.</p></div>''', 'rxss', q=q, result=result, link=link)


def csrf_log(icon, msg):
    entries = session.get('csrf_log', [])
    entries.append({'time': datetime.now().strftime('%H:%M:%S'), 'icon': icon, 'msg': msg})
    session['csrf_log'] = entries[-20:]


@app.route('/csrf')
def csrf():
    if 'victim_email' not in session:
        session['victim_email'] = 'victim@example.com'
        csrf_log('ℹ️', 'Victim session started.')
    session['csrf_token'] = secrets.token_hex(16)
    return page('CSRF', '''<h1>CSRF — POST-Based Forged Action</h1><p>Member 5 | Category: CSRF | Variant: POST Auto-Submitting Form</p><div class="alert-blue">An attacker’s hidden form can send a request with a victim’s cookies. The attacker page runs on localhost:5001, a separate origin from localhost:5000. Both are same-site, so this demonstrates a cross-origin POST without relying on cross-site cookie behavior.</div><div class="card"><h2>👤 Victim's Profile (simulated logged-in user)</h2><p>Current Email: <b>{{ email }}</b></p><form method="post" action="/csrf/action"><label>New Email<input name="email" required></label>{% if secure %}<input type="hidden" name="csrf_token" value="{{ token }}">{% endif %}<button class="btn btn-blue">Update Email</button></form></div><div class="card"><h2>⚠️ Attacker's Page</h2><p>The page auto-submits a forged email update after three seconds.</p><a class="btn btn-red" href="http://localhost:5001/csrf/attacker" target="_blank" rel="noopener">🔗 Open Attacker Page (new tab)</a></div><div class="card"><h2>📋 Attack Timeline</h2><div class="log-panel">{% for item in log %}<p>[{{ item.time }}] {{ item.icon }} {{ item.msg }}</p>{% else %}No activity yet.{% endfor %}</div><p><a href="/csrf/clear_log">Clear Log</a></p></div>''', 'csrf', email=session['victim_email'], token=session['csrf_token'], log=session.get('csrf_log', []))


@app.route('/csrf/attacker')
def csrf_attacker():
    return page('Attacker Page', '''<div class="card" style="border-color:#ff6b6b"><h1>☠️ Attacker-Controlled Page</h1><p>1. Open http://localhost:5000/csrf first to start the victim session. This page is served from localhost:5001, a different origin.</p><p>2. A hidden form submits in three seconds: <b id="countdown">3</b></p><p>3. After the redirect, check the profile email.</p><form id="csrf_form" action="http://localhost:5000/csrf/action" method="post"><input type="hidden" name="email" value="hacked@attacker.com"></form><script>let count=3;const el=document.getElementById('countdown');const timer=setInterval(()=>{count--;el.textContent=count;if(count<=0){clearInterval(timer);el.textContent='💥 Firing!';document.getElementById('csrf_form').submit()}},1000);</script></div>''')


@app.route('/csrf/action', methods=['POST'])
def csrf_action():
    if 'victim_email' not in session:
        abort(403)
    email = request.form.get('email', '')
    if not session.get('csrf_secure'):
        # ⚠️ VULNERABLE: state changes without verifying request intent.
        old = session.get('victim_email', 'victim@example.com')
        session['victim_email'] = email
        csrf_log('⚠️', f'Unverified request changed email from {old} to {email}; no token was checked.')
    else:
        # ✅ SECURE: require a matching unpredictable token.
        token, expected = request.form.get('csrf_token', ''), session.get('csrf_token', '')
        if not token or not expected or not secrets.compare_digest(token, expected):
            csrf_log('🛡️', 'CSRF BLOCKED — token mismatch; request rejected with 403.')
            return page('403 — Forbidden', '''<div class="alert-red"><h1>403 — Forbidden</h1><p>CSRF token mismatch. This request was rejected.</p><p>The attacker's page did not supply the secret token, so the server refused the forged request.</p><a href="/csrf">← Back to Profile</a></div>'''), 403
        session['victim_email'] = email
        csrf_log('ℹ️', f'Email updated legitimately to {email}')
    return redirect(url_for('csrf'))


@app.route('/csrf/clear_log')
def csrf_clear_log():
    session['csrf_log'] = []
    return redirect(url_for('csrf'))


init_db()

if __name__ == '__main__':
    # Start only in the debug reloader's serving process; bind both servers locally.
    if is_running_from_reloader():
        attacker_server = make_server('127.0.0.1', 5001, app, threaded=True)
        threading.Thread(target=attacker_server.serve_forever, daemon=True).start()
    app.run(debug=True, port=5000)
