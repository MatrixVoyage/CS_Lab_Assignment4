# Web Security Demonstration
### IIIT Allahabad | Cyber Security (IT-30001) 

## Setup & Run

```sh
pip install flask
python app.py
# Open http://localhost:5000
```

Run these commands from the `vulnlab` folder. The SQLite database is created beside `app.py` on first start. This application deliberately executes operating-system commands and contains other vulnerabilities. Use only on an isolated machine with untrusted access prevented; do not deploy or expose it to a network. Its debug server, fixed secret and sample credentials are for demonstration only. The cookie is intentionally JavaScript-readable to demonstrate theft. The example secrets are fictitious.

## Ownership Table

| Member | Name     | Roll No    | Category         | Variant                   |
|--------|----------|------------|------------------|---------------------------|
| M1     | Gauransh | IIT2024110 | SQL Injection    | Authentication Bypass     |
| M2     | Prince   | IIT2024145 | OS Cmd Injection | In-Band Command Injection |
| M3     | Aditya   | IIT2024108 | XSS              | Stored XSS                |
| M4     | Hemant   | IIT2024112 | XSS              | Reflected XSS             |
| M5     | Yuvraj   | IIT2024109 | CSRF             | POST-Based Auto-Submit    |

## Exploit Cheatsheet

### SQL Injection (M1) — /sqli

Username: `admin'--`  
Password: `anything`  
Effect: Logs in as admin and exposes the demo secret data.

### OS Command Injection (M2) — /cmdi

Unix hostname: `127.0.0.1; whoami`, `127.0.0.1; cat /etc/passwd`, or `127.0.0.1; ls -la /`  
Windows hostname: `127.0.0.1 & whoami` or `127.0.0.1 & dir C:\`  
Effect: The server executes the additional command and displays its output. Ping must be installed; an injected command may still run if ping fails.

### Stored XSS (M3) — /sxss

Comment:

```html
<script>var i=new Image();i.src='/sxss/steal?cookie='+encodeURIComponent(document.cookie);</script>
```

Effect: Visitors' JavaScript-readable cookies are sent to the local receiver. Reload to see the log after the browser sends the request. Open a vulnerability page first to establish a session cookie. HttpOnly cookies would not be readable to JavaScript.

### Reflected XSS (M4) — /rxss

Search for `<script>alert('XSS:'+document.cookie)</script>` or `<img src=x onerror="alert(document.cookie)">`. The page also provides an encoded demonstration link. The script executes on page load in vulnerable mode.

### CSRF (M5) — /csrf

1. Open `/csrf` to start the simulated victim session. Requests sent before this step receive HTTP 403.
2. Use **Open Attacker Page** to open `http://localhost:5001/csrf/attacker` in a new tab; the form submits after three seconds.
3. Refresh `/csrf` to see the changed email and timeline.
4. Apply the fix and repeat: the forged request receives HTTP 403. A legitimate form submission includes the token.

The attacker page runs on `http://localhost:5001` and posts to `http://localhost:5000`: these are distinct origins but the same site. Keep both local ports available and use `localhost` for the victim page. This demonstrates a cross-origin forged POST, but not a cross-site cookie-policy bypass; SameSite rules can affect attacks from a different site. Flask's default session is a signed client-side cookie; the token is not a server-side synchronizer-token store. The attacker cannot read the cookie or form cross-origin under the browser's same-origin policy, but a production system should use established CSRF protection and secure session management.

## Viva Demo Flow (per member)

1. Open the app and confirm 🔴 vulnerable mode.
2. Run the exploit and show its effect.
3. Click **Apply Fix** to switch to 🟢 secure mode.
4. Run the same exploit and show it blocked.
5. Expand **Show Code, Root Cause & Theory** to explain the difference and other mitigations.

## Reset Between Demos

Click **⟳ Reset All** to clear the current browser session and its mode flags and CSRF timeline, delete all stored comments, and clear the in-memory stolen-cookie log. Other browsers retain their own sessions. The log is process-local and disappears when the server restarts.
