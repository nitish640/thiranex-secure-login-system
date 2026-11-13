# Thiranex Cyber Security — Task 4: Secure Login System

A secure login web app built for the Thiranex Cyber Security internship
(Task 4, due 21 Jul 2026). Flask + SQLite + bcrypt, with optional TOTP 2FA.

## Features (mapped to the task requirements)

| Requirement | How it is implemented |
|---|---|
| User registration & login with hashed passwords | bcrypt (`bcrypt.hashpw` / `checkpw`); only the hash is stored in SQLite — never the plaintext password |
| Input validation | Username 3–20 chars (letters/digits/underscore), email regex, password must be 8+ chars with upper, lower, digit and special character; server-side checks on every POST |
| Protection from SQL injection | **Parameterised queries only** (`WHERE username = ?`, …). No string-concatenated SQL anywhere. An injection string such as `' OR '1'='1` is treated as a literal username and fails safely (verified in tests) |
| Session management with logout | Flask sessions, 30-minute lifetime, `HttpOnly` + `SameSite=Lax` cookies; `/dashboard` is protected (`@login_required`); `/logout` clears the session immediately |
| Optional 2FA | TOTP via `pyotp`: set up from the dashboard (QR code data URI, scan with Google Authenticator / Authy), then the login flow requires the 6-digit code before the session is created. Can be disabled from the dashboard |
| Extra hardening | Rate limiting / lockout: 5 failed logins → 5-minute lockout; password strength meter + show/hide password on the forms |

## Project structure

```
task-4-secure-login-system/
├── app.py               # Flask app: routes, validation, bcrypt, sessions, TOTP, lockout
├── requirements.txt     # Flask, bcrypt, pyotp, qrcode, Pillow
├── test_app.py          # 17 automated checks (Flask test client, no server needed)
├── templates/
│   ├── base.html        # shared layout / styling
│   ├── register.html    # register + strength meter + show/hide password
│   ├── login.html       # login + show/hide password
│   ├── dashboard.html   # protected page, 2FA status, logout
│   ├── setup_2fa.html   # QR code + secret, verify code to enable 2FA
│   └── verify_2fa.html  # TOTP code prompt during login
├── .gitignore           # excludes .venv/, users.db, __pycache__
└── README.md
```

## Setup & run (local only)

```bash
cd task-4-secure-login-system
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
# open http://127.0.0.1:5000
```

The SQLite database `users.db` is created automatically on first run.
For a real deployment, set a persistent `SECRET_KEY` environment variable,
serve over HTTPS, and use a production WSGI server — the built-in Flask
server is for local development only.

## Demo flow (test credentials only — created locally, never real passwords)

1. Open http://127.0.0.1:5000/register and create a test account, e.g.
   username `demouser`, email `demo@example.com`, password `Demo!Pass9`
   (the strength meter should show Strong/Very strong).
2. Log in at `/login` with those credentials → protected dashboard.
3. Optional 2FA: on the dashboard click **Set up two-factor
   authentication**, scan the QR code with an authenticator app, enter the
   6-digit code. Log out and log in again — you will now be asked for the
   TOTP code after the password.
4. Log out from the dashboard; visiting `/dashboard` again redirects to login.

## Tests

```bash
.venv/bin/python test_app.py
```

**Test results (run 13 Nov 2026, local): 17 passed, 0 failed**, covering:
register, weak-password rejection, duplicate-username rejection, bcrypt
hash storage (hash starts `$2b$`, plaintext absent from the DB), correct
login → dashboard, dashboard protected after logout, wrong-password
rejection, SQL injection as username **and** as password both failing
safely with no login, lockout after 5 failed attempts, and the full
2FA setup + login flow (wrong code rejected, correct code logs in).

**Live server test (same day, `curl` against `http://127.0.0.1:5000`):**
register → 302 to login with "Account created"; login → 302 to
`/dashboard` and the dashboard shows "Welcome, demouser"; logout works
and `/dashboard` then redirects to login; wrong password → "Invalid
username or password"; SQL-injection username `' OR '1'='1` → "Invalid
username or password" and no login. All confirmed.

## What I learned

- Passwords must never be stored — only a salted, adaptive hash
  (bcrypt) belongs in the database.
- SQL injection is prevented by parameterised queries, not by filtering
  or blacklisting input: the dangerous string is data, never code.
- Authentication is two parts: verifying the password **and** managing
  the session afterwards (expiry, HttpOnly cookies, explicit logout).
- Rate limiting matters as much as hashing: without a lockout, even a
  strong hash can be brute-forced one guess at a time.
- TOTP 2FA adds a second factor that stays secure even if the password
  leaks — the login must not create a session until the code is verified.
