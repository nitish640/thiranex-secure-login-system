"""Automated checks for the Secure Login System (Task 4).

Run with the project venv, from the project directory:
    .venv/bin/python test_app.py

Uses Flask's test client — no server needed, no real network.
Covers: register, login, logout, wrong password, SQL-injection
attempt, weak-password rejection, protected dashboard, and the
full TOTP 2FA setup + login flow.
"""
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pyotp  # noqa: E402

import app as app_module  # noqa: E402

DB = app_module.DB_PATH
if os.path.exists(DB):
    os.remove(DB)
app_module.init_db()
app_module.app.config["TESTING"] = True
client = app_module.app.test_client()

passed, failed = [], []


def check(name, condition):
    (passed if condition else failed).append(name)
    print(("PASS" if condition else "FAIL"), "-", name)


# 1. Register a test user (local test credentials only)
r = client.post(
    "/register",
    data={"username": "testuser", "email": "test@example.com",
          "password": "Str0ng!Pass", "confirm": "Str0ng!Pass"},
    follow_redirects=True,
)
check("register test user -> login page", b"Log in" in r.data)

# 2. Weak password is rejected
r = client.post(
    "/register",
    data={"username": "weakuser", "email": "weak@example.com",
          "password": "12345", "confirm": "12345"},
    follow_redirects=True,
)
check("weak password rejected", b"Password needs" in r.data)

# 3. Duplicate username is rejected
r = client.post(
    "/register",
    data={"username": "testuser", "email": "other@example.com",
          "password": "Str0ng!Pass", "confirm": "Str0ng!Pass"},
    follow_redirects=True,
)
check("duplicate username rejected", b"already registered" in r.data)

# 4. Password is stored as a bcrypt hash, not plaintext
row = sqlite3.connect(DB).execute(
    "SELECT password_hash FROM users WHERE username = ?", ("testuser",)
).fetchone()
check("password stored as bcrypt hash, not plaintext",
      row is not None and row[0].startswith(b"$2b$") and b"Str0ng!Pass" not in row[0])

# 5. Login with correct password -> dashboard
r = client.post(
    "/login", data={"username": "testuser", "password": "Str0ng!Pass"},
    follow_redirects=True,
)
check("login with correct password -> dashboard", b"Welcome, testuser" in r.data)

# 6. Dashboard is protected: after logout it redirects to login
client.get("/logout", follow_redirects=True)
r = client.get("/dashboard", follow_redirects=True)
check("dashboard requires login after logout", b"Log in" in r.data and b"Welcome, testuser" not in r.data)

# 7. Wrong password fails
r = client.post(
    "/login", data={"username": "testuser", "password": "Wrong!Pass1"},
    follow_redirects=True,
)
check("wrong password rejected", b"Invalid username or password" in r.data)

# 8. SQL injection attempt fails safely
#    "' OR '1'='1" is treated as a literal username via a parameterised
#    query — it matches no user, so login fails and no data leaks.
r = client.post(
    "/login", data={"username": "' OR '1'='1", "password": "anything"},
    follow_redirects=True,
)
check("SQL injection \"' OR '1'='1\" fails safely", b"Invalid username or password" in r.data)
r = client.post(
    "/login", data={"username": "testuser", "password": "' OR '1'='1"},
    follow_redirects=True,
)
check("SQL injection as password fails safely", b"Invalid username or password" in r.data)
check("injection did not log anyone in",
      client.get("/dashboard", follow_redirects=True).data.find(b"Welcome, testuser") == -1)

# 9. Lockout after 5 failed attempts
for _ in range(5):
    client.post("/login", data={"username": "testuser", "password": "Wrong!Pass1"})
r = client.post(
    "/login", data={"username": "testuser", "password": "Str0ng!Pass"},
    follow_redirects=True,
)
check("account locked after 5 failed attempts", b"locked for 5 minutes" in r.data)
app_module.FAILED_ATTEMPTS.clear()  # reset lockout for the 2FA test

# 10. TOTP 2FA: setup, then login requires the code
client.post("/login", data={"username": "testuser", "password": "Str0ng!Pass"},
            follow_redirects=True)
r = client.get("/setup-2fa")
check("2FA setup page shows QR code", b"data:image/png;base64" in r.data)
secret = re.search(rb"secret manually: <code>([^<]+)</code>", r.data)
assert secret, "TOTP secret not found on setup page"
secret = secret.group(1).decode()
code = pyotp.TOTP(secret).now()
r = client.post("/setup-2fa", data={"code": code}, follow_redirects=True)
check("2FA enabled with valid TOTP code", b"Two-factor authentication enabled" in r.data)
client.get("/logout", follow_redirects=True)

# Login now stops at the 2FA step
r = client.post("/login", data={"username": "testuser", "password": "Str0ng!Pass"},
                follow_redirects=True)
check("login with 2FA enabled asks for TOTP code", b"Two-factor authentication" in r.data)
check("not fully logged in before 2FA", b"Welcome, testuser" not in r.data)
# Wrong code fails, correct code logs in
r = client.post("/verify-2fa", data={"code": "000000"}, follow_redirects=True)
check("wrong 2FA code rejected", b"Invalid 2FA code" in r.data)
r = client.post("/verify-2fa", data={"code": pyotp.TOTP(secret).now()},
                follow_redirects=True)
check("correct 2FA code completes login", b"Welcome, testuser" in r.data)

print(f"\n{len(passed)} passed, {len(failed)} failed")
if failed:
    print("Failed:", failed)
    sys.exit(1)
print("All tests passed.")
