# Cybersecurity Authentication Toolkit

> **Educational project.** Use only on systems you own or are explicitly authorised to test.

## 1. Problem Statement
Weak registration and login systems (plain-text passwords, SQL injection, missing validation, insecure sessions) are among the most common causes of account compromise. Beginners need a small, readable example of doing it correctly.

## 2. Objective
Build a minimal Flask web application that demonstrates secure user registration, password hashing, login, session handling and logout, using a SQLite database.

## 3. Features
- User registration with server-side validation (username, email, password strength)
- Salted password hashing (Werkzeug `generate_password_hash`)
- SQLite database with parameterised queries
- Session management (cookie flags, 30-minute lifetime, session reset on login)
- Logout (POST + CSRF token)
- Clear, safe error messages (same message for wrong username or wrong password)
- Basic login throttling (5 failed attempts then a 5-minute wait)
- Configuration via environment variables, no hard-coded production secret

## 4. Technologies Used
- Python 3
- Flask
- SQLite (`sqlite3` module)
- HTML + CSS (Jinja2 templates)

## 5. Folder Structure
```text
01-cybersecurity-authentication-toolkit/
  .env.example
  .gitignore
  LICENSE
  README.md
  app.py
  requirements.txt
  static/style.css
  templates/base.html
  templates/dashboard.html
  templates/error.html
  templates/index.html
  templates/login.html
  templates/register.html
```

## 6. Installation Steps
1. Install **Python 3.9 or newer** from <https://www.python.org/downloads/> (tick "Add Python to PATH" on Windows).
2. Open a terminal **inside this project folder**.
3. Create and activate a virtual environment:
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv venv` then `source venv/bin/activate`
4. Install the dependencies: `pip install -r requirements.txt`

## 7. Commands to Run
```bash
python app.py
# Optional: set your own secret key first
#   Windows (PowerShell): $env:SECRET_KEY="your-long-random-string"
#   macOS/Linux:          export SECRET_KEY="your-long-random-string"
# Then open http://127.0.0.1:5000 in your browser
```

## 8. How It Works
1. `init_db()` creates a `users` table in `users.db` on start-up.
2. **Register** validates input on the server, hashes the password and stores only the hash.
3. **Login** looks the user up with a parameterised query, verifies the hash, clears the old session and stores the user id in a signed cookie.
4. **Dashboard** is only shown when a session exists; **Logout** clears the session.
5. Every POST form carries a CSRF token that the server checks.

## 9. Example Input / Output
**Input (Register form):** username `alice_1`, email `alice@example.com`, password `GoodPass123`.

**Output:** redirect to Login with the message *Account created. You can now log in.*

**Wrong password:** *Invalid username or password.* (HTTP 401)

**Weak password (`short`):** *Password must be at least 10 characters long.*

## 10. Screenshots
_Add your own screenshots after running the project (do not use screenshots from elsewhere)._

| Description | Screenshot |
|---|---|
| Main screen / output | `docs/screenshot-1.png` _(placeholder)_ |
| Another feature | `docs/screenshot-2.png` _(placeholder)_ |

## 11. Demo Link
`<YOUR-DEMO-LINK-HERE>` _(placeholder: this project has not been deployed by the author of this template)_

## 12. Security Measures
- Passwords are never stored in plain text (salted hash)
- Parameterised SQL queries (prevents SQL injection)
- CSRF tokens on all POST forms
- HttpOnly + SameSite cookies; Secure flag available via `SESSION_COOKIE_SECURE=1`
- Secret key from environment; random temporary key if missing
- Security headers (CSP, X-Frame-Options, nosniff, no-store)
- Jinja2 auto-escaping (prevents XSS)
- Debug mode is off by default

## 13. Limitations
- Login throttling is in memory only (resets on restart; not suitable for multiple servers)
- No email verification or password reset
- No multi-factor authentication
- Uses Flask's development server: not for production
- SQLite is fine for learning, not for large deployments

## 14. Future Improvements
- Email verification and password reset
- TOTP two-factor authentication
- Persistent rate limiting (e.g. Redis)
- Account lockout notifications
- Automated unit tests

## 15. GitHub Upload Instructions
1. Sign in at <https://github.com> and click **New repository** (the **+** icon, top right).
2. Name it `01-cybersecurity-authentication-toolkit`, choose Public or Private, and click **Create repository**.
3. On the new repo page click **uploading an existing file**.
4. Drag in the **contents** of this folder (files and sub-folders, *not* the ZIP itself). Hidden files such as `.gitignore` must be included.
5. Write a commit message such as `Initial commit` and click **Commit changes**.
6. Edit `LICENSE` and replace `<YOUR NAME>`; add real screenshots to a `docs/` folder and update the README.

## License
MIT. See `LICENSE`.
