# Secure Login System

A Python Flask web application that provides secure user registration, login, protected dashboard access, logout, password hashing, session management, CSRF protection, login rate limiting, and optional two-factor authentication.

The user interface is generated from Python code. The project does not use separate HTML, CSS, or JavaScript source files.

## Features

- User registration
- Full name, username, email, password, and password confirmation fields
- Password complexity validation
- Bcrypt password hashing
- Login with username or email
- Generic login error messages
- SQLite database with SQLAlchemy ORM
- Unique username and email constraints
- CSRF protection
- Login rate limiting
- Protected dashboard
- Secure logout and session invalidation
- HttpOnly and SameSite session cookies
- Optional TOTP two-factor authentication
- Pytest security and functionality tests

## Technologies

- Python 3.11+
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- Flask-Limiter
- PyOTP
- SQLite
- pytest

## Project Structure

```text
secure-login-system/
├── app.py
├── requirements.txt
├── tests/
│   └── test_app.py
├── .gitignore
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/secure-login-system.git
cd secure-login-system
```

Create a virtual environment:

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Set a strong random secret key before running outside a local development environment.

### Windows PowerShell

```powershell
$env:SECRET_KEY="replace-this-with-a-long-random-secret"
```

### macOS/Linux

```bash
export SECRET_KEY="replace-this-with-a-long-random-secret"
```

For HTTPS deployment, enable secure cookies:

```bash
export COOKIE_SECURE=1
```

The default SQLite database is created as `secure_login.db` in the project directory. This file is excluded from Git by `.gitignore`.

## Run the Application

```bash
python app.py
```

Open the local address shown by Flask, usually:

```text
http://127.0.0.1:5000
```

## User Flow

1. Open **Register** and create an account.
2. Sign in using the username or email address.
3. View the protected dashboard.
4. Open **Security** to configure optional TOTP two-factor authentication.
5. Log out using the secure POST logout action.

## Run Tests

```bash
pytest -q
```

The tests cover:

- Password hashing
- Registration
- Login
- Generic invalid-login messages
- CSRF protection
- Protected dashboard access
- Logout and session invalidation
- Weak-password rejection

## Security Notes

- Passwords are never stored in plaintext.
- Password hashes are never included in application responses.
- SQLAlchemy ORM operations are used instead of string-built SQL queries.
- Login attempts are rate-limited.
- Login errors do not reveal whether a username or email exists.
- CSRF tokens are required for state-changing form submissions.
- Session cookies are configured with HttpOnly and SameSite protections.
- Secure cookies should be enabled when deploying behind HTTPS.
- The development fallback secret key is generated at process start and must not be used as a production configuration.
- Password reset is not included in this educational version; add a carefully designed, expiring, single-use token flow before production use.

## License

This project is provided for educational purposes.
