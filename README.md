Secure Login System

A Python Flask web application that provides secure user registration, login, logout, protected dashboard access, password hashing, session management, CSRF protection, rate limiting, and optional two-factor authentication.

Features

•
User registration

•
Login with username or email

•
Bcrypt password hashing

•
Password complexity validation

•
SQLite database

•
SQLAlchemy ORM

•
CSRF protection

•
Login rate limiting

•
Protected user dashboard

•
Secure logout and session invalidation

•
HttpOnly and SameSite session cookies

•
Optional TOTP two-factor authentication

•
Automated tests with pytest

Technologies

•
Python 3.11+

•
Flask

•
Flask-SQLAlchemy

•
Flask-Bcrypt

•
Flask-Limiter

•
PyOTP

•
SQLite

•
pytest

Project Structure

Plain Text


secure-login-system/
├── app.py
├── requirements.txt
├── tests/
│   └── test_app.py
└── README.md



Installation

Clone the repository:

Bash


git clone https://github.com/your-username/secure-login-system.git
cd secure-login-system



Replace your-username with your GitHub username.

Create a virtual environment:

Windows

Bash


python -m venv .venv
.venv\Scripts\activate



macOS/Linux

Bash


python3 -m venv .venv
source .venv/bin/activate



Install the dependencies:

Bash


pip install -r requirements.txt



Configuration

Set a secret key before using the application outside local development.

Windows PowerShell

Plain Text


$env:SECRET_KEY="your-long-random-secret-key"



macOS/Linux

Bash


export SECRET_KEY="your-long-random-secret-key"



For HTTPS deployment, enable secure cookies:

Bash


export COOKIE_SECURE=1



Run the Application

Bash


python app.py



Open the application at:

Plain Text


http://127.0.0.1:5000



How to Use

1.
Register a new account.

2.
Log in with your username or email.

3.
Open the protected dashboard.

4.
Visit the Security page to configure optional two-factor authentication.

5.
Log out using the logout button.

Run Tests

Bash


pytest -q



The tests cover registration, password hashing, login, CSRF protection, protected dashboard access, logout, and weak-password rejection.

Security Notes

•
Passwords are never stored in plaintext.

•
Password hashes are not shown in responses.

•
Login errors use generic messages.

•
Database operations use SQLAlchemy ORM.

•
Login attempts are rate-limited.

•
CSRF tokens protect form submissions.

•
Sessions use HttpOnly and SameSite cookie settings.

•
Enable secure cookies when deploying with HTTPS.

•
Never use development settings or a temporary secret key in production.

License

This project is provided for educational purposes.

