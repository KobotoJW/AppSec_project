# IMPORTANT

When creating an account the activation email will be printed to the termnal. The link may be broken with a newline - in that case you need to delete the `=` character for the link!

```
Hello,

Please click the link below to activate your account:

http://127.0.0.1:8000/accounts/activate/cae1658041ef3c9d0c3d1a95ad29b4f6586ee=  <--- HERE
93eb2df7368d96ecaf384084eaf/

This link will expire in 24 hours.

If you did not register for this account, please ignore this email.
```

## Installation

Docker compose file in this project is a database container - not a main program.

1. Create a virtual env.
```
python -m venv .venv
source .venv/bin/activate
```

2. Install requeired dependencies.
```
pip install --upgrade pip
pip install -r requirements.txt
```

3. Create a `.env` file in project's root.

`.env` file contents:
```
# Django Settings - DEVELOPMENT ONLY
DJANGO_SECRET_KEY=django-insecure-dev-key-for-local-development-only
DJANGO_DEBUG=True

# Database Configuration
DB_NAME=appsec_db
DB_USER=appsec_user
DB_PASSWORD=appsec_secret_password
DB_HOST=localhost
DB_PORT=5432

EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend

ALLOWED_HOSTS=localhost,127.0.0.1
```
4. Initialize a DB.
```
docker-compose up db
```

5. Starting django app.
```
python manage.py migrate
python manage.py createsuperuser

# Migrate and createsuperuser need to be performed only once when first launching a program.
python manage.py runserver
```

