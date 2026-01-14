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

