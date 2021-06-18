#!/bin/bash

echo "Starting migrations..."


python manage.py migrate

echo "Migrations complete, Starting collectstatic..."

python manage.py collectstatic --no-input

echo "Collectstatic complete, Starting createsu..."

python manage.py createsu

echo "Createsu complete, Starting Import default config..."

python manage.py import_default_config

echo "Import default config complete, Show crontabs..."

python manage.py crontab show

echo "Show crontabs complete, Adding crontabs..."

python manage.py crontab add

echo "Crontab add completed, Show crontabs..."

python manage.py crontab show

echo "Show crontabs complete, Starting Server using bjoern..."

python bjoern_run.py --env DJANGO_SETTINGS_MODULE=purpleleaf.settings purpleleaf.wsgi:application --bind 0.0.0.0:8004


echo "Server started"
