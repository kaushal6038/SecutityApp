#!/bin/bash

echo "Starting migrations..."

python manage.py migrate

echo "Migrations complete, Starting collectstatic using nginx..."

python manage.py collectstatic --no-input

echo "Collectstatic complete, Starting createsu..."

python manage.py createsu

echo "Createsu complete, Starting import default configurations..."

python manage.py import_default_config

echo "Import default configurations complete, Starting create region command..."

python manage.py create_region

echo "Create region command complete, Starting update scans schedule..."

python manage.py update_scan_schedule

echo "Update scans schedule command complete, Starting Server using gunicorn..."

echo "Inviting Default User"

python manage.py invite_user

gunicorn --env DJANGO_SETTINGS_MODULE=redtree.settings redtree.wsgi:application --bind 0.0.0.0:8005

echo "Server started"