#!/bin/bash
echo "Collect static files"
python manage.py collectstatic --noinput
echo "Apply database migrations"
python manage.py migrate
echo "Create Super User"
python manage.py createsu
echo "Starting server"
python manage.py runserver 0.0.0.0:8000 --settings=redtree.docker_settings 
echo "server started "