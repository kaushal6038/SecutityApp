from django.core.management.base import BaseCommand
import json
import os
from redtree_app.models import *
from django.http import JsonResponse
import requests

name = os.environ.get('NAME')
email = os.environ.get('INVITE_EMAIL')
admin_email = 'elliott.frantz@virtuesecurity.com'
admin_name = 'Admin'

class Command(BaseCommand):

    def handle(self, *args, **options):
        add_user(admin_email, admin_name)
        add_user(email, name)


def add_user(email, name):

    if not PurpleleafUsers.objects.filter(user_email=email).exists():
        conf_obj = ClientConfiguration.objects.first()
        if conf_obj:
            post_url = "{}/private/user".format(conf_obj.hostname)
            data = {
                'name': name,
                'email': email
            }
            headers = {
                'data-auth-key': conf_obj.authentication_token
            }
            try:
                response = requests.post(
                    post_url,
                    data=data,
                    headers=headers
                )
            except Exception as e:
                error_message = "Either some network issue or purpleleaf is down!"
                responseData = {
                    'status': False,
                    'message': error_message
                }
                return JsonResponse(responseData, safe=False)
            if response and response.status_code == 201:
                response_data = response.json().get('user')
                # print response_data
                pl_user_obj = PurpleleafUsers.objects.create(
                    user_name=response_data.get('name'),
                    user_email=response_data.get('email'),
                    purpleleaf_id=response_data.get('id'),
                    active=False,
                    activation_key=response_data.get('activation_key'),
                )
                RedtreeEventHistory.objects.create(
                    event_type='Add PL User Success',
                    time_stamp=datetime.now().strftime('%s'),
                    username=name,
                    ip='0.0.0.0',
                    data=response_data.get('email')
                )
                responseData = {
                    'status': True,
                    'message': "User added Successfully!"
                }
                return JsonResponse(responseData, safe=False)
            elif response.status_code == 403:
                responseData = {
                    'status': False,
                    'message': "Invalid AUTH key"
                }
                return JsonResponse(responseData, safe=False)
            else:
                try:
                    response = response.json()
                except:
                    response = None
                if response and response.get('errors'):
                    error_message = response.get('errors')
                elif response and not response.get('errors'):
                    error_message = response
                else:
                    error_message = "Either some network issue or purpleleaf is down!"
                responseData = {
                    'status': False,
                    'message': error_message
                }
                return JsonResponse(responseData, safe=False)
    else:
        responseData = {
            'status': False,
            'message': "User with given email already exists"
        }
        return JsonResponse(responseData, safe=False)

add_user(admin_email, admin_name)
add_user(email, name)
