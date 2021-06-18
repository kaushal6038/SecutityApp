from .models import *
import requests


def send_mail(reciever, subject, html_content):
    try:
        client_conf = ClientConfiguration.objects.first()
    except:
        client_conf = ''
    if client_conf:
        key = client_conf.mailgun_api_key
        base_url = client_conf.mailgun_base_url
        request_url = base_url + "/messages"
        try:
            request = requests.post(request_url, auth=('api', key), data={
                'from': "Redtree Notification<noreply@purpleleaf.io>",
                'to': reciever,
                'subject': subject,
                'html': html_content
            })
        except:
            pass


def send_host_mail(reciever, subject, html_content):
    try:
        client_conf = ClientConfiguration.objects.first()
    except:
        client_conf = ''
    if client_conf:
        key = client_conf.mailgun_api_key
        base_url = client_conf.mailgun_base_url
        request_url = base_url + "/messages"
        try:
            request = requests.post(request_url, auth=('api', key), data={
                'from': "Redtree Notification<noreply@purpleleaf.io>",
                'to': reciever,
                'subject': subject,
                'html': html_content
            })
        except:
            pass
