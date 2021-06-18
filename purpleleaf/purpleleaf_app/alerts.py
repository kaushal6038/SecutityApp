import requests
from .models import *
from twilio.rest import Client
import random
from django.conf import settings


def send_confirmation_code(to_number):
	verification_code = generate_code()
	message = "Your One Time Password Is {}".format(verification_code)
	sms_status = send_sms(to_number, message)
	if sms_status == True:
		return verification_code
	else:
		return None


def generate_code():
	return str(random.randrange(100000, 999999))


def send_sms(to_number, body):
	try:
		client_conf = Configuration.objects.first()
	except:
		client_conf = None
	if client_conf:
		account_sid = client_conf.twilio_account_sid
		account_auth_token = client_conf.twilio_auth_key
		twilio_number = client_conf.twilio_account_number
	else:
		return False
	client = Client(account_sid, account_auth_token)
	try:
		msg = client.messages.create(to_number, from_=twilio_number, body=body)
		return True
	except:
		return False


def send_mail(reciever, subject, html_content):
	client_conf = Configuration.objects.first()
	if client_conf:
		key = client_conf.mailgun_api_key
		base_url = client_conf.mailgun_base_url
		request_url = base_url + "/messages"
		try:
			request = requests.post(request_url, auth=('api', key), data={
			'from': "PurpleLeaf <noreply@purpleleaf.io>",
			'to': reciever,
			'subject': subject,
			'html': html_content
			})
		except:
			pass
