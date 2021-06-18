import requests
from django.utils import timezone

from utils.helpers import get_private_request_header

from purpleleaf_app.models import (
	PrivateConfiguration
)
from urlparse import urlparse


def get_request_ip(request):
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_forwarded_for:
		ip = x_forwarded_for.split(',')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	return ip


def log_user_activity(request):
	request_url = request.build_absolute_uri()
	parsed_uri = urlparse(request_url)
	if parsed_uri.path.startswith('/'):
		path = (parsed_uri.path)[1:]
	else:
		path = parsed_uri.path
	url = '{uri.scheme}://{uri.netloc}/{path}'.format(
		uri=parsed_uri, path=path
	)
	if "verify-2fa" in url:
		url = "Login"
	time_stamp = timezone.now().strftime('%s')
	ip = get_request_ip(request)
	username = request.user.email
	conf_obj = PrivateConfiguration.objects.first()
	data = {
		'event_type': url,
		'time_stamp': time_stamp,
		'ip': ip,
		'username': username
	}
	try:
		post_url = "{}/private/purpleleaf-activity/".format(
			conf_obj.redtree_base_url
		)
		response = requests.post(
			post_url,
			json=data,
			headers=get_private_request_header()
		)
	except:
		pass