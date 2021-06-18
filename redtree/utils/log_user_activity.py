import requests
from django.utils import timezone
from urlparse import urlparse
from private.serializers import LogRedtreeUserActivitySerializer


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
	if "user-login" in url:
		url = "Login"
	elif "logout" in url:
		url = "Logout"
	time_stamp = timezone.now().strftime('%s')
	ip = get_request_ip(request)
	username = request.user.email
	data = {
		'event_type': url,
		'time_stamp': time_stamp,
		'ip': ip,
		'username': username
	}
	serializer = LogRedtreeUserActivitySerializer(data=data)
	if serializer.is_valid():
		serializer.save()