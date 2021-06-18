from redtree_app.models import *
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions


def is_valid_request(request):
	message = "No Authentication key provided"
	conf_obj = Configuration.objects.first()
	auth_key = request.META.get('HTTP_DATA_AUTH_KEY')
	if auth_key and (auth_key == conf_obj.purpleleaf_auth_key):
		return True
	elif auth_key and not (auth_key == conf_obj.purpleleaf_auth_key):
		message = "Invalid auth key provided"
	raise PermissionDenied(message)


class CustomAuthentication(authentication.BaseAuthentication):
	def authenticate(self, request):
		conf_obj = Configuration.objects.first()
		data_auth_key = request.META.get('HTTP_DATA_AUTH_KEY')
		if not data_auth_key:
			return None
		if data_auth_key == conf_obj.purpleleaf_auth_key:
			try:
				user = User.objects.get(username="elliott")
			except User.DoesNotExist:
				raise exceptions.AuthenticationFailed('No superuser exists to enable auth')
			return (user, None)
		else:
			raise exceptions.AuthenticationFailed('Invalid auth key provided')
