import os
import pytz
import logging
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from threading import local
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.contrib import messages

_user = local()

class TimezoneMiddleware(MiddlewareMixin):

	def process_request(self, request):
		from redtree_app.models import ClientConfiguration # to avoid circular dependency
		conf_obj = ClientConfiguration.objects.first()
		if conf_obj and conf_obj.time_zone:
			tzname = conf_obj.time_zone
			timezone.activate(pytz.timezone(tzname))
		else:
			timezone.activate("America/Cancun")


class CurrentUserMiddleware(MiddlewareMixin):
	def process_request(self, request):
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for:
			ip = x_forwarded_for.split(',')[0]
		else:
			ip = request.META.get('REMOTE_ADDR')
		_user.ip = ip
		_user.value = request.user


class VariablesCheckMiddleware(MiddlewareMixin):
	def process_request(self, request):
		env_variables = [os.environ.get('PURPLELEAF_URL'), os.environ.get('REDTREE_URL')]
		if all(env_variables):
			return None
		else:
			if not request.path == '/user-login':
				logout(request)
				logging.error('Environment variable is missing')
				return redirect('/user-login')


def get_current_user():
	return _user.value, _user.ip
