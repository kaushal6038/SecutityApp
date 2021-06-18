import pytz
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from django.http import HttpResponseNotAllowed
from django.shortcuts import render

User = get_user_model()


class TimezoneMiddleware(MiddlewareMixin):

    def process_request(self, request):
        username = request.session.get('usr')
        try:
            user = User.objects.get(pk=username)
        except:
            user = None
        if user:
            tzname = user.time_zone
            if tzname:
                timezone.activate(pytz.timezone(tzname))
            else:
                timezone.activate("UTC")
        else:
            timezone.activate("UTC")

    def process_exception(self, request, exception):
        db_error  = "settings.DATABASES is improperly configured. Please supply the NAME value."
        if exception.__class__.__name__ == "ImproperlyConfigured" and exception.message == db_error:
            return HttpResponse("<b>Database is improperly configured.</b> Please contact admin for more details")
        else:
            return None


class HttpResponseNotAllowedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if isinstance(response, HttpResponseNotAllowed):
            return HttpResponse('method not allowded')

        return response