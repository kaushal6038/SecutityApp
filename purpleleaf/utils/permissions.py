from account.models import Configuration
from rest_framework.exceptions import PermissionDenied


def is_valid_request(request):
	conf_obj = Configuration.objects.first()
	auth_key = request.META.get('HTTP_DATA_AUTH_KEY')
	if auth_key and (auth_key == conf_obj.redtree_auth_key):
		return True
	raise PermissionDenied()