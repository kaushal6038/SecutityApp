from purpleleaf_app.models import PrivateConfiguration


def get_private_request_header():
	conf_obj = PrivateConfiguration.objects.first()
	if conf_obj and conf_obj.data_auth_key:
		header = {'data-auth-key': conf_obj.data_auth_key}
	else:
		header = {'data-auth-key': None}
	return header
