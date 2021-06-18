from account.models import Configuration

def application_analytic_status(request):
	conf_obj = Configuration.objects.first()
	if conf_obj:
		application_status = conf_obj.application_status
		analytics_status = conf_obj.analytics_status
	else:
		application_status = False
		analytics_status = False
	context = {
		'application_status': application_status,
		'analytics_status': analytics_status
	}
	return context