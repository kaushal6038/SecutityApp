from django.template import Context
from redtree_app.models import TestVulnerabilities, RetestVulnerabilities
import os
import subprocess
import redtree
from redtree_app.environment_constant import environment_name

def count_test_vulnerability(request):
	test_vul_count = TestVulnerabilities.objects.all().count()
	retest_count = RetestVulnerabilities.objects.filter(status="Requested").count()
	if test_vul_count == 0:
		test_vul_count = ''
	context = {
			'test_vul_count':test_vul_count,
			'retest_count': retest_count
		}
	
	return context


def get_branch_name(request):
	context = {
		'environment_name': environment_name
	}
	return context