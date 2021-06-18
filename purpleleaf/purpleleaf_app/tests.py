# # -*- coding: utf-8 -*-
# from __future__ import unicode_literals
# from django.test import TestCase
# from django.test import Client
# from purpleleaf_app.views import *
# from purpleleaf_app.models import *
# from django.utils import timezone
# from django.urls import reverse
# from django.contrib.auth.hashers import check_password

# # Create your tests here.

# # class PurpleleafTestCase(TestCase):
# # 	fixtures = [
# #  		'purpleleaf_app/fixtures/purpleleaf_app_data.json',
# #  	]
# #  	client = Client(enforce_csrf_checks=True)

# #  	''' Login Test '''
# #  	def login_test(self):
# # 		response = self.client.post("/signin/", {"email": "rajinder.ameo@gmail.com", "password": "123"}, follow=True)
# # 		session = self.client.session
# # 		session_obj = AppuserSession.objects.get(session_id=session['session_id'])
# # 		user = User.objects.get(id=session_obj.user.id)
# # 		session['usr'] = user.id
# # 		session['email'] = user.email
# # 		session.save()
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		self.assertEquals(response.redirect_chain[1][0], '/2fa/')

# # 	''' Logout test '''
# # 	def logout_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/signout/", follow=True)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		self.assertEquals(response.redirect_chain[1][0], '/signin/')
# # 		self.assertNotEquals(response.status_code, 404)

# # 	'''Change Password Form test case with valid data'''
# # 	def change_password_form_valid_test(self):
# # 		form = ChangePasswordForm(data={'password': 123, "new_password": 123, 'confirm_password': 123})
# # 		self.assertTrue(form.is_valid())

# # 	'''Change Password Form test case with invalid data'''
# # 	def change_password_form_invalid_test(self):
# # 		form = ChangePasswordForm(data={'password': 123, "new_password": 6633, 'confirm_password': 333})
# # 		self.assertFalse(form.is_valid())

# # 	'''Change Password Test Case with valid data'''
# # 	def change_password_success_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/change-password/", {'password': "123", "new_password": "233", 'confirm_password': "233"}, follow=True)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(response.redirect_chain[0][0], "/dashboard")
# # 		session = self.client.session
# # 		session_obj = AppuserSession.objects.get(session_id=session['session_id'])
# # 		user = User.objects.get(id=session_obj.user.id)
# # 		self.assertTrue(check_password("233", user.password))

# # 	'''Change Password Test Case with invalid data'''
# # 	def change_password_failure_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/change-password/", {'password': "123", "new_password": "222", 'confirm_password': "233"}, follow=True)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		session = self.client.session
# # 		session_obj = AppuserSession.objects.get(session_id=session['session_id'])
# # 		user = User.objects.get(id=session_obj.user.id)
# # 		self.assertFalse(check_password("222", user.password))

# # 	''' Settings page test '''
# # 	def settings_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/settings/", {"password":"123", "new_password": "456", "confirm_password": "456"} , follow=True)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		self.assertEquals(response.redirect_chain[1][0], '/dashboard/')
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Home page test '''
# #  	def home_page_test(self):
# #  		self.login_test()
# #  		response = self.client.get("", follow=True)
# #  		self.assertNotEquals(len(response.redirect_chain), 0)
# #  		if response.redirect_chain[-1][0] == '/dashboard/':
# #  			self.assertEquals(response.redirect_chain[1][0], '/dashboard/')
# #  		elif response.redirect_chain[-1][0] == '/dashboard/':
# #  			self.assertEquals(response.redirect_chain[1][0], '/dashboard/')
# #  		self.assertNotEquals(response.status_code, 404)
		
# # 	''' Target page test '''
# # 	def target_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/dashboard/",{"ip_address":"10.1.4.2,10.5.1.3"},follow=True)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		self.assertEquals(response.redirect_chain[1][0], '/dashboard/')
# # 		self.assertNotEquals(response.status_code, 404)
	
# # 	''' Add new IP test '''
# # 	def addnewip_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/newips/",{"network_id":"106","ip_address":"10.1.4.2,10.5.1.3"},follow=True)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		last_url = response.redirect_chain[-1]
# # 		redirect_to_host = False
# # 		if "hosts" in last_url[0]:
# # 			redirect_to_host = True
# # 		self.assertTrue(redirect_to_host)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Vulnerability page test '''
# # 	def vulnerability_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/vulnerabilities/", follow=True)
# # 		self.assertEqual(response.templates[0].name,'purpleleaf_app/vulnerabilities.html')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertTemplateUsed(response, 'purpleleaf_app/vulnerabilities.html')

# # 	''' Analytics page test '''
# # 	def analytics_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/analytics/", follow=True)
# # 		if len(response.redirect_chain) == 0:
# # 			self.assertEquals(len(response.redirect_chain), 0)
# # 		else:
# # 			self.assertEquals(response.redirect_chain[0][0], '/error-404')
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Reports page test '''
# # 	def report_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/reports/", follow=True)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Vulnerability affected hosts page test '''
# # 	def vulnerability_affected_hosts_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/vulnerabilities/{}/".format("11"), follow=True)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Analytics data test '''
# # 	def analytics_data_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/api/analytics/", follow=True, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Vulnerability affected host page(individual vulnerability page) '''
# # 	def vulnerability_affected_host_detail_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/vulnerabilities/{0}/{1}".format("11","4056"), follow=True)
# # 		self.assertEqual(response.templates[0].name,'purpleleaf_app/affected-host-detail.html')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertTemplateUsed(response, 'purpleleaf_app/affected-host-detail.html')

# # 	''' Affected host retest test '''
# # 	def affected_host_retest_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/vulnerabilitiesretest/{0}/{1}".format("11","4056"), follow=True)
# # 		self.assertNotEquals(len(response.redirect_chain), 0)
# # 		self.assertEquals(response.redirect_chain[0][0], '/vulnerabilities/{}/'.format("11"))
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Show historical data test '''
# # 	def show_historical_data_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/api/charts/dashboard_history/", follow=True, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Ip related vulnerability count test '''
# # 	def ip_vul_count_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/hosts/ip-vul-count/", {"host_id":"407"}, follow=True, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Add New Network Test case with valid data '''
# # 	def add_network_success_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/addnetwork", {"network": "Home"}, HTTP_X_REQUESTED_WITH='XMLHttpRequest', follow=True)
# # 		response_content = response.json()['data']
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(response_content, "network_created")

# # 	''' Add New Network Test case with invalid data '''
# # 	def add_network_failure_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/addnetwork", {"network": "Default Network"}, HTTP_X_REQUESTED_WITH='XMLHttpRequest', follow=True)
# # 		response_content = response.json()['data']
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(response_content, "network_already_exists")

# # 	''' History page test '''
# # 	def history_page_test(self):
# # 		self.login_test()
# # 		response = self.client.get("/history", follow=True)
# # 		self.assertEqual(response.templates[0].name,'purpleleaf_app/closed-vulnerabilities.html')
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertTemplateUsed(response, 'purpleleaf_app/closed-vulnerabilities.html')

# # 	''' Notification test '''
# # 	def notifications_test(self):
# # 		self.login_test()
# # 		response = self.client.get('/notifications', follow=True)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)      

# # 	''' Add application url test with valid data '''
# # 	def addapplicationurl_success_test(self):
# # 		self.login_test()
# # 		response = self.client.post('/addapplicationurl', {"application_url_name": "www.google.co.in"}, HTTP_X_REQUESTED_WITH='XMLHttpRequest', follow=True)
# # 		response_content = response.json()['data']
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(response_content, "url_created")

# # 	''' Add application url test with invalid data '''
# # 	def addapplicationurl_failure_test(self):
# # 		self.login_test()
# # 		response = self.client.post('/addapplicationurl', {"application_url_name": "https://google.com"}, HTTP_X_REQUESTED_WITH='XMLHttpRequest', follow=True)
# # 		response_content = response.json()['data']
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)
# # 		self.assertEquals(response_content, "url_already_exists")

# # 	''' Delete host test '''
# # 	# def delete_host_test(self):
# # 	# 	self.login_test()
# # 	# 	response = self.client.post("/hosts/delete/", {"host_id":"393"}, follow=True, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
# # 	# 	self.assertEquals(len(response.redirect_chain), 0)
# # 	# 	self.assertEquals(response.status_code, 404)

# # 	''' Show risk historical data test '''
# # 	def show_risk_historical_data_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/api/charts/dashboard_history/", follow=True)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Report file test '''
# # 	def report_file_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/show-report/{}/".format("1"), {'content_type':'application/pdf'}, follow=True)
# # 		self.assertEquals(response['Content-Type'],"application/pdf")
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)

# # 	''' Delete report test '''
# # 	def report_file_test(self):
# # 		self.login_test()
# # 		response = self.client.post("/delete-report", {'report_id': '1'}, follow=True)
# # 		self.assertEquals(len(response.redirect_chain), 0)
# # 		self.assertNotEquals(response.status_code, 404)