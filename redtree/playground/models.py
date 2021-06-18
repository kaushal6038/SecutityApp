# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# djnago imports
from django.db import models

# in house apps import
from redtree_app.models import Applications
from utils.base_models import BaseModel

# Create your models here.


class ApplicationScans(BaseModel):
	application = models.ForeignKey(
		Applications,
		null=True,
		blank=True,
		on_delete=models.CASCADE
		)
	scan_id = models.TextField(null=True, blank=True)
	status_uri = models.TextField(null=True, blank=True)
	scan_status = models.BooleanField(default=False)

	class Meta:
		verbose_name_plural = 'Application Scans'
		ordering = ['-id']

	def __str__(self):
		return self.scan_id


class ApplicationScanData(BaseModel):
	application = models.ForeignKey(
		ApplicationScans,
		null=True,
		blank=True,
		on_delete=models.SET_NULL
		)
	application_fk = models.ForeignKey(
		Applications,
		null=True,
		blank=True,
		on_delete=models.CASCADE,
		related_name="application_scans"
	)
	origin = models.TextField(null=True, blank=True)
	confidence = models.TextField(null=True, blank=True)
	name = models.TextField(null=True, blank=True)
	description = models.TextField(null=True, blank=True)
	evidence = models.TextField(null=True, blank=True)
	caption = models.TextField(null=True, blank=True)
	type_index = models.TextField(null=True, blank=True)
	internal_data = models.TextField(null=True, blank=True)
	path = models.TextField(null=True, blank=True)
	serial_number = models.TextField(null=True, blank=True)
	severity = models.CharField(max_length=32, null=True, blank=True)
	virtue_id = models.IntegerField(null=True, blank=True)
	confirmed = models.BooleanField(default=False)
	date_confirmed = models.DateField(null=True, blank=True)

	class Meta:
		verbose_name_plural = "Application Scan Result"
		ordering = ['-id']

	def __str__(self):
		return self.name

	@property
	def evidences(self):
		return self.issue_evidence.all()
	


class BurpEvidence(BaseModel):
	issue = models.ForeignKey(
		ApplicationScanData,
		null=True,
		blank=True,
		on_delete=models.CASCADE,
		related_name="issue_evidence"
		)
	url = models.TextField(null=True, blank=True)
	request = models.TextField(null=True, blank=True)
	response = models.TextField(null=True, blank=True)

	class Meta:
		verbose_name_plural = "Burp Evidence"
		ordering = ['-id']

	def __str__(self):
		return "{} - {}".format(self.issue, self.url)


class SshyzeType(BaseModel):
	name = models.CharField(max_length=500, null=True, blank=True)

	class Meta:
		verbose_name_plural = "Sshyze Type"
		ordering = ['-id']

	def __str__(self):
		return self.name


class SshyzeCiphers(BaseModel):
	cipher_type = models.ForeignKey(
		SshyzeType,
		null=True,
		blank=True,
		related_name="sshyze_ciphers",
		on_delete=models.CASCADE
		)
	ciphers = models.CharField(max_length=500, null=True, blank=True)
	host = models.CharField(max_length=500, null=True, blank=True)
	port = models.CharField(max_length=500, null=True, blank=True)

	class Meta:
		verbose_name_plural = "Sshyze Ciphers"
		# ordering = ['-id']

	def __str__(self):
		return self.ciphers
