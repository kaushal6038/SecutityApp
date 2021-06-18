# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import *
from markdownx.admin import MarkdownxModelAdmin


# Register your models here.


class NessusFileAdmin(admin.ModelAdmin):
    model = NessusFile
    readonly_fields = ('file_code',)


class NessusDataAdmin(admin.ModelAdmin):
    model = NessusData
    list_filter = ('linked_file',)


class RetestNoteAdmin(admin.ModelAdmin):
    model = RetestNote
    list_display = ('note', 'status', 'vulnerability_id', 'id')


class CiphersAdmin(admin.ModelAdmin):
    model = Ciphers
    list_display = ('host', 'port', 'protocol', 'cipher', 'key_size', 'strength')


admin.site.register(NessusFile, NessusFileAdmin)
admin.site.register(NessusData, NessusDataAdmin)
admin.site.register(Vulnerability, MarkdownxModelAdmin)
admin.site.register(RetestVulnerabilities)
admin.site.register(Notifications)
admin.site.register(Configuration)
admin.site.register(ClientConfiguration)
admin.site.register(Host)
admin.site.register(PurpleleafUsers)
admin.site.register(Applications)
admin.site.register(NotificationEmails)
admin.site.register(CloudAssetsData)
admin.site.register(Reports)
admin.site.register(NessusFileLog)
admin.site.register(RetestNote, RetestNoteAdmin)
admin.site.register(NessusFileRecord)
admin.site.register(Networks)
admin.site.register(RedtreeEventHistory)
admin.site.register(S3Uploads)
admin.site.register(TestVulnerabilities)
admin.site.register(Ciphers, CiphersAdmin)
admin.site.register(AppNotification)
admin.site.register(AwsRegion)
admin.site.register(ApplicationVulnerability)
admin.site.register(Appliances)
admin.site.register(Domains)
admin.site.register(ApplianceSettings)
admin.site.register(HistoricalData)
admin.site.register(RiskHistoricalData)
admin.site.register(ClientAwsAssets)
admin.site.register(EnumeratedSubdomains)
admin.site.register(PurpleleafEventHistory)
admin.site.register(ActivityLog)
admin.site.register(ClosedVulnerabilities)
admin.site.register(AwsDomains)
admin.site.register(LogMicroServiceDnsEnum)
admin.site.register(PurpleleafUserEventHistory)
admin.site.register(LogMicroServiceBurp)
admin.site.register(LogMicroServiceSslyze)
admin.site.register(LogMicroServiceMasscan)
admin.site.register(AwsApiGateway)
admin.site.register(LogMicroServiceCloudstorage)
admin.site.register(CloudstorageScanData)
admin.site.register(AwsRdsEndpoint)
admin.site.register(LogMicroServiceScreenshot)
admin.site.register(WhoisRecord)
admin.site.register(WhoisNetsRecord)
admin.site.register(WhoisNetsEmailsRecord)
admin.site.register(WhoisNetNoticesRecord)
admin.site.register(WhoisNetEventsRecord)
admin.site.register(WhoisNetLinksRecord)
admin.site.register(EventCountHistory)
admin.site.register(IpWhoisRecord)
admin.site.register(EmailRecord)
admin.site.register(WhoisBasicRecord)
admin.site.register(LogMicroServiceNessus)
admin.site.register(UserHosts)
admin.site.register(LogMicroServiceSshyze)
admin.site.register(RedtreeUserEventHistory)
admin.site.register(SslyzeCertificates)
admin.site.register(EncryptionCacheCiphers)
admin.site.register(EncryptionCacheSsh)
admin.site.register(ApplicationVulnerabilityChart)
admin.site.register(ArchiveVulnerabilities)