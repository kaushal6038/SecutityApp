from rest_framework.serializers import ModelSerializer
from rest_framework.validators import (
	UniqueTogetherValidator,
	UniqueValidator
)
from utils.helpers import (
	get_sorted_host_vulnerabilities,
	get_sorted_user_host_vulnerabilities,
	get_risk_factor
)
from django.db.models import Count, Sum
from redtree_app.models import *
from redtree_app.ip_validator import * 
from playground.models import *
from rest_framework import serializers
from utils.MediaUploader import MediaUploader
import os
import re


class ConfigurationsSerializer(ModelSerializer):
	class Meta:
		model = Configuration
		fields=['scanning_status',]


class CloudAssetSerializer(ModelSerializer):
	bucket_type = serializers.SerializerMethodField()

	class Meta:
		model = CloudAssetsData
		fields = [
			'id',
			'category',
			'bucket',
			'bucket_type'
		]

		validators = [
			UniqueTogetherValidator(
				queryset=CloudAssetsData.objects.all(),
				fields=('category', 'bucket')
			)
		]

	def get_bucket_type(self, obj):
		if obj.aws_link:
			return obj.aws_link.token_description
		return "Unmanaged"


class DomainSerializer(ModelSerializer):

	class Meta:
		model = Domains
		fields = [
			'id',
			'domain_name',
			'network_type',
		]

	def validate_domain_name(self, value):
		if not value:
			raise serializers.ValidationError("This field can't be null.")
		if Domains.objects.filter(
			domain_name__iexact=value
			).exists():
			raise serializers.ValidationError("Domain name already exists.")
		else:
			return value


class EnumeratedSubdomainsSerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(
		format="%m-%d-%Y",
		read_only=True
	)

	class Meta:
		model = EnumeratedSubdomains
		fields = [
			'id',
			'subdomain',
			'in_scope',
			'domain_host',
			'client_confirmed',
			'client_confirmed_date',
			'created'
		]


class DomainDetailSerializer(serializers.ModelSerializer):
	sub_domains = serializers.SerializerMethodField()

	class Meta:
		model = Domains
		fields = [
			'id',
			'domain_name',
			'network_type',
			'sub_domains'
		]

	def get_sub_domains(self, obj):
		subdomains = obj.subdomains.all()
		serializer = EnumeratedSubdomainsSerializer(
			subdomains,
			many=True
		)
		return serializer.data


class SshyzeCiphersSerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(
		format="%m-%d-%Y",
		read_only=True
		)
	modified = serializers.DateTimeField(
		format="%m-%d-%Y",
		read_only=True
		)
	class Meta:
		model = SshyzeCiphers
		fields = [
			'id',
			'ciphers',
			'host',
			'port',
			'created',
			'modified',
		]


class SshyeCipherTypesSerializer(serializers.ModelSerializer):
	ciphers_list = serializers.SerializerMethodField()

	class Meta:
		model = SshyzeType
		fields = [
			'id',
			'name',
			'ciphers_list',
		]

	def get_ciphers_list(self, obj):
		ciphers = obj.sshyze_ciphers.all()
		serializer = SshyzeCiphersSerializer(ciphers, many=True)
		return serializer.data


class GetHistoricalDataSerializer(serializers.ModelSerializer):

	class Meta:
		model = HistoricalData
		fields = [
			'id',
			'active_ips',
			'open_ports',
		]


class GetRiskHistoricalDataSerializer(serializers.ModelSerializer):
	Date = serializers.SerializerMethodField()
	Critical = serializers.SerializerMethodField()
	Medium = serializers.SerializerMethodField()
	High = serializers.SerializerMethodField()
	Low = serializers.SerializerMethodField()

	class Meta:
		model = RiskHistoricalData
		fields = [
			'id',
			'Critical',
			'Medium',
			'High',
			'Low',
			'Date',
		]

	def get_Critical(self, obj):
		if not obj.critical_risk:
			return 0
		else:
			return int(obj.critical_risk)

	def get_Medium(self, obj):
		if not obj.medium_risk:
			return 0
		else:
			return int(obj.medium_risk)

	def get_High(self, obj):
		if not obj.high_risk:
			return 0
		else:
			return int(obj.high_risk)

	def get_Low(self, obj):
		if not obj.low_risk:
			return 0
		else:
			return int(obj.low_risk)

	def get_Date(self, obj):
		return obj.created.strftime("%m-%d-%Y")


class GetAppVulnerabilityHistoricalDataSerializer(serializers.ModelSerializer):
	Date = serializers.SerializerMethodField()
	Critical = serializers.SerializerMethodField()
	Medium = serializers.SerializerMethodField()
	High = serializers.SerializerMethodField()
	Low = serializers.SerializerMethodField()

	class Meta:
		model = ApplicationVulnerabilityChart
		fields = [
			'id',
			'Critical',
			'Medium',
			'High',
			'Low',
			'Date',
		]

	def get_Critical(self, obj):
		if not obj.critical_risk:
			return 0
		else:
			return int(obj.critical_risk)

	def get_Medium(self, obj):
		if not obj.medium_risk:
			return 0
		else:
			return int(obj.medium_risk)

	def get_High(self, obj):
		if not obj.high_risk:
			return 0
		else:
			return int(obj.high_risk)

	def get_Low(self, obj):
		if not obj.low_risk:
			return 0
		else:
			return int(obj.low_risk)

	def get_Date(self, obj):
		return obj.created.strftime("%m-%d-%Y")


class NetworkSerializer(serializers.ModelSerializer):
	
	class Meta:
		model = Networks
		fields = [
			'id',
			'network',
			'network_type',
			'ip_count',
		]

	def validate(self, data):
		if self.instance:
			if self.instance.network != data['network']:
				network_objs = Networks.objects.exclude(id=self.instance.id).\
					values_list('network', flat=True)
				network_list = [network for network in network_objs]
				if data['network'] in network_list:
					raise serializers.ValidationError("Network already exists")
		else:
			if Networks.objects.filter(
				network=data['network']
				).exists():
				raise serializers.ValidationError("Network already exists")
		return data


class NetworkDetailSerializer(serializers.ModelSerializer):

	class Meta:
		model = Networks
		fields = [
			'id',
			'network',
			'network_type',
			'ip_count',
			'vulnerabilities'
		]


class NetworkVulnerabilitiesSerializer(serializers.ModelSerializer):
	sorted_vulnerabilities = serializers.SerializerMethodField()

	class Meta:
		model = Networks
		fields = [
			'id',
			'network',
			'network_type',
			'ip_count',
			'sorted_vulnerabilities'
		]

	def get_sorted_vulnerabilities(self, obj):
		hosts = obj.network_hosts.all()
		vulnerabilities_obj = Vulnerability.objects.\
			filter(host__user_host__in=hosts).values('virtue_id', 'risk', 'title') \
			.annotate(instances=Count('title'))
		for data in vulnerabilities_obj:
			data['risk_factor'] = get_risk_factor(data['risk'])
		return sorted(vulnerabilities_obj, key=lambda x: x['risk_factor'], reverse=True)


class UserHostsSerializer(serializers.ModelSerializer):
	network = NetworkSerializer()

	class Meta:
		model = UserHosts
		fields = [
			'id',
			'host',
			'host_type',
			'network',
			'count'
		]


class UserHostsDetailSerializer(serializers.ModelSerializer):
	network = NetworkSerializer()
	host_id = serializers.SerializerMethodField()

	class Meta:
		model = UserHosts
		fields = [
			'id',
			'host',
			'host_type',
			'network',
			'count',
			'host_id'
		]

	def get_host_id(self, obj):
		host_type = ['ip', 'host_name']
		if obj.host_type in host_type:
			return obj.user_host.first().id
		else:
			return None
			

class HostSerializer(serializers.ModelSerializer):
	user_host = UserHostsDetailSerializer()

	class Meta:
		model = Host
		fields = [
			'id',
			'host',
			'user_host',
		]


class HostDetailSerializer(serializers.ModelSerializer):
	user_host = UserHostsDetailSerializer()
	sorted_vulnerabilities = serializers.SerializerMethodField()

	class Meta:
		model = Host
		fields = [
			'id',
			'host',
			'user_host',
			'sorted_vulnerabilities',
		]

	def get_sorted_vulnerabilities(self, obj):
		virtue_ids = obj.host_vulnerability.values_list(
			'virtue_id', flat=True
		)
		vul_objs = get_sorted_host_vulnerabilities(
			virtue_ids=virtue_ids,
			host=obj,
		)
		return vul_objs


class VulnerabilityPartialDetailSerializer(serializers.ModelSerializer):
	host = HostSerializer()
	vul_evidence = serializers.SerializerMethodField()
	retest_status = serializers.SerializerMethodField()
	created = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")
	modified = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")

	class Meta:
		model = Vulnerability
		fields = [
			'id',
			'title',
			'virtue_id',
			'host_ip',
			'risk',
			'port',
			'banner',
			'retest',
			'created',
			'modified',
			'host',
			'vul_evidence',
			'retest_status',
		]

	def get_retest_status(self, obj):
		try:
			retest_obj = obj.retest
		except RetestVulnerabilities.DoesNotExist:
			retest_obj = RetestVulnerabilities.objects.create(
				vulnerability=obj
			)
		return retest_obj.status

	def get_vul_evidence(self, obj):
		if obj.evidence:
			markdown_evidence = get_markdown_with_images(
				obj.evidence
			)
			return markdownify(markdown_evidence)
		else:
			return None


class VulnerabilityDetailSerailizer(serializers.ModelSerializer):
	host = HostSerializer()
	retest_notes = serializers.SerializerMethodField()
	created = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")
	modified = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")

	class Meta:
		model = Vulnerability
		fields = [
			'id',
			'title',
			'formatted_description',
			'formatted_remediation',
			'formatted_evidence',
			'virtue_id',
			'port',
			'host_ip',
			'banner',
			'retest',
			'retest_notes',
			'host',
			'created',
			'modified',	
		]

	def get_retest_notes(self, obj):
		serializer = RetestNotesSerailizer(obj.retest_notes.all(), many=True)
		return serializer.data


class RetestNotesSerailizer(serializers.ModelSerializer):
	created = serializers.DateTimeField(format='%b %d %Y %I:%M%p')

	class Meta:
		model = RetestNote
		fields = [
			'note',
			'status',
			'created'
		]


class VulnerabilityNetworkSerializer(serializers.ModelSerializer):

	class Meta:
		model = Networks
		fields = [
			'id',
			'network',
			'network_type',
			'purpleleaf_id'
		]

class EncryptionSerializer(serializers.ModelSerializer):
	host_id = serializers.SerializerMethodField()
	modified = serializers.DateTimeField(
		format="%m-%d-%Y",
		read_only=True
		)

	class Meta:
		model = Ciphers
		fields = [
			'id',
			'host',
			'port',
			'protocol',
			'cipher',
			'key_size',
			'host_id',
			'modified'
		]

	def get_host_id(self, obj):
		try:
			return Host.objects.filter(host=obj['host']).first().id
		except:
			return None


class EncryptionHostSerializer(serializers.ModelSerializer):
	cipher_count = serializers.SerializerMethodField()
	host_id = serializers.SerializerMethodField()

	class Meta:
		model = Ciphers
		fields = [
			'id',
			'host',
			'port',
			'protocol',
			'host_id',
			'cipher_count'
		]

	def get_host_id(self, obj):
		try:
			host_obj = Host.objects.filter(host=obj['host']).first()
			if host_obj:
				return host_obj.id
				# user_host_id = host_obj.user_host.id
				# return UserHosts.objects.get(id=host_obj.user_host.id).id
			return None
		except:
			return None

	def get_cipher_count(self, obj):
		return obj.get('cipher_count')


class SslyzeCertificatesSerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(
		format="%d-%m-%Y",
		read_only=True
	)
	modified = serializers.DateTimeField(
		format="%d-%m-%Y",
		read_only=True
	)
	
	class Meta:
		model = SslyzeCertificates
		fields = [
			'id',
			'host',
			'port',
			'verified_certificate_chain',
			'sha1_in_chain',
			'subject',
			'algorithm',
			'created',
			'modified',
			'common_name'
		]


class EncryptionDetailSerializer(serializers.ModelSerializer):
	modified = serializers.DateTimeField(
		format="%m-%d-%Y",
		read_only=True
	)
	protocol = serializers.SerializerMethodField()
	host_id = serializers.SerializerMethodField()

	class Meta:
		model = Ciphers
		fields = [
			'host',
			'port',
			'modified',
			'protocol',
			'strength',
			'host_id'
		]

	def get_protocol(self, obj):
		proto = list(set(Ciphers.objects.filter(
			host=obj.host,
			port=obj.port
		).distinct('protocol').values_list('protocol', flat=True)))
		return sorted(proto)

	def get_host_id(self, obj):
		try:
			host_obj = Host.objects.filter(host=obj.host).first()
			if host_obj:
				return host_obj.id
			return None
		except:
			return None

class ReportsSerializer(serializers.ModelSerializer):
	filename = serializers.SerializerMethodField()
	created = serializers.DateTimeField(
		format="%B %d, %Y",
		read_only=True
		)

	class Meta:
		model = Reports
		fields = [
			'id',
			'filename',
			'created'
		]

	def get_filename(self, obj):
		filename = str(os.path.basename(obj.file.name))
		file = filename.replace("_", " ").replace("-", " - ")
		obj.file.name = filename.replace("_", " ").replace("-", " - ").replace("."," ")
		matchObj = re.match( r'(.*) Report (.*?) .*', obj.file.name, re.M|re.I)
		if matchObj:
			file_name = obj.file.name.replace((matchObj.group(2)),".").replace(" . ",".")
		else:
			file_name = file
		return file_name



class ReportDetailSerializer(serializers.ModelSerializer):
	file_key = serializers.SerializerMethodField()

	class Meta:
		model = Reports
		fields = [
			'id',
			'created',
			'file_key',
		]

	def get_file_key(self, obj):
		file_key = ''.join(['media/', str(obj.file)])
		client_conf_obj = ClientConfiguration.objects.first()
		media_uploader = MediaUploader(client_conf_obj, file_key)
		s3_link = media_uploader.get_link()
		return s3_link


class ClientAwsAssetsSerializer(serializers.ModelSerializer):
	client_aws_access_token = serializers.CharField(required=True)
	assets = serializers.SerializerMethodField()

	class Meta:
		model = ClientAwsAssets
		fields = [
			'id',
			'client_aws_access_token',
			'client_aws_secret_token',
			'scan_status',
			'scan_state',
			'token_description',
			'assets'
		]

	def  validate_client_aws_access_token(self, value):
		if ClientAwsAssets.objects.filter(
			client_aws_access_token__iexact=value
			).exists():
			raise serializers.ValidationError("AWS Token already exists.")
		return value

	def get_assets(self, obj):
		asset = ""
		if obj.ec2_count and obj.ec2_count != 0:
			asset = "EC2 ({})".format(obj.ec2_count)
		if obj.s3_count and obj.s3_count != 0:
			if asset:
				asset = "{}, S3 ({})".format(asset, obj.s3_count)
			else:
				asset = "S3 ({})".format(obj.s3_count)
		if obj.rds_count and obj.rds_count != 0:
			if asset:
				asset = "{}, RDS ({})".format(asset, obj.rds_count)
			else:
				asset = "RDS ({})".format(obj.rds_count)
		return asset

class ApplicationSerializer(serializers.ModelSerializer):
	application_url = serializers.CharField(required=True)
	network_type = serializers.CharField(required=True)

	class Meta:
		model = Applications
		fields = [
			'id',
			'application_url',
			'application_title',
			'network_type',
		]

	def  validate_application_url(self, value):
		if Applications.objects.filter(
			application_url__iexact=value
			).exists():
			raise serializers.ValidationError("Application already exists.")
		return value


class ApplicationScanStatusUpdateSerializer(serializers.ModelSerializer):

	class Meta:
		model = Applications
		fields = [
			'id',
			'scanning_enabled'
		]


class ApplicationDetailSerializer(serializers.ModelSerializer):
	modified = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	created = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	last_seen = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	last_scan = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)

	class Meta:
		model = Applications
		fields = [
			'id',
			'application_title',
			'application_url',
			's3_image',
			'scope',
			'network_type',
			'modified',
			'created',
			'last_scan',
			'last_seen',
			'scanning_enabled',
		]


class BurpDetailSerializer(serializers.ModelSerializer):
	burp_issues_count = serializers.SerializerMethodField()
	modified = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	created = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	last_seen = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)
	last_scan = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',
		read_only=True
	)

	class Meta:
		model = Applications
		fields = [
			'id',
			'application_title',
			'application_url',
			's3_image',
			'scope',
			'network_type',
			'modified',
			'created',
			'last_scan',
			'last_seen',
			'scanning_enabled',
			'burp_issues_count',
		]

	def get_burp_issues_count(self, obj):
		issue_by_count = ApplicationScanData.objects.filter(
			application_fk=obj.id,
			).values('severity').annotate(
			count=Count('severity')
		)
		issues = {
			'critical': 0,
			'info':0,
			'high': 0,
			'medium': 0,
			'low': 0,
		}
		for issue_count in issue_by_count:
			issues[issue_count['severity']]+=issue_count['count']  
		issues['Total'] = (sum(issues.values()))
		issues_ex_info = issues.copy()
		issues_ex_info.pop('info')
		issues['TotalExInfo'] = (sum(issues_ex_info.values()))
		return issues

class IpwhoisSerailizer(serializers.ModelSerializer):
	asn_description = serializers.SerializerMethodField()
	network_name = serializers.SerializerMethodField()

	class Meta:
		model = IpWhoisRecord
		fields = [
			'id',
			'asn_description',
			'network_name',
		]

	def get_asn_description(self, obj):
		return obj.whois_record.asn_description

	def get_network_name(self, obj):
		return obj.whois_record.network_name



class IpwhoisDetailSerailizer(serializers.ModelSerializer):

	class Meta:
		model = IpWhoisRecord
		fields = [
			'city',
			'longitude',
			'latitude',
		]


class UserHostDetailSerializer(serializers.ModelSerializer):
	user_host = UserHostsSerializer()
	whois_detail = serializers.SerializerMethodField()
	open_ports = serializers.SerializerMethodField()
	vulnerabilities = serializers.SerializerMethodField()
	applications = serializers.SerializerMethodField()

	class Meta:
		model = Host
		fields = [
			'id',
			'host',
			'user_host',
			'whois_detail',
			'open_ports',
			'vulnerabilities',
			'applications'
		]

	def get_whois_detail(self, obj):
		user_host = obj.user_host
		whois_obj = IpWhoisRecord.objects.filter(ip=user_host)
		whois_basic_record = IpwhoisSerailizer(whois_obj.first())
		whois_map_record = IpwhoisDetailSerailizer(whois_obj, many=True)
		context = {
			'basic_record': whois_basic_record.data,
			'map_data': whois_map_record.data
		}
		return context

	def get_open_ports(self, obj):
		vul_obj = obj.host_vulnerability.filter(
			title="Open TCP Port"
		).distinct('port')
		vulnerabilities = sorted(vul_obj,
			key=lambda x: int(x.port)
		)
		open_ports = VulnerabilityPartialDetailSerializer(
			vulnerabilities,
			many=True
		)
		return open_ports.data

	def get_vulnerabilities(self, obj):
		virtue_ids = obj.host_vulnerability.values_list(
			'virtue_id', flat=True
		)
		vul_objs = get_sorted_host_vulnerabilities(
			virtue_ids=virtue_ids,
			host=obj,
		)
		return vul_objs

	def get_applications(self, obj):
		user_host = obj.user_host
		applications = Applications.objects.filter(
            host=user_host,
            application_url__icontains=obj.host
        )
		application_serializer = ApplicationSerializer(
			applications,
			many=True
		)
		return application_serializer.data


class NessusDetailSerializer(serializers.ModelSerializer):
	linked_file_code = serializers.SerializerMethodField()

	class Meta:
		model = NessusData
		fields = [
			'id',
			'plugin_id',
			'risk',
			'linked_file_code',
			'host',
			'protocol',
			'port',
			'name',
			'svc_type',
			'first_identified',
			'last_seen',
			'confirmed',
			'date_confirmed',
			'description',
			'synopsis',
			'plugin_output',
			'virtue_id',
			'banner',
			'created',
			'modified',
			'host_link',
			'solution',
		]

	def get_linked_file_code(self, obj):
		file_code = obj.linked_file.file_code
		return file_code

class RedtreeEventHistorySerializer(serializers.ModelSerializer):

	class Meta:
		model = RedtreeEventHistory
		fields = [
			'event_type',
			'time_stamp',
			'username',
			'ip',
			'data'
		]


class ActivityLogSerializer(serializers.ModelSerializer):
	created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%p")

	class Meta:
		model = ActivityLog
		fields = [
			'activity',
			'created_at'
		]


class ClosedVulnerabilitiesSerializer(serializers.ModelSerializer):
	closed_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%p")

	class Meta:
		model = ClosedVulnerabilities
		fields = [
			'title',
			'host',
			'port',
			'risk',
			'retest_note',
			'closed_date'
		]


class LogPurpleleafUserActivitySerializer(serializers.ModelSerializer):

	class Meta:
		model = PurpleleafUserEventHistory
		fields = [
			'event_type',
			'time_stamp',
			'username',
			'ip'
		]


class LogRedtreeUserActivitySerializer(serializers.ModelSerializer):

	class Meta:
		model = RedtreeUserEventHistory
		fields = [
			'event_type',
			'time_stamp',
			'username',
			'ip'
		]


class ApplicationVulnerabilitySerializer(serializers.ModelSerializer):

	def to_representation(self, instance):
			formatted_response = {
				'id': instance.id,
				'title': instance.title,
				'virtue_id': instance.virtue_id,
				'risk': instance.risk,
				'instances': instance.instances,
				'network': instance.application.network_type

			}
			return formatted_response

	class Meta:
		model = ApplicationVulnerability
		fields = [
			'id',
			'virtue_id',
			'risk',
			'title'
		]


class ApplicationHostSerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',read_only=True)
	last_seen = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',read_only=True)
	last_scan = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',read_only=True)

	class Meta:
		model = Applications
		fields = [
			'id',
			'created',
			'last_seen',
			'last_scan',
			's3_image',
			'application_title'
		]

class ApplicationVulnerabilityDetailSerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',read_only=True)
	modified_date = serializers.DateTimeField(format='%b %d %Y, %I:%M%p',read_only=True)

	class Meta:
		model = ApplicationVulnerability
		fields = [
			'id',
			'title',
			'formatted_description',
			'formatted_remediation',
			'formatted_evidence',
			'virtue_id',
			'port',
			'modified_date',
			'plugin_id',
			'created'
		]


class CloudStorageSerializer(serializers.ModelSerializer):
	last_scan = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")
	unauthenticated_data_status = serializers.SerializerMethodField()
	authenticated_data_status = serializers.SerializerMethodField()

	class Meta:
		model = CloudAssetsData
		fields = [
			'id',
			'bucket',
			'last_scan',
			'unauthenticated_data_status',
			'authenticated_data_status',
		]

	def get_unauthenticated_data_status(self, obj):
		cloud_storage_obj = obj
		unauthenticated_data = CloudstorageScanData.objects.filter(
			cloud_asset_bucket=cloud_storage_obj,
			bucket_name__isnull=False
		).values_list('unauthenticated_status', flat=True)
		unauthenticated_data_list = [data for data in unauthenticated_data]
		if unauthenticated_data_list and (False in unauthenticated_data_list):
			unauthenticated_data_status = 'fail'
		elif unauthenticated_data_list and not (False in unauthenticated_data_list):
			unauthenticated_data_status = 'pass'
		else:
			unauthenticated_data_status = None
		return unauthenticated_data_status

	def get_authenticated_data_status(self, obj):
		cloud_storage_obj = obj
		authenticated_data = CloudstorageScanData.objects.filter(
			cloud_asset_bucket=cloud_storage_obj,
			bucket_name__isnull=False
		).values_list('authenticated_status', flat=True)
		authenticated_data_list = [data for data in authenticated_data]
		if authenticated_data_list and (False in authenticated_data_list):
			authenticated_data_status = 'fail'
		elif authenticated_data_list and not (False in authenticated_data_list):
			authenticated_data_status = 'pass'
		else:
			authenticated_data_status = None
		return authenticated_data_status


class AwsApiGatewaySerializer(serializers.ModelSerializer):
	created = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")
	last_scan = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")

	class Meta:
		model = AwsApiGateway
		fields = [
			'id',
			'api_url',
			'region',
			'status_code',
			'content',
			'created',
			'last_scan'
		]


class AwsRdsSerializer(serializers.ModelSerializer):
	last_scan = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")

	class Meta:
		model = AwsRdsEndpoint
		fields = [
			'id',
			'host',
			'port',
			'region',
			'last_scan',
			'scan_status'
		]


class AwsDomainSerializer(serializers.ModelSerializer):
	created_at = serializers.DateTimeField(format="%B %d, %Y, %H:%M %p")

	class Meta:
		model = AwsDomains
		fields = [
			'id',
			'domain',
			'created_at',
		]


class CloudStorageScanSerializer(serializers.ModelSerializer):
	bucket = serializers.SerializerMethodField()

	class Meta:
		model = CloudstorageScanData
		fields = [
			'id',
			'cloud_asset_bucket',
			'bucket_name',
			'unauthenticated_status',
			'authenticated_status',
			'file',
			'bucket'
		]

	def get_bucket(self, obj):
		return obj.cloud_asset_bucket.bucket


class HostApplicationSerializer(serializers.ModelSerializer):

	class Meta:
		model = Applications
		fields = [
			'id',
			'application_url'
		]

class ArchiveVulnerabilitiesSeralizer(serializers.ModelSerializer):

	class Meta:
		model = ArchiveVulnerabilities 
		fields = '__all__'