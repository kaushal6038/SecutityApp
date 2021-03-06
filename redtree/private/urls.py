from django.conf.urls import url
from . import views
from .views import (
    RetestVulnerabilityApiView, ScanStatusApiView, CloudAssetsApiView,
    DeleteHostsApi, HostNetworkUpdateApi, NetworkCreateListAPiView,
    NetworkDetailAPiView, AwsAssetsCreateListView, ApplicationsCreateListAPiView,
    DomainListAPIView, SshEncryptionApi, SshEncryptionDetailApi,
    VulnerabilityListApiView, VulnerabilityDetailListApi, GetDashboardHistoricalData,
    VulnerabilityDetailAPIView, NetworkVulnerabilitiesAPIView, EncryptionApi,
    EncryptionProtocolDetailApi, EncryptionCipherApi, ReportsApi,
    RegistraionMail, ReportDetailApiView, CloudAssetsDetailApiView,
    UpdateCountListApi, HostCreateListAPiView, SubHostInfoListApi,
    ApplicationsDetailApiView, DashBoardAPIView, DomainDetailAPIView,
    PurpleleafHistoryAPIView, HostVulnerabilityDetailAPIView, AWSKeyStatusAPIView,
    LogPurpleleafUserActivityCreateAPIView, ApplicationVulnerabilityAPIView, 
    ApplicationVulnerabilityDetailAPIView, HostVulnerabilitiesAPIView,
    HostVulnerabilitiesDetailAPIView, CloudStorageDetailAPIView,
    CloudAssetDetailAPIView, UpdateApplicationScanStatusApiView,
    ApplicationsListAPiView,HostDetailAPiView,HostsWhoisMapView,
    VulnerabilityNetworkDetailAPIView, EncryptionChartsApiView,
    EncyptionCiphersApi,EncryptionCertificateApi
)

urlpatterns = [
    url(
        r'^api/retest/(?P<vul_id>[0-9]+)$',
        RetestVulnerabilityApiView.as_view(),
        name='retest_vulnerability_api'
    ),
    url(
        r'^registraion_mail/$',
        RegistraionMail.as_view(),
        name='retest_vulnerability_api'
    ),
    url(
        r'^api/toggle_activity$',
        ScanStatusApiView.as_view(),
        name='scanstatus'
    ),
    url(
        r'^applications$',
        ApplicationsListAPiView.as_view(),
        name='application-list'
    ),
    url(
        r'^application/$',
        ApplicationsCreateListAPiView.as_view(),
        name='application-create-list'
    ),
    url(
        r'^application/(?P<application_id>[0-9]+)/toggle_active$',
        UpdateApplicationScanStatusApiView.as_view(),
        name='update_application_scan_status'
    ),
    url(
        r'^application/(?P<id>[0-9]+)/$',
        ApplicationsDetailApiView.as_view(),
        name='application_detail'
    ),
    url(
        r'^host$',
        HostCreateListAPiView.as_view(),
        name='host-create-list'
    ),
    url(
        r'^host/(?P<id>[0-9]+)$',
        HostDetailAPiView.as_view(),
        name='host-detail'
    ),
    url(
        r'^host/whois$',
        HostsWhoisMapView.as_view(),
        name='host_create_Map'
    ),
    url(
        r'^network$',
        NetworkCreateListAPiView.as_view(),
        name='network-create-list'
    ),
    url(
        r'^network/(?P<network_id>[0-9]+)$',
        NetworkDetailAPiView.as_view(),
        name='network-detail'
    ),
    url(
        r'^delete-host$',
        DeleteHostsApi.as_view(),
        name='delete_host_api'
    ),
    url(
        r'^update-host-network/(?P<host_id>[0-9]+)$',
        HostNetworkUpdateApi.as_view(),
        name='update_host_api'
    ),
    url(
        r'^cloud-assets$',
        CloudAssetsApiView.as_view(),
        name='cloud_asset'
    ),
    url(
        r'^cloud-assets/(?P<asset_id>[0-9]+)$',
        CloudAssetsDetailApiView.as_view(),
        name='cloud_assets_detail'
    ),
    url(
        r'^aws-assets$',
        AwsAssetsCreateListView.as_view(),
        name='aws_assets_create_list'
    ),
    url(
        r'^domain$',
        DomainListAPIView.as_view(),
        name='domain-create-list'
    ),
    url(
        r'^ssh-encryption$',
        SshEncryptionApi.as_view(),
        name='ssh_encryption'
    ),
    url(
        r'^ssh-encryption/(?P<type>[0-9A-Za-z-_]+)/(?P<cipher>[0-9A-Za-z-.@]+)$',
        SshEncryptionDetailApi.as_view(),
        name='ssh-encryption-detail'
    ),
    url(
        r'^api/charts/dashboard_history/$',
        GetDashboardHistoricalData.as_view(),
        name='get_dashboard_historical_data'
    ),
    url(
        r'^api/charts/encryption$',
        EncryptionChartsApiView.as_view(),
        name='get_encryption_chart_data'
    ),
    url(
        r'^vulnerabilities$', 
        VulnerabilityListApiView.as_view(), 
        name='vulnerabilities-list'
    ),
    url(
        r'^vulnerabilities/external/(?P<virtue_id>\w+)$',
        VulnerabilityDetailListApi.as_view(),
        name='external-vulnerability-list-detail'
    ),
    url(
        r'^vulnerabilities/internal/(?P<virtue_id>\w+)/$',
        VulnerabilityDetailListApi.as_view(),
        name='internal-vulnerability-list-detail'
    ),
    url(
        r'^vulnerabilities/host/(?P<host_id>[0-9]+)$',
        HostVulnerabilitiesAPIView.as_view(),
        name='vulnerability_host'
    ),
    url(
        r'^vulnerabilities/host/(?P<host_id>[0-9]+)/(?P<virtue_id>[0-9]+)$',
        HostVulnerabilitiesDetailAPIView.as_view(),
        name='vulnerabilities_host_detail'
    ),
    url(
        r'^vulnerabilities/(?P<virtue_id>[0-9]+)/(?P<vul_id>\w+)$', 
        VulnerabilityDetailAPIView.as_view(),
        name='vulnerability_detail'
    ),
    url(
        r'^host/vulnerability/(?P<vul_id>\w+)$', 
        HostVulnerabilityDetailAPIView.as_view(),
        name='vulnerability_detail'
    ),
    url(
        r'^vulnerabilities/network/(?P<network_id>[0-9]+)$',
        NetworkVulnerabilitiesAPIView.as_view(),
        name='vulnerability_network'
    ),
    url(
        r'^vulnerabilities/network/(?P<network_id>[0-9]+)/(?P<virtue_id>\w+)/$',
        VulnerabilityNetworkDetailAPIView.as_view(),
        name='vulnerability_network_detail'
    ),
    url(
        r'^encryption/$',
        EncryptionApi.as_view(),
        name='encryption'
    ),
    url(
        r'^encryption/ciphers/$',
        EncyptionCiphersApi.as_view(),
        name='encryption_ciphers'
    ),
    url(
        r'^encryption/certificates/$',
        EncryptionCertificateApi.as_view(),
        name='encryption_certificates'
    ),
    url(
        r'^encryption/proto/(?P<protocol>\w+)/$',
        EncryptionProtocolDetailApi.as_view(),
        name='encryption_protocol_detail'
    ),
    url(
        r'^encryption/(?P<cipher>[0-9A-Za-z-_.@]+)$',
        EncryptionCipherApi.as_view(),
        name='encryption_cipher'
    ),
    url(
        r'^reports$',
        ReportsApi.as_view(),
        name='reports'
    ),
    url(
        r'^report/(?P<id>[0-9]+)$',
        ReportDetailApiView.as_view(),
        name='report-detail'
    ),
    url(
        r'^update-count$',
        UpdateCountListApi.as_view(),
        name='update_count'
    ),
    url(
        r'^subhost-info/(?P<host_id>[0-9]+)$',
        SubHostInfoListApi.as_view(),
        name='sub_host_info'
    ),
    url(
        r'^dashboard$',
        DashBoardAPIView.as_view(),
        name='dashboard_detail'
    ),
    url(
        r'^domains/(?P<domain_id>[0-9]+)$',
        DomainDetailAPIView.as_view(),
        name='domains-detail'
    ),
    url(
        r'^history$',
        PurpleleafHistoryAPIView.as_view(),
        name='pl-history'
    ),
    url(
        r'^aws/aws-key-status/(?P<id>[0-9]+)$', 
        AWSKeyStatusAPIView.as_view(),
        name='aws_key_status'
    ),
    url(
        r'^purpleleaf-activity/$',
        LogPurpleleafUserActivityCreateAPIView.as_view(),
        name='purpleleaf-activity'
    ),
    url(
        r'^applications/(?P<id>[0-9]+)$',
        ApplicationVulnerabilityAPIView.as_view(),
        name='application_vulnerability'
    ),
    url(
        r'^application/(?P<id>\w+)/vulnerabilities/(?P<virtue_id>\w+)$',
        ApplicationVulnerabilityDetailAPIView.as_view(),
        name='application_vulnerability_details'
    ),
    url(
        r'^cloud$',
        CloudStorageDetailAPIView.as_view(),
        name='cloud_storage_detail' 
    ),
    url(
        r'^cloud/s3/(?P<cloud_asset_id>[0-9]+)$',
        CloudAssetDetailAPIView.as_view(),
        name="cloud_asset_detail"
    ),
]