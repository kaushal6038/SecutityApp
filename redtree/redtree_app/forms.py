from django import forms
from .models import *
from markdownx.fields import MarkdownxFormField
import re
from lxml import etree
from django.db.models import Q
from redtree_app.ip_validator import *
from django.conf import settings
from utils.helpers import find_markdown_images, change_media_path
from utils.MediaUploader import MediaUploader


class NessusFileUploadForm(forms.ModelForm):
    file = forms.FileField()

    class Meta:
        model = NessusFile
        fields = ['file']

    def clean(self):
        cleaned_data = super(NessusFileUploadForm, self).clean()
        nessus_file = cleaned_data.get("file")
        file_name = nessus_file.name
        if not re.search(".nessus", file_name):
            raise forms.ValidationError("Only .nessus files are supported.")
        file_path = "NessusFiles/" + file_name
        try:
            file_obj = NessusFile.objects.get(file=file_path)
        except Exception as e:
            file_obj = ''
        if file_obj:
            error_message = "This scan file was already uploaded on {0}".format(
                file_obj.uploaded_at.strftime("%d-%m-%y"))
            raise forms.ValidationError(error_message)


class VulnerabilityEditForm(forms.Form):
    risk_choices = [
        ("", ""),
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Note", "Note")
    ]
    title = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = MarkdownxFormField()
    risk = forms.ChoiceField(choices=risk_choices, widget=forms.Select(attrs={'class': 'form-control'}))
    port = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    remediation = MarkdownxFormField()
    evidence = MarkdownxFormField(required=False)


class VulnerabilityForm(forms.Form):
    risk_choices = [
        ("", ""),
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Note", "Note")
    ]
    title = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = MarkdownxFormField()
    risk = forms.ChoiceField(choices=risk_choices, widget=forms.Select(attrs={'class': 'form-control'}))
    port = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    remediation = MarkdownxFormField()
    evidence = MarkdownxFormField(required=False)
    host = forms.CharField(widget=forms.TextInput(
        attrs={
            'class': 'form-control',
            'name': 'host_array',
            'readonly': True,
            'id': 'host_array',
            'required': True
        })
    )

    def clean(self, *args, **kwargs):
        cleaned_data = super(VulnerabilityForm, self).clean()
        host_array = cleaned_data.get('host')
        host_not_exist_list = list()
        if host_array:
            host_list = host_array.split(',')
            for host in host_list:
                host_type = get_host_type(host)
                user_host = check_host_exists(host, host_type)
                if not user_host:
                    host_not_exist_list.append(host)
        else:
            raise forms.ValidationError(
                "Please enter hosts."
            )
        if host_not_exist_list:
            host_list = ", ".join(host_not_exist_list)
            if len(host_not_exist_list) == 1:
                exception_message = "host {} doesn't exists..".format(
                    host_list
                )
            elif len(host_not_exist_list) > 1:
                exception_message = "hosts {} doesn't exists..".format(
                    host_list
                )
            raise forms.ValidationError(
                exception_message
            )


class ApplicationVulnerabilityForm(forms.ModelForm):

    class Meta:
        model = ApplicationVulnerability
        fields = [
            'application',
            'risk',
            'title',
            'description',
            'remediation',
            'evidence',
            'virtue_id'
        ]

    def clean_virtue_id(self):
        if not self.cleaned_data['virtue_id']:
            if not ApplicationVulnerability.objects.all().exists():
                virtue_id = 50000
            else:
                last_vul = ApplicationVulnerability.objects.filter(virtue_id__gte=50000).last()
                if last_vul:
                    last_virtue_id = last_vul.virtue_id
                else:
                    last_virtue_id = 50000
                virtue_id = last_virtue_id + 1
            return virtue_id
        else:
            return self.cleaned_data['virtue_id']

    def upload_image(self, image):
        client_conf_obj = ClientConfiguration.objects.first()
        base_path = str(settings.BASE_DIR)
        image_path = base_path + str(image)
        image_file = File(open(image_path, 'rb'))
        if client_conf_obj and client_conf_obj.storage_type == "S3":
            image_key = ''.join(['screenshots/', os.path.basename(image_file.name)])
            if not S3Uploads.objects.filter(key=image_key).exists():
                media_uploader = MediaUploader(client_conf_obj, image_key, image_file)
                result = media_uploader.upload()
                if result == "success":
                    S3Uploads.objects.create(
                        key=image_key,
                        filename=os.path.basename(image_file.name)
                    )

    def clean_description(self):
        description_images = find_markdown_images(self.cleaned_data['description'])
        if description_images:
            client_conf_obj = ClientConfiguration.objects.first()
            base_path = str(settings.BASE_DIR)
            for image in description_images:
                self.upload_image(image)
        return change_media_path(self.cleaned_data['description'])

    def clean_remediation(self):
        remediation_images = find_markdown_images(self.cleaned_data['remediation'])
        if remediation_images:
            for image in remediation_images:
                self.upload_image(image)
        return change_media_path(self.cleaned_data['remediation'])

    def clean_evidence(self):
        evidence_images = find_markdown_images(self.cleaned_data['evidence'])
        if evidence_images:
            client_conf_obj = ClientConfiguration.objects.first()
            base_path = str(settings.BASE_DIR)
            for image in evidence_images:
                self.upload_image(image)
        return change_media_path(self.cleaned_data['evidence'])


class ConfigurationSubmitField(forms.widgets.Textarea):
    def render(self, name, value, attrs=None):
        html = "<button type='submit' class='btn btn-success'>Save</button>"
        return html


class ClientConfigurationForm(forms.ModelForm):
    CHOICES = ((True, 'Enable',), (False, 'Disable'))
    application_status = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect(attrs={'class': 'status-ul'}))
    analytics_status = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect(attrs={'class': 'status-ul'}))
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ClientConfiguration
        fields = ['client_name', 'client_legal_name', 'mailgun_api_key', 'hostname', 'mailgun_base_url',
                  'authentication_token',
                  'twilio_account_sid', 'twilio_auth_key', 'twilio_account_number', 'application_status',
                  'analytics_status', 'session_timeout_length', 'manual_hours_purchased', 'manual_hours_remaining', 'max_ips']
        widgets = {
            'client_name': forms.TextInput(attrs={'class': 'form-control'}),
            'client_legal_name': forms.TextInput(attrs={'class': 'form-control'}),
            'mailgun_api_key': forms.TextInput(attrs={'class': 'form-control'}),
            'hostname': forms.TextInput(attrs={'class': 'form-control has-popover',
                                               'data-content': "Don't append '/' in the end",
                                               'data-placement': 'top', 'data-container': 'body'}),

            'mailgun_base_url': forms.TextInput(attrs={'class': 'form-control has-popover'}),

            'authentication_token': forms.TextInput(attrs={'class': 'form-control has-popover',
                                                           'data-content': "Redtree Authentication Key",
                                                           'data-placement': 'top', 'data-container': 'body'}),

            'twilio_account_sid': forms.TextInput(attrs={'class': 'form-control has-popover',
                                                         'data-content': "Twilio Account SID",
                                                         'data-placement': 'top', 'data-container': 'body'}),

            'twilio_auth_key': forms.TextInput(attrs={'class': 'form-control has-popover',
                                                      'data-content': "Twilio AUTH Key",
                                                      'data-placement': 'top', 'data-container': 'body'}),

            'twilio_account_number': forms.TextInput(attrs={'class': 'form-control has-popover',
                                                            'data-content': "Twilio Number",
                                                            'data-placement': 'top', 'data-container': 'body'}),
            'session_timeout_length': forms.NumberInput(attrs={'class': 'form-control'}),
            'manual_hours_purchased': forms.TextInput(attrs={'class': 'form-control'}),
            'manual_hours_remaining': forms.TextInput(attrs={'class': 'form-control'}),
            'max_ips': forms.TextInput(attrs={'class': 'form-control'})
        }


class MicroServiceScanFrequencyForm(forms.ModelForm):
    Freq_Choices = ((1, "1 Day"), (4, "4 Days"), (7, "7 Days"), (14, "14 Days"))
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)
    scan_frequency = forms.ChoiceField(choices=Freq_Choices, widget=forms.Select(attrs={'class': 'form-control'}))

    class Meta:
        model = ClientConfiguration
        fields = ['scan_frequency']


class MicroServiceConfigurationForm(forms.ModelForm):
    Freq_Choices = ((1, "1 Day"), (4, "4 Days"), (7, "7 Days"), (14, "14 Days"))
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['access_token', 'secret_access_token', 's3_bucket_scan_url']
        widgets = {
            'access_token': forms.TextInput(attrs={'class': 'form-control'}),
            'secret_access_token': forms.TextInput(attrs={'class': 'form-control'}),
            's3_bucket_scan_url': forms.TextInput(attrs={'class': 'form-control'}),
        }


class WebScreenShotForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['webscreenshot_app_url']
        widgets = {
            'webscreenshot_app_url': forms.TextInput(attrs={'class': 'form-control'})
        }

class CloudStorageForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['cloudstorage_url']
        widgets = {
            'cloudstorage_url': forms.TextInput(attrs={'class': 'form-control'})
        }


class NessusSettingsForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['nessus_url', 'nessus_username', 'nessus_password', 'nessus_driver_url', 'max_simul_hosts']

        widgets = {
            'nessus_url': forms.TextInput(attrs={'class': 'form-control'}),
            'nessus_username': forms.TextInput(attrs={'class': 'form-control'}),
            'nessus_password': forms.TextInput(attrs={'class': 'form-control'}),
            'nessus_driver_url': forms.TextInput(attrs={'class': 'form-control'}),
            'max_simul_hosts': forms.NumberInput(attrs={'class': 'form-control'})
        }


class SslyzeForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['microservice_scan_url', 'sslyze_max_simul_hosts']

        widgets = {
            'microservice_scan_url': forms.TextInput(attrs={'class': 'form-control'}),
            'sslyze_max_simul_hosts': forms.NumberInput(attrs={'class': 'form-control'})
        }


class SshyzeForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['sshyze_scan_url', 'sshyze_max_simul_hosts']

        widgets = {
            'sshyze_scan_url': forms.TextInput(attrs={'class': 'form-control'}),
            'sshyze_max_simul_hosts': forms.NumberInput(attrs={'class': 'form-control'})
        }


class BurpSettingsForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['burp_url']

        widgets = {
            'burp_url': forms.TextInput(attrs={'class': 'form-control'})
        }

class DnsEnumForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['dnsenum_url']

        widgets = {
            'dnsenum_url': forms.TextInput(attrs={'class': 'form-control'})
        }


class MasscanSettingsForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ApplianceSettings
        fields = ['masscan_ip_address', 'masscan_ports', 'masscan_maximum_hosts_per_scan']

        widgets = {
            'masscan_ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'masscan_ports': forms.TextInput(attrs={'class': 'form-control'}),
            'masscan_maximum_hosts_per_scan': forms.TextInput(attrs={'class': 'form-control'})
        }

class AwsSettingsForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)

    class Meta:
        model = ClientAwsAssets
        fields = ['client_aws_access_token', 'client_aws_secret_token']

        widgets = {
            'client_aws_access_token': forms.TextInput(attrs={'class': 'form-control'}),
            'client_aws_secret_token': forms.TextInput(attrs={'class': 'form-control'}),
        }


class AppConfigurationForm(forms.ModelForm):
    purpleleaf_auth_key = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control has-popover',
                                                                        'data-content': 'Please enter Purpleleaf data auth key',
                                                                        'data-placement': 'top',
                                                                        'data-container': 'body'}))

    class Meta:
        model = Configuration
        fields = ['purpleleaf_auth_key', ]


class MediaUploadTypeForm(forms.ModelForm):
    storage_types = (('local', "Default(local)"), ('S3', "S3"))
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)
    storage_type = forms.ChoiceField(choices=storage_types, 
        widget=forms.Select(attrs={'class': 'form-control storage'}))

    class Meta:
        model = ClientConfiguration
        fields = ['storage_type', 's3_access_token', 's3_secret_access_token', 's3_bucket_name', 'pre_signed_time_length']
        widgets = {
            's3_access_token': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Access Token'}),
            's3_secret_access_token': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Secret Access Token'}),
            's3_bucket_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Bucket Name'}),
            'pre_signed_time_length': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Pre Sigbed Time Length'})
        }



class UserForm(forms.ModelForm):
    user_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    user_email = forms.EmailField(widget=forms.TextInput(attrs={'class': 'form-control'}))

    class Meta:
        model = PurpleleafUsers
        fields = ['user_name', 'user_email']


class NotificationEmailListForm(forms.ModelForm):
    email = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))

    class Meta:
        model = NotificationEmails
        fields = ['email']


class RetestNoteForm(forms.ModelForm):
    class Meta:
        model = RetestNote
        fields = ['note']
        widgets = {
            'note': forms.Textarea(
                attrs={
                    'class': 'form-control retest_vul_note_class',
                    'id': 'retest-note-placeholder'
                }
            ),
        }


class QueueVulnerabilityEditForm(forms.ModelForm):
    risk_choices =[
        ("", ""),
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Note", "Note")
    ]
    title = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    description = MarkdownxFormField()
    risk = forms.ChoiceField(choices=risk_choices, widget=forms.Select(attrs={'class': 'form-control'}))
    port = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    remediation = MarkdownxFormField()
    evidence = MarkdownxFormField(required=False)

    class Meta:
        model = TestVulnerabilities
        fields= ['title','description','risk','port','remediation','evidence']


class TimezoneForm(forms.Form):
    timezones = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles']
    timezone = forms.ChoiceField(
        label=('Time Zone'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=[(timezone, timezone) for timezone in timezones]
    )


class AppliancesForm(forms.ModelForm):
    submit = forms.CharField(widget=ConfigurationSubmitField(), required=False)
    appliance_ip = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    port = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    network_type = (('External', "External"), ('Internal', "Internal"))
    network_type = forms.ChoiceField(choices=network_type, 
        widget=forms.Select(attrs={'class': 'form-control'}))

    class Meta:
        model = Appliances
        fields= ['appliance_ip','port','network_type']


class AddKbBurpArticleForm(forms.Form):
    risk_choices = [
        ("", "---------"),
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Note", "Note")
    ]
    triage_choices = [
        ("Manual", "Manual"),
        ("Auto", "Auto")
    ]
    article_choices = [
        ("application", "Application")
    ]
    description = MarkdownxFormField()
    remediation = MarkdownxFormField()
    title = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    slug = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}), required=False)
    triage = forms.ChoiceField(
        choices=triage_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    risk = forms.ChoiceField(
        choices=risk_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    article_type = forms.ChoiceField(
        choices=article_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )


class ApplicationCreationForm(forms.ModelForm):
    scope_choices = [
        ("black", "Black"),
        ("grey", "Gray"),
        ("white", "White")
    ]
    network_choices = [
        ("External", "External"),
        ("Internal", "Internal")
    ]
    host = forms.ModelChoiceField(
        queryset=UserHosts.objects.all(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}))
    host_link = forms.ModelChoiceField(
        queryset=Host.objects.all(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}))
    scope = forms.ChoiceField(
        choices=scope_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    network_type = forms.ChoiceField(
        choices=network_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    screenshot = MarkdownxFormField(required=False)
    screenshot_title = forms.BooleanField(label='Disable screenshot and title', required=False)
    class Meta:
        model = Applications
        fields = ['host','host_link','application_url', 'application_title',
                  'screenshot', 'scope', 'network_type', 'screenshot_title']
        widgets = {
            'application_url': forms.TextInput(attrs={'class': 'form-control'}),
            'application_title': forms.TextInput(attrs={'class': 'form-control'}),

            'screenshot_filename': forms.TextInput(attrs={'class': 'form-control'}),

            'screenshot_path': forms.TextInput(attrs={'class': 'form-control'})
        }


class ApplicationVulnerabilityEditForm(forms.ModelForm):
    risk_choices = [
        ("", ""),
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Note", "Note")
    ]
    risk = forms.ChoiceField(
        choices=risk_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    application = forms.ModelChoiceField(
        queryset=Applications.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}))
    description = MarkdownxFormField(required=False)
    remediation = MarkdownxFormField(required=False)
    evidence = MarkdownxFormField(required=False)

    class Meta:
        model = ApplicationVulnerability
        fields = [
            'application',
            'risk',
            'title',
            'description',
            'remediation',
            'evidence'
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'virtue_id': forms.TextInput(attrs={'class': 'form-control'})
        }
