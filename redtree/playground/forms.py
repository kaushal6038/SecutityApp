from django import forms


class NessusCronForm(forms.Form):
    nes_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class MassScanCronForm(forms.Form):
    masscan_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class SslyzeCronForm(forms.Form):
    sslyze_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class SshyzeCronForm(forms.Form):
    sshyze_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class BurpCronForm(forms.Form):
    burp_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class DnsCronForm(forms.Form):
    dnsenum_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class ScreenshotCronForm(forms.Form):
    screenshot_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class CloudStorageCronForm(forms.Form):
    cloudstorage_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class WhoisCronForm(forms.Form):
    whois_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class RDSCronForm(forms.Form):
    rds_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))


class AssetRefreshCronForm(forms.Form):
    asset_refresh_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))

class ApiGatewayCronForm(forms.Form):
    apigateway_job = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
