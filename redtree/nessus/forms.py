from django import forms
from . models import *
import re
from lxml import etree
from markdownx.fields import MarkdownxFormField

class ApiForm(forms.ModelForm):

    class Meta:
        model = ApiList
        fields = ['api', 'kb_base_url', 'kb_auth_token']
        widgets = {
            'api': forms.TextInput(attrs={'class': 'form-control'}),
            'kb_base_url': forms.TextInput(attrs={'class': 'form-control'}),
            'kb_auth_token': forms.TextInput(attrs={'class': 'form-control'})
        }


class MasscanFileUploadForm(forms.Form):
    file = forms.FileField()

    def clean(self):
        cleaned_data = super(MasscanFileUploadForm, self).clean()
        masscan_file = cleaned_data.get("file").name
        if not re.search(".xml", masscan_file):
            raise forms.ValidationError("Only .xml files are supported.")


class AddKbArticleForm(forms.Form):
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
        ("",""),
        ("network","Network"),
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