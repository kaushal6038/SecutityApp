
# forms.py ------------------------------------------------------

class ApplicationVulEditForm(forms.ModelForm):
    risk_choices = [
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low")
    ]
    risk = forms.ChoiceField(
        choices=risk_choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    class Meta:
        model = ApplicationVulnerability
        fields = ['risk','title','banner','description','remediation','evidence']

        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'banner': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.TextInput(attrs={'class': 'form-control'}),
            'remediation' : forms.TextInput(attrs={'class': 'form-control'}),
            'evidence' : forms.TextInput(attrs={'class': 'form-control'})
        }

# urls.py---------------------------------------------------------------------------------------

url(
    r'^application/edit-vul/(?P<id>[0-9]+)/$',
    ApplicationVulEditView.as_view(),
    name='application_edit_vul'
),



# views.py (add the function)----------------------------------------------------------------------------


@method_decorator(login_required, name='dispatch')
class ApplicationVulEditView(View):
    '''
    To update the title of Applications
    '''
    form = ApplicationVulEditForm
    def get(self, request, id):
        try:
            vul_obj = ApplicationVulnerability.objects.get(id=id)
        except ApplicationVulnerability.DoesNotExist:
            vul_obj = None
        if vul_obj:
            form = self.form(instance=vul_obj)
        edit_form = render_to_string(
            'redtree_app/application-edit-form.html',
            {'form': form}
        )
        return HttpResponse(edit_form)

    def post(self, request, id):
        base_path = str(settings.BASE_DIR)
        try:
            vul_obj = ApplicationVulnerability.objects.get(id=id)
        except ApplicationVulnerability.DoesNotExist:
            vul_obj = None
        if vul_obj:
            form = self.form(request.POST)
            print True
            if form.is_valid():
                vul_obj.risk =  form.cleaned_data.get('risk')
                vul_obj.title =  form.cleaned_data.get('title')
                vul_obj.banner =  form.cleaned_data.get('banner')
                vul_obj.description =  form.cleaned_data.get('description')
                vul_obj.remediation =  form.cleaned_data.get('remediation')
                vul_obj.evidence =  form.cleaned_data.get('evidence')
                vul_obj.save()
                response = {
                    'status': True,
                    'status_code': 200,
                    'message': 'Application updated successfully.',
                }
        else:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Application not found.'
            }
        return JsonResponse(response, safe=False)



# views.py (line 3612 add id in values)----------------------
app_vul_obj = ApplicationVulnerability.objects.filter(
    application__id=app_id
).values('title', 'risk', 'virtue_id','id').annotate(instances=Count('title'))