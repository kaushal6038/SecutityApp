from django.conf.urls import url, include
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls import handler403, handler404, handler500
from django.views.static import serve
from purpleleaf_app.views import e_handler500
from purpleleaf_app import views as purpleleaf_app_views
import debug_toolbar


urlpatterns = [
    url(r'^', include('purpleleaf_app.urls', namespace='purpleleaf')),
    url(r'^', include('account.urls', namespace='account')),
    url('^', include('django.contrib.auth.urls')),
    url(r'^private/', include('private.urls', namespace='private')),
    url(r'^markdownx/', include('markdownx.urls')),
    url(r'^__debug__/', include(debug_toolbar.urls)),

    url(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT})
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

admin.site.site_header = 'Purpleleaf Administration'
handler403 = purpleleaf_app_views.error_403_view
handler404 = purpleleaf_app_views.error_404_view
handler500 = e_handler500
