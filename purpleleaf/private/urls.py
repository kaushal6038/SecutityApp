from django.conf.urls import url
from . import views
from .views import (
    UserApiView, UserDetailAPIView, UpdateConfigurationApiView,
    EventHistoryApi, InitializeAuthKeysApi, ActivityLogApiView,
    NotificationAPIView,
)


urlpatterns = [
    url(
        r'^user$',
        UserApiView.as_view(),
        name='create_user'
    ),
    url(
        r'^user/(?P<id>[0-9]+)$',
        UserDetailAPIView.as_view(),
        name='delete_user'
    ),
    url(
        r'^update-configuration',
        UpdateConfigurationApiView.as_view(),
        name='update_configuration'
    ),
    url(
        r'^event-history$',
        EventHistoryApi.as_view(),
        name='event_history'
    ),
    url(
        r'^initialize-auth-keys$',
        InitializeAuthKeysApi.as_view(),
        name='initialize_auth_keys'
    ),
    url(
        r'^activity-log/$',
        ActivityLogApiView.as_view(),
        name='activity-log'
    ),
    url(
        r'^notifications/$',
        NotificationAPIView.as_view(),
        name='notification-create'
    ),
]