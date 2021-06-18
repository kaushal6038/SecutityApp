# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from rest_framework.response import Response
from rest_framework import status
from purpleleaf_app.models import *
from account.models import *
from .serializers import (
    UserSeriallizer,ConfigurationSerializer,
    NotificationSerializer, UserDetailSeriallizer,
)
from rest_framework.exceptions import (
    NotFound,
)
from rest_framework.views import APIView
from datetime import datetime
from utils.permissions import is_valid_request

# Create your views here.

class UserApiView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSeriallizer

    def get_obj(self):
        data = self.request.data
        try:
            return User.objects.get(email=data['check_email'])
        except:
            res_data = {
                'status': False,
                'message': 'User does not exists'
            }
            raise NotFound(res_data)

    def post(self, request, format=None):
        is_valid_request(request)
        data = request.data.copy()
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response_data = {
                'status': True,
                'user': serializer.data,
                'message': "User created successfully."
            }
            return Response(
                response_data,
                status=status.HTTP_201_CREATED
            )
        else:
            response_data = {
                'status': False,
                'errors': serializer.errors,
                'message': 'Unable to create User.'
            }
            return Response(
                response_data,
                status=status.HTTP_400_BAD_REQUEST
            )

    def patch(self, request, *args, **kwargs):
        data = request.data.copy()
        if "check_email" not in data.keys():
            res_data = {
                'status': False,
                'message': "Please provide an email."
            }
            return Response(
                res_data,
                status=status.HTTP_400_BAD_REQUEST
            )
        obj = self.get_obj()
        serializer = self.serializer_class(
            instance=obj,
            data=data,
            partial=True
            )
        if serializer.is_valid():
            serializer.save()
            res_data = {
                'status': True,
                'data': serializer.data,
                'message': "User details updated successfully."
            }
            return Response(
                res_data,
                status=status.HTTP_200_OK
            )
        else:
            res_data = {
                'status': False,
                'errors': serializer.errors,
                'message': "Unable to update user details."
            }
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        is_valid_request(request)
        data = request.data.copy()
        if "check_email" not in data.keys():
            res_data = {
                'status': False,
                'message': "Please provide an email."
            }
            return Response(
                res_data,
                status=status.HTTP_400_BAD_REQUEST
            )
        obj = self.get_obj()
        obj.delete()
        res_data = {
            'status': True,
            'message': 'User deleted successfully.'
        }
        return Response(
            res_data,
            status=status.HTTP_200_OK
        )
        

class UserDetailAPIView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSeriallizer

    def get_obj(self):
        user_id = self.kwargs.get('id')
        try:
            return User.objects.get(id=user_id)
        except:
            res_data = {
                'status': False,
                'message': 'User does not exists'
            }
            raise NotFound(res_data)

    def delete(self, request, *args, **kwargs):
        is_valid_request(request)
        user_obj = self.get_obj()
        user_obj.delete()
        res_data = {
            'status': True,
            'message': 'User deleted successfully.'
        }
        return Response(
            res_data,
            status=status.HTTP_200_OK
        )

    def patch(self, request, *args, **kwargs):
        data = request.data.copy()
        obj = self.get_obj()
        serializer = self.serializer_class(
            instance=obj,
            data=data,
            partial=True
            )
        if serializer.is_valid():
            serializer.save()
            res_data = {
                'status': True,
                'data': serializer.data,
                'message': "User details updated successfully."
            }
            return Response(
                res_data,
                status=status.HTTP_200_OK
            )
        res_data = {
            'status': False,
            'errors': serializer.errors,
            'message': "Unable to update user details."
        }
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateConfigurationApiView(APIView):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer

    def post(self, request, *args, **kwargs):
        try:
            conf_obj = Configuration.objects.first()
            auth_key = self.request.META['HTTP_DATA_AUTH_KEY']
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if auth_key == conf_obj.redtree_auth_key:
            configuration_obj = Configuration.objects.first()
            serializer = self.serializer_class(instance=configuration_obj, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class EventHistoryApi(APIView):

    def get(self, request ,format=None):
        try:
            conf_obj = Configuration.objects.first()
            auth_key = self.request.META['HTTP_DATA_AUTH_KEY']
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if auth_key == conf_obj.redtree_auth_key:
            event_list = []
            event_objs = EventHistory.objects.all()
            for event_obj in event_objs:
                timestamp = event_obj.time_stamp
                time_stamp = datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M %p')
                event_dict = {'event_type': event_obj.event_type,
                              'timestamp': time_stamp,
                              'data': event_obj.data,
                              'username': event_obj.username,
                              'ip': event_obj.ip
                              }
                event_list.append(event_dict)
            return Response(event_list,status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class InitializeAuthKeysApi(APIView):
    serializer_class = UserDetailSeriallizer

    def post(self, request, format=None):
        conf_obj = Configuration.objects.first()
        private_conf_obj = PrivateConfiguration.objects.first()
        # if conf_obj and private_conf_obj and (conf_obj.auth_reset is False)\
        #     or (private_conf_obj.auth_reset is False):
        redtree_auth = request.data.get('redtree_auth')
        purpleleaf_auth = request.data.get('purpleleaf_auth')
        if redtree_auth and purpleleaf_auth:
            conf_obj.redtree_auth_key = redtree_auth
            conf_obj.auth_reset = True
            private_conf_obj.data_auth_key = purpleleaf_auth
            private_conf_obj.auth_reset = True
            conf_obj.save()
            private_conf_obj.save()
            users = User.objects.all()
            serializer = self.serializer_class(
                users,
                many=True
            )
            response_data = {
                'status': True,
                'users': serializer.data
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class ActivityLogApiView(APIView):

    def post(self, request, format=None):
        conf_obj = Configuration.objects.first()
        try:
            auth_key = self.request.META['HTTP_DATA_AUTH_KEY']
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if auth_key == conf_obj.redtree_auth_key:
            activity_text = request.data
            ActivityLog.objects.create(activity=activity_text)
            return Response(True, status=status.HTTP_200_OK)
        else:
            return Response(False, status=status.HTTP_400_BAD_REQUEST)


class NotificationAPIView(APIView):
    serializer_class = NotificationSerializer

    def post(self, request, *args, **kwargs):
        is_valid_request(request)
        data = request.data.copy()
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            response_data = {
                'status': True,
                'code': 2000,
                'message': "Notification created successfully.",
                'data': serializer.data
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        response_data = {
            'status': False,
            'code': 4000,
            'message': "Unable to create notification.",
            'data': serializer.errors
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
