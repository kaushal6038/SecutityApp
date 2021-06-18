from rest_framework import serializers
from redtree_app.models import *


def get_risk_factor(risk):
    risk_status = dict()
    risk_status["Critical"] = 5
    risk_status["High"] = 4
    risk_status["Medium"] = 3
    risk_status["Low"] = 2
    risk_status["None"] = 1
    risk_status[None] = 0

    return risk_status[risk]


class NessusDataSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        formatted_response = {
            'instances': instance['instances'],
            'plugin_id': instance['plugin_id'],
            'name': instance['name'],
            'risk_factor': get_risk_factor(instance['risk']),
            'risk': instance['risk'],
            'virtue_id': instance['virtue_id']
        }
        return formatted_response


    class Meta:
        model = NessusData
        fields = [
            'plugin_id',
            'risk',
            'name',
        ]