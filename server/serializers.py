from rest_framework import serializers
from django.contrib.auth.models import User

from server.models import Network

class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User
        fields = ['id', 'username', 'password', 'email']

class NetworkSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = Network
        # fields = ['id', 'ssid', 'bssid', 'security', 'mode']
        fields = ['ssid', 'bssid', 'security', 'mode']
