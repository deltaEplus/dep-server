from rest_framework import serializers
from .models import UserDetails


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ('name', 'email', 'zip_code', 'floor_number')
        model = UserDetails


class WeatherDetailSerializer(serializers.Serializer):
    latitude = serializers.CharField(max_length=100)
    longitude = serializers.CharField(max_length=100)
