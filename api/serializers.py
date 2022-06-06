from rest_framework import serializers
from .models import UserDetails


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ('name', 'email', 'zip_code', 'floor_number')
        model = UserDetails
