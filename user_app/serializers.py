
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .models import ServiceArea, ServiceIndustry

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser']
        read_only_fields = ['id']


class LoginSerializer(serializers.Serializer):
    """Login serializer for admin authentication"""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_superuser:
                    raise serializers.ValidationError("Only admins can access this interface.")
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                data['user'] = user
            else:
                raise serializers.ValidationError("Invalid credentials.")
        else:
            raise serializers.ValidationError("Must include username and password.")
        
        return data


class ServiceAreaSerializer(serializers.ModelSerializer):
    """Serializer for ServiceArea model"""
    class Meta:
        model = ServiceArea
        fields = ['id', 'name', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ServiceIndustrySerializer(serializers.ModelSerializer):
    """Serializer for ServiceIndustry model"""
    class Meta:
        model = ServiceIndustry
        fields = ['id', 'name', 'price', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']