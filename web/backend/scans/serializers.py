from rest_framework import serializers
from .models import Vulnerability, ScanConfiguration

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'scan', 'name', 'description', 'severity', 'evidence', 'created_at']
        read_only_fields = ['id', 'created_at']

class ScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanConfiguration
        fields = ['id', 'name', 'scan_types', 'auth_config', 'created_at']
        read_only_fields = ['id', 'created_at']
