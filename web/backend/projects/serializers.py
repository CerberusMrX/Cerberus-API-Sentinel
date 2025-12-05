from rest_framework import serializers
from .models import Project, Scan

class ScanSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = ['id', 'project', 'status', 'started_at', 'completed_at', 'results', 'vulnerability_count']
        read_only_fields = ['id', 'started_at', 'completed_at']
    
    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count() if hasattr(obj, 'vulnerabilities') else 0

class ProjectSerializer(serializers.ModelSerializer):
    scans = ScanSerializer(many=True, read_only=True)
    scan_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Project
        fields = ['id', 'name', 'target_url', 'description', 'created_at', 'owner', 'scans', 'scan_count']
        read_only_fields = ['id', 'created_at', 'owner']
    
    def get_scan_count(self, obj):
        return obj.scans.count()

class ProjectListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    scan_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Project
        fields = ['id', 'name', 'target_url', 'description', 'created_at', 'scan_count']
        read_only_fields = ['id', 'created_at']
    
    def get_scan_count(self, obj):
        return obj.scans.count()
