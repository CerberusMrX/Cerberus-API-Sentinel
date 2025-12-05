from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Vulnerability, ScanConfiguration
from .serializers import VulnerabilitySerializer, ScanConfigurationSerializer

class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing vulnerabilities"""
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    serializer_class = VulnerabilitySerializer
    # permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Vulnerability.objects.all()

class ScanConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan configurations"""
    queryset = ScanConfiguration.objects.all()
    serializer_class = ScanConfigurationSerializer
    serializer_class = ScanConfigurationSerializer
    # permission_classes = [IsAuthenticated]
