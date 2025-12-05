from django.db import models
from projects.models import Scan
import uuid

class Vulnerability(models.Model):
    """Model to store individual vulnerabilities found in a scan"""
    SEVERITY_CHOICES = [
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, related_name='vulnerabilities', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    evidence = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.severity}"

class ScanConfiguration(models.Model):
    """Model to store scan configuration templates"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    scan_types = models.JSONField(default=list)  # ['sqli', 'xss', 'cmdi', etc.]
    auth_config = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
