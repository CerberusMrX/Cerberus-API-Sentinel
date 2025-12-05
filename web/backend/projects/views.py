from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import Project, Scan
from .serializers import ProjectSerializer, ProjectListSerializer, ScanSerializer
from .scan_executor import ScanExecutor
import logging

logger = logging.getLogger(__name__)

class ProjectViewSet(viewsets.ModelViewSet):
    """ViewSet for Project CRUD operations"""
    queryset = Project.objects.all()
    # permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ProjectListSerializer
        return ProjectSerializer
    
    def get_queryset(self):
        return Project.objects.all()
    
    def perform_create(self, serializer):
        # Allow creation without owner or set to None
        serializer.save(owner=None)
    
    @action(detail=True, methods=['get'])
    def scans(self, request, pk=None):
        """Get all scans for a project"""
        project = self.get_object()
        scans = project.scans.all()
        serializer = ScanSerializer(scans, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):
        """Start a new scan for the project"""
        project = self.get_object()
        
        # Create scan record
        scan = Scan.objects.create(
            project=project,
            status='PENDING',
            started_at=timezone.now()
        )
        
        logger.info(f"Scan {scan.id} created for project {project.name}")
        
        import threading
        import time
        
        def run_scan_in_background(scan_id):
            # Give frontend time to connect to WebSocket
            time.sleep(2)
            
            try:
                # Need to close old connections in new thread to avoid issues
                from django.db import connections
                connections.close_all()
                
                scan_obj = Scan.objects.get(id=scan_id)
                executor = ScanExecutor()
                success = executor.execute_scan(scan_obj)
                
                if success:
                    logger.info(f"Scan {scan_id} completed successfully")
                else:
                    logger.warning(f"Scan {scan_id} failed")
            except Exception as e:
                logger.error(f"Error executing scan {scan_id}: {e}")
                try:
                    # Re-fetch scan to ensure we have fresh object
                    scan_obj = Scan.objects.get(id=scan_id)
                    scan_obj.status = 'FAILED'
                    scan_obj.completed_at = timezone.now()
                    scan_obj.results = {'error': str(e)}
                    scan_obj.save()
                except:
                    pass
            finally:
                from django.db import connections
                connections.close_all()

        # Execute the scan in a background thread
        thread = threading.Thread(target=run_scan_in_background, args=(scan.id,))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Started background scan thread for scan {scan.id}")
        
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ScanViewSet(viewsets.ModelViewSet):
    """ViewSet for Scan operations including delete"""
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    # permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.all()
    
    def destroy(self, request, pk=None):
        """Delete a scan"""
        scan = self.get_object()
        logger.info(f"Deleting scan {scan.id}")
        scan.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['get'])
    def vulnerabilities(self, request, pk=None):
        """Get all vulnerabilities for a scan"""
        scan = self.get_object()
        from scans.serializers import VulnerabilitySerializer
        vulnerabilities = scan.vulnerabilities.all()
        serializer = VulnerabilitySerializer(vulnerabilities, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a running scan"""
        scan = self.get_object()
        
        if scan.status == 'RUNNING':
            scan.status = 'FAILED'
            scan.completed_at = timezone.now()
            scan.save()
            return Response({'message': 'Scan cancelled'})
        else:
            return Response(
                {'error': 'Scan is not running'},
                status=status.HTTP_400_BAD_REQUEST
            )
