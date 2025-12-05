from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet, ScanViewSet

router = DefaultRouter()
router.register(r'projects', ProjectViewSet)
router.register(r'scans', ScanViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
