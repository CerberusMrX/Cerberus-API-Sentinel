from django.urls import path, include
from rest_framework.routers import SimpleRouter
from .views import VulnerabilityViewSet, ScanConfigurationViewSet

router = SimpleRouter()
router.register(r'vulnerabilities', VulnerabilityViewSet)
router.register(r'configurations', ScanConfigurationViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
