from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminLoginView,
    AdminLogoutView,
    AdminTokenObtainPairView,
    AdminTokenRefreshView,
    ServiceAreaViewSet,
    ServiceIndustryViewSet
)

# Create a router and register our viewsets
router = DefaultRouter()
router.register(r'service-areas', ServiceAreaViewSet, basename='servicearea')
router.register(r'service-industries', ServiceIndustryViewSet, basename='serviceindustry')

urlpatterns = [
    # Authentication endpoints
    path('admin/login/', AdminLoginView.as_view(), name='admin-login'),
    path('admin/logout/', AdminLogoutView.as_view(), name='admin-logout'),
    path('admin/token/', AdminTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('admin/token/refresh/', AdminTokenRefreshView.as_view(), name='token_refresh'),
    
    # Service CRUD endpoints
    path('', include(router.urls)),
]

