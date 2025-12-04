from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminLoginView,
    AdminLogoutView,
    AdminTokenObtainPairView,
    AdminTokenRefreshView,
    ServiceAreaViewSet,
    ServiceIndustryViewSet,
    PublicServiceAreaListView,
    PublicServiceIndustryListView,
    UserSignupView,
    UserLoginView,
    UserProfileView,
    AdminUserListView,
    AdminUserDetailView,
    WalletRechargeWebhookView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    JobWebhookView,
    PendingJobsView,
    MyJobsView,
    AcceptJobView,
    RejectJobView,
    UpdateJobStatusView
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
    
    # Public endpoints for signup form
    path('public/service-areas/', PublicServiceAreaListView.as_view(), name='public-service-areas'),
    path('public/service-industries/', PublicServiceIndustryListView.as_view(), name='public-service-industries'),
    
    # User endpoints
    path('signup/', UserSignupView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    
    # Password reset endpoints
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # Webhook endpoints
    path('webhook/wallet-recharge/', WalletRechargeWebhookView.as_view(), name='wallet-recharge-webhook'),
    path('webhook/job/', JobWebhookView.as_view(), name='job-webhook'),
    
    # Job endpoints
    path('jobs/pending/', PendingJobsView.as_view(), name='pending-jobs'),
    path('jobs/my-jobs/', MyJobsView.as_view(), name='my-jobs'),
    path('jobs/accept/', AcceptJobView.as_view(), name='accept-job'),
    path('jobs/reject/', RejectJobView.as_view(), name='reject-job'),
    path('jobs/update-status/', UpdateJobStatusView.as_view(), name='update-job-status'),
    
    # Admin user management endpoints
    path('admin/users/', AdminUserListView.as_view(), name='admin-user-list'),
    path('admin/users/<int:user_id>/', AdminUserDetailView.as_view(), name='admin-user-detail'),
    
    # Service CRUD endpoints
    path('', include(router.urls)),
]

