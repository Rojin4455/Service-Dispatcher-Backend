from django.contrib import admin
from .models import ServiceArea, ServiceIndustry, UserProfile, Job, JobRejection

# Register your models here.


@admin.register(ServiceArea)
class ServiceAreaAdmin(admin.ModelAdmin):
    """Admin interface for ServiceArea model"""
    list_display = ['id', 'name', 'is_active', 'created_at', 'updated_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name']
    list_editable = ['is_active']
    ordering = ['name']


@admin.register(ServiceIndustry)
class ServiceIndustryAdmin(admin.ModelAdmin):
    """Admin interface for ServiceIndustry model"""
    list_display = ['id', 'name', 'price', 'is_active', 'created_at', 'updated_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name']
    list_editable = ['is_active', 'price']
    ordering = ['name']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model"""
    list_display = ['id', 'user', 'phone', 'get_service_areas', 'get_service_industries', 'created_at', 'updated_at']
    list_filter = ['created_at', 'service_areas', 'service_industries']
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name', 'phone']
    filter_horizontal = ['service_areas', 'service_industries']
    readonly_fields = ['created_at', 'updated_at']

    def get_service_areas(self, obj):
        """Display service areas as comma-separated list"""
        return ", ".join([area.name for area in obj.service_areas.all()])
    get_service_areas.short_description = 'Service Areas'

    def get_service_industries(self, obj):
        """Display service industries as comma-separated list"""
        return ", ".join([industry.name for industry in obj.service_industries.all()])
    get_service_industries.short_description = 'Service Industries'


@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    """Admin interface for Job model"""
    list_display = ['id', 'service_needed', 'service_area', 'status', 'price', 'assigned_to', 'postal_code', 'created_at']
    list_filter = ['status', 'assigned_to', 'service_area', 'created_at']
    search_fields = ['service_needed', 'service_area', 'postal_code', 'email', 'phone', 'full_name', 'assigned_to__username', 'assigned_to__email']
    list_editable = ['status']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'updated_at']
    fieldsets = (
        ('Job Information', {
            'fields': ('name', 'service_needed', 'service_area', 'status', 'price', 'service_industry', 'assigned_to')
        }),
        ('Contact Information', {
            'fields': ('contact_id', 'first_name', 'last_name', 'full_name', 'email', 'phone', 'company_name')
        }),
        ('Address Information', {
            'fields': ('address1', 'city', 'state', 'country', 'postal_code')
        }),
        ('Additional Information', {
            'fields': ('service_request_message', 'created_at', 'updated_at')
        }),
    )


@admin.register(JobRejection)
class JobRejectionAdmin(admin.ModelAdmin):
    """Admin interface for JobRejection model"""
    list_display = ['id', 'job', 'user', 'created_at']
    list_filter = ['created_at']
    search_fields = ['job__name', 'user__username', 'user__email']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
