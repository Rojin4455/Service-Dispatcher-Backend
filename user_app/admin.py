from django.contrib import admin
from .models import ServiceArea, ServiceIndustry

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
