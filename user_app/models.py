from django.db import models

# Create your models here.


class ServiceArea(models.Model):
    """Model for available service areas"""
    name = models.CharField(max_length=255, unique=True, help_text="Name of the service area")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Service Area"
        verbose_name_plural = "Service Areas"
        ordering = ['name']

    def __str__(self):
        return self.name


class ServiceIndustry(models.Model):
    """Model for available service industries"""
    name = models.CharField(max_length=255, unique=True, help_text="Name of the service industry")
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Price for this service industry")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Service Industry"
        verbose_name_plural = "Service Industries"
        ordering = ['name']

    def __str__(self):
        return f"{self.name} - ${self.price}"
