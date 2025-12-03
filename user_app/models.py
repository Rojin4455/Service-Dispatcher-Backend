from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.utils import timezone
from datetime import timedelta

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


class UserProfile(models.Model):
    """Extended user profile with additional information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone = models.CharField(
        max_length=20,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
            )
        ],
        help_text="Phone number in international format"
    )
    service_areas = models.ManyToManyField(
        ServiceArea,
        related_name='users',
        blank=True,
        help_text="Service areas the user operates in"
    )
    service_industries = models.ManyToManyField(
        ServiceIndustry,
        related_name='users',
        blank=True,
        help_text="Service industries the user operates in"
    )
    ghl_contact_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="GoHighLevel contact ID"
    )
    pincodes = models.JSONField(
        default=list,
        blank=True,
        help_text="List of pincodes"
    )
    wallet_balance = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        help_text="Wallet balance"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} - {self.phone}"


class PasswordResetOTP(models.Model):
    """Model to store OTP for password reset"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_otps')
    email = models.EmailField(help_text="Email address for password reset")
    otp = models.CharField(max_length=6, help_text="6-digit OTP code")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="OTP expiration time")
    is_used = models.BooleanField(default=False, help_text="Whether OTP has been used")
    
    class Meta:
        verbose_name = "Password Reset OTP"
        verbose_name_plural = "Password Reset OTPs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'otp', 'is_used']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"OTP for {self.email} - {'Used' if self.is_used else 'Active'}"
    
    def is_expired(self):
        """Check if OTP has expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired()
    
    @classmethod
    def generate_otp(cls):
        """Generate a 6-digit OTP"""
        import random
        return str(random.randint(100000, 999999))
    
    @classmethod
    def create_otp(cls, user, email):
        """Create a new OTP for password reset"""
        # Invalidate any existing unused OTPs for this email
        cls.objects.filter(email=email, is_used=False).update(is_used=True)
        
        # Create new OTP
        otp_code = cls.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=10)  # OTP expires in 10 minutes
        
        return cls.objects.create(
            user=user,
            email=email,
            otp=otp_code,
            expires_at=expires_at
        )
