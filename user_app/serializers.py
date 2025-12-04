
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from decimal import Decimal
from .models import ServiceArea, ServiceIndustry, UserProfile, PasswordResetOTP, Job, JobRejection

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser']
        read_only_fields = ['id']


class LoginSerializer(serializers.Serializer):
    """Login serializer for admin authentication"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            # Try to find user by email
            try:
                from django.contrib.auth.models import User
                user = User.objects.get(email=email)
                # Authenticate using the username (which might be email) and password
                user = authenticate(username=user.username, password=password)
                if user:
                    if not user.is_superuser:
                        raise serializers.ValidationError("Only admins can access this interface.")
                    if not user.is_active:
                        raise serializers.ValidationError("User account is disabled.")
                    data['user'] = user
                else:
                    raise serializers.ValidationError("Invalid credentials.")
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        else:
            raise serializers.ValidationError("Must include email and password.")
        
        return data


class UserLoginSerializer(serializers.Serializer):
    """Login serializer for regular user authentication"""
    email = serializers.EmailField(help_text="User email address")
    password = serializers.CharField(write_only=True, help_text="User password")

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            # Try to authenticate using email as username
            user = authenticate(username=email, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                data['user'] = user
            else:
                raise serializers.ValidationError("Invalid email or password.")
        else:
            raise serializers.ValidationError("Must include email and password.")
        
        return data


class ServiceAreaSerializer(serializers.ModelSerializer):
    """Serializer for ServiceArea model"""
    class Meta:
        model = ServiceArea
        fields = ['id', 'name', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ServiceIndustrySerializer(serializers.ModelSerializer):
    """Serializer for ServiceIndustry model"""
    price = serializers.DecimalField(
        max_digits=10,
        decimal_places=2,
        required=False,
        default=Decimal('0.00'),
        help_text="Price for the service industry (defaults to 0 if not provided)"
    )
    
    class Meta:
        model = ServiceIndustry
        fields = ['id', 'name', 'price', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        """Create service industry with default price if not provided"""
        if 'price' not in validated_data or validated_data.get('price') is None:
            validated_data['price'] = Decimal('0.00')
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Update service industry, defaulting price to 0 if not provided"""
        if 'price' in validated_data and validated_data['price'] is None:
            validated_data['price'] = Decimal('0.00')
        return super().update(instance, validated_data)


class ServiceAreaItemSerializer(serializers.Serializer):
    """Serializer for individual service area item in bulk create"""
    name = serializers.CharField(required=True, help_text="Name of the service area")
    is_active = serializers.BooleanField(required=False, default=True, help_text="Whether the service area is active")


class ServiceIndustryItemSerializer(serializers.Serializer):
    """Serializer for individual service industry item in bulk create"""
    name = serializers.CharField(required=True, help_text="Name of the service industry")
    price = serializers.DecimalField(
        max_digits=10,
        decimal_places=2,
        required=False,
        default=Decimal('0.00'),
        help_text="Price for the service industry (defaults to 0 if not provided)"
    )
    is_active = serializers.BooleanField(required=False, default=True, help_text="Whether the service industry is active")


class BulkServiceAreaSerializer(serializers.Serializer):
    """Serializer for bulk creating service areas"""
    service_areas = ServiceAreaItemSerializer(many=True, min_length=1)
    
    def validate_service_areas(self, value):
        """Validate that each service area has required fields"""
        for item in value:
            if 'name' not in item or not item.get('name'):
                raise serializers.ValidationError("Each service area must have a 'name' field")
        return value


class BulkServiceIndustrySerializer(serializers.Serializer):
    """Serializer for bulk creating service industries"""
    service_industries = ServiceIndustryItemSerializer(many=True, min_length=1)
    
    def validate_service_industries(self, value):
        """Validate that each service industry has required fields"""
        for item in value:
            if 'name' not in item or not item.get('name'):
                raise serializers.ValidationError("Each service industry must have a 'name' field")
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model"""
    service_areas = ServiceAreaSerializer(many=True, read_only=True)
    service_industries = ServiceIndustrySerializer(many=True, read_only=True)
    service_area_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceArea.objects.filter(is_active=True),
        source='service_areas',
        write_only=True,
        required=False
    )
    service_industry_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceIndustry.objects.filter(is_active=True),
        source='service_industries',
        write_only=True,
        required=False
    )

    class Meta:
        model = UserProfile
        fields = ['id', 'phone', 'service_areas', 'service_industries', 
                  'service_area_ids', 'service_industry_ids', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserSignupSerializer(serializers.Serializer):
    """Serializer for user signup"""
    name = serializers.CharField(max_length=255, help_text="Full name of the user")
    email = serializers.EmailField()
    phone = serializers.CharField(
        max_length=20,
        help_text="Phone number in international format"
    )
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        help_text="User password"
    )
    service_area_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceArea.objects.filter(is_active=True),
        required=False,
        allow_empty=True,
        help_text="List of service area IDs"
    )
    service_industry_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceIndustry.objects.filter(is_active=True),
        required=False,
        allow_empty=True,
        help_text="List of service industry IDs"
    )
    pincodes = serializers.ListField(
        child=serializers.CharField(max_length=10),
        required=False,
        allow_empty=True,
        help_text="List of pincodes"
    )

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        name = validated_data.pop('name')
        email = validated_data.pop('email')
        phone = validated_data.pop('phone')
        password = validated_data.pop('password')
        service_area_ids = validated_data.pop('service_area_ids', [])
        service_industry_ids = validated_data.pop('service_industry_ids', [])
        pincodes = validated_data.pop('pincodes', [])

        # Split name into first_name and last_name
        name_parts = name.split(maxsplit=1)
        first_name = name_parts[0] if name_parts else ''
        last_name = name_parts[1] if len(name_parts) > 1 else ''

        # Create user
        user = User.objects.create_user(
            username=email,  # Use email as username
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )

        # Create user profile
        profile = UserProfile.objects.create(
            user=user,
            phone=phone,
            pincodes=pincodes if pincodes else []
        )

        # Add service areas and industries
        if service_area_ids:
            profile.service_areas.set(service_area_ids)
        if service_industry_ids:
            profile.service_industries.set(service_industry_ids)

        return user


class UserProfileDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for user profile with user information"""
    user = UserSerializer(read_only=True)
    service_areas = ServiceAreaSerializer(many=True, read_only=True)
    service_industries = ServiceIndustrySerializer(many=True, read_only=True)
    service_area_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceArea.objects.filter(is_active=True),
        source='service_areas',
        write_only=True,
        required=False
    )
    service_industry_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceIndustry.objects.filter(is_active=True),
        source='service_industries',
        write_only=True,
        required=False
    )
    name = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'name', 'phone', 'is_active', 'ghl_contact_id', 'pincodes', 'wallet_balance', 'service_areas', 'service_industries',
                  'service_area_ids', 'service_industry_ids', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'ghl_contact_id', 'wallet_balance', 'created_at', 'updated_at']

    def get_name(self, obj):
        """Get full name from user"""
        full_name = obj.user.get_full_name()
        return full_name if full_name else obj.user.username

    def get_is_active(self, obj):
        """Get is_active status from user"""
        return obj.user.is_active


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""
    name = serializers.CharField(max_length=255, required=False, help_text="Full name of the user")
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(max_length=20, required=False)
    is_active = serializers.BooleanField(required=False, help_text="User account active status")
    service_area_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceArea.objects.filter(is_active=True),
        source='service_areas',
        write_only=True,
        required=False
    )
    service_industry_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ServiceIndustry.objects.filter(is_active=True),
        source='service_industries',
        write_only=True,
        required=False
    )
    pincodes = serializers.ListField(
        child=serializers.CharField(max_length=10),
        required=False,
        allow_empty=True,
        help_text="List of pincodes"
    )

    class Meta:
        model = UserProfile
        fields = ['name', 'email', 'phone', 'is_active', 'pincodes', 'service_area_ids', 'service_industry_ids']

    def update(self, instance, validated_data):
        # Update user fields if provided
        user = instance.user
        name = validated_data.pop('name', None)
        email = validated_data.pop('email', None)
        is_active = validated_data.pop('is_active', None)

        if name:
            name_parts = name.split(maxsplit=1)
            user.first_name = name_parts[0] if name_parts else ''
            user.last_name = name_parts[1] if len(name_parts) > 1 else ''
            user.save()

        if email and email != user.email:
            if User.objects.filter(email=email).exclude(id=user.id).exists():
                raise serializers.ValidationError({"email": "A user with this email already exists."})
            user.email = email
            user.username = email  # Update username to match email
            user.save()

        if is_active is not None:
            user.is_active = is_active
            user.save()

        # Update profile fields
        phone = validated_data.pop('phone', None)
        if phone:
            instance.phone = phone

        # Update pincodes if provided
        if 'pincodes' in validated_data:
            instance.pincodes = validated_data['pincodes']

        # Update service areas and industries
        if 'service_areas' in validated_data:
            instance.service_areas.set(validated_data['service_areas'])
        if 'service_industries' in validated_data:
            instance.service_industries.set(validated_data['service_industries'])

        instance.save()
        return instance


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for requesting password reset OTP"""
    email = serializers.EmailField(help_text="Email address to send OTP")
    
    def validate_email(self, value):
        """Validate that user exists with this email"""
        if not User.objects.filter(email=value).exists():
            # Don't reveal if email exists or not for security
            raise serializers.ValidationError("If this email exists, an OTP will be sent.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for confirming password reset with OTP"""
    email = serializers.EmailField(help_text="Email address")
    otp = serializers.CharField(max_length=6, min_length=6, help_text="6-digit OTP code")
    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        help_text="New password"
    )
    confirm_password = serializers.CharField(
        write_only=True,
        help_text="Confirm new password"
    )
    
    def validate(self, data):
        """Validate OTP and password confirmation"""
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        # Validate password confirmation
        if new_password != confirm_password:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })
        
        # Validate OTP
        try:
            user = User.objects.get(email=email)
            otp_record = PasswordResetOTP.objects.filter(
                user=user,
                email=email,
                otp=otp,
                is_used=False
            ).order_by('-created_at').first()
            
            if not otp_record:
                raise serializers.ValidationError({
                    'otp': 'Invalid or expired OTP.'
                })
            
            if not otp_record.is_valid():
                raise serializers.ValidationError({
                    'otp': 'OTP has expired. Please request a new one.'
                })
            
            data['otp_record'] = otp_record
            data['user'] = user
            
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'email': 'Invalid email address.'
            })
        
        return data


class JobSerializer(serializers.ModelSerializer):
    """Serializer for Job model"""
    assigned_to_username = serializers.SerializerMethodField()
    service_industry_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Job
        fields = [
            'id', 'name', 'status', 'price', 'assigned_to', 'assigned_to_username',
            'service_area', 'service_needed', 'service_request_message',
            'contact_id', 'first_name', 'last_name', 'full_name', 'email', 'phone',
            'address1', 'city', 'state', 'country', 'postal_code', 'company_name',
            'service_industry', 'service_industry_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'assigned_to', 'assigned_to_username', 'service_industry_name',
            'created_at', 'updated_at'
        ]
    
    def get_assigned_to_username(self, obj):
        """Get username of assigned user"""
        return obj.assigned_to.username if obj.assigned_to else None
    
    def get_service_industry_name(self, obj):
        """Get name of matching service industry"""
        return obj.service_industry.name if obj.service_industry else None


class JobWebhookSerializer(serializers.Serializer):
    """Serializer for job webhook payload - handles both space and underscore field names"""
    # Handle field names with spaces (from webhook) - map to underscore versions
    def to_internal_value(self, data):
        # Map webhook field names (with spaces) to internal field names (with underscores)
        mapped_data = {}
        for key, value in data.items():
            # Map "Service Area" to "Service_Area", etc.
            mapped_key = key.replace(' ', '_')
            mapped_data[mapped_key] = value
        return super().to_internal_value(mapped_data)
    
    Service_Area = serializers.CharField(required=False, allow_blank=True, allow_null=True, help_text="Service Area")
    Service_Needed = serializers.CharField(required=False, allow_blank=True, allow_null=True, help_text="Service Needed")
    Service_Request_Message = serializers.CharField(required=False, allow_blank=True, allow_null=True, help_text="Service Request Message")
    contact_id = serializers.CharField(required=False, allow_blank=True, allow_null=True, help_text="GHL Contact ID")
    first_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    last_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    full_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    phone = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    address1 = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    city = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    state = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    country = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    postal_code = serializers.CharField(required=False, allow_blank=True, allow_null=True, help_text="Postal code")
    company_name = serializers.CharField(required=False, allow_blank=True, allow_null=True)


class AcceptJobSerializer(serializers.Serializer):
    """Serializer for accepting a job"""
    job_id = serializers.IntegerField(help_text="ID of the job to accept")


class RejectJobSerializer(serializers.Serializer):
    """Serializer for rejecting a job"""
    job_id = serializers.IntegerField(help_text="ID of the job to reject")


class UpdateJobStatusSerializer(serializers.Serializer):
    """Serializer for updating job status"""
    job_id = serializers.IntegerField(help_text="ID of the job to update")
    status = serializers.ChoiceField(
        choices=Job.STATUS_CHOICES,
        help_text="New status for the job"
    )
    
    def validate_status(self, value):
        """Validate that status transition is allowed"""
        # Users can only change status to 'completed' or 'cancelled' from 'accepted'
        # This validation will be done in the view to check the current status
        return value