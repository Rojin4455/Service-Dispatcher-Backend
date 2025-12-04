from rest_framework import status
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import (
    LoginSerializer, UserSerializer, ServiceAreaSerializer, ServiceIndustrySerializer,
    UserSignupSerializer, UserLoginSerializer, UserProfileDetailSerializer, UserProfileUpdateSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer, JobSerializer, JobWebhookSerializer, 
    AcceptJobSerializer, RejectJobSerializer, UpdateJobStatusSerializer
)
from rest_framework.views import APIView
from rest_framework import viewsets
from .models import ServiceArea, ServiceIndustry, UserProfile, PasswordResetOTP, Job, JobRejection
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import ProtectedError
from decimal import Decimal, InvalidOperation
from .services import sync_user_to_ghl, send_password_reset_otp_email, sync_profile_custom_fields_to_ghl
import logging

logger = logging.getLogger(__name__)

# Import token blacklist models if available
try:
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
    TOKEN_BLACKLIST_AVAILABLE = True
except ImportError:
    TOKEN_BLACKLIST_AVAILABLE = False



class IsAdminPermission(BasePermission):
    """Custom permission to only allow admins to access views"""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_staff


class IsAuthenticatedUser(BasePermission):
    """Custom permission to allow authenticated users (non-admin)"""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    


class AdminTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]
    print('here')
    # permission_classes = [IsAdminUser]

class AdminTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]

class AdminLogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # Requires Blacklist app enabled
            return Response({"detail": "Successfully logged out."})
        except Exception as e:
            return Response({"detail": "Invalid token or already logged out."}, status=400)



# Authentication Views
class AdminLoginView(APIView):
    """Admin login view"""
    permission_classes = [AllowAny]

    def post(self, request):
        print("request: ", request.data)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': UserSerializer(user).data,
                'message': 'Login successful'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Service Area CRUD Views
class ServiceAreaViewSet(viewsets.ModelViewSet):
    """ViewSet for ServiceArea CRUD operations"""
    queryset = ServiceArea.objects.all()
    serializer_class = ServiceAreaSerializer
    permission_classes = [IsAdminPermission]

    def get_queryset(self):
        queryset = ServiceArea.objects.all()
        # Optional: Filter by is_active if needed
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        return queryset


class PublicServiceAreaListView(APIView):
    """Public endpoint to get active service areas for signup form"""
    permission_classes = [AllowAny]

    def get(self, request):
        """Get all active service areas"""
        service_areas = ServiceArea.objects.filter(is_active=True).order_by('name')
        serializer = ServiceAreaSerializer(service_areas, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Service Industry CRUD Views
class ServiceIndustryViewSet(viewsets.ModelViewSet):
    """ViewSet for ServiceIndustry CRUD operations"""
    queryset = ServiceIndustry.objects.all()
    serializer_class = ServiceIndustrySerializer
    permission_classes = [IsAdminPermission]

    def get_queryset(self):
        queryset = ServiceIndustry.objects.all()
        # Optional: Filter by is_active if needed
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        return queryset


class PublicServiceIndustryListView(APIView):
    """Public endpoint to get active service industries for signup form"""
    permission_classes = [AllowAny]

    def get(self, request):
        """Get all active service industries"""
        service_industries = ServiceIndustry.objects.filter(is_active=True).order_by('name')
        serializer = ServiceIndustrySerializer(service_industries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# User Signup and Login Views
class UserSignupView(APIView):
    """User signup view"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            profile = user.profile
            
            # Sync user to GHL (search and upsert)
            try:
                ghl_contact = sync_user_to_ghl(profile)
                if ghl_contact:
                    logger.info(f"Successfully synced user {user.email} to GHL")
                else:
                    logger.warning(f"Failed to sync user {user.email} to GHL")
            except Exception as e:
                # Log error but don't fail the signup
                logger.error(f"Error syncing user to GHL: {str(e)}")
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': UserProfileDetailSerializer(profile).data,
                'message': 'Signup successful'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """User login view"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            try:
                profile = user.profile
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': UserProfileDetailSerializer(profile).data,
                    'message': 'Login successful'
                }, status=status.HTTP_200_OK)
            except UserProfile.DoesNotExist:
                # If profile doesn't exist, return basic user info
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': UserSerializer(user).data,
                    'message': 'Login successful. Please complete your profile.'
                }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """View for users to get and update their own profile"""
    permission_classes = [IsAuthenticatedUser]

    def get(self, request):
        """Get current user's profile"""
        try:
            profile = request.user.profile
            serializer = UserProfileDetailSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found. Please complete your profile.'},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request):
        """Update current user's profile (full update)"""
        try:
            profile = request.user.profile
            serializer = UserProfileUpdateSerializer(profile, data=request.data)
            if serializer.is_valid():
                serializer.save()
                
                # Sync updated profile to GHL
                try:
                    ghl_contact = sync_user_to_ghl(profile)
                    if ghl_contact:
                        logger.info(f"Successfully synced updated profile for user {request.user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync updated profile for user {request.user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing updated profile to GHL: {str(e)}")
                
                # Return updated profile
                updated_serializer = UserProfileDetailSerializer(profile)
                return Response(updated_serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found. Please complete your profile.'},
                status=status.HTTP_404_NOT_FOUND
            )

    def patch(self, request):
        """Update current user's profile (partial update)"""
        try:
            profile = request.user.profile
            serializer = UserProfileUpdateSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                
                # Sync updated profile to GHL
                try:
                    ghl_contact = sync_user_to_ghl(profile)
                    if ghl_contact:
                        logger.info(f"Successfully synced updated profile for user {request.user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync updated profile for user {request.user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing updated profile to GHL: {str(e)}")
                
                # Sync custom fields to GHL
                try:
                    ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                    if ghl_custom_fields:
                        logger.info(f"Successfully synced custom fields for user {request.user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync custom fields for user {request.user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing custom fields to GHL: {str(e)}")
                
                # Return updated profile
                updated_serializer = UserProfileDetailSerializer(profile)
                return Response(updated_serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found. Please complete your profile.'},
                status=status.HTTP_404_NOT_FOUND
            )


# Admin User Management Views
class AdminUserListView(APIView):
    """Admin view to list all users"""
    permission_classes = [IsAdminPermission]

    def get(self, request):
        """Get all users with their profiles"""
        users = User.objects.all().select_related('profile').prefetch_related(
            'profile__service_areas', 'profile__service_industries'
        )
        profiles = [user.profile for user in users if hasattr(user, 'profile')]
        serializer = UserProfileDetailSerializer(profiles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminUserDetailView(APIView):
    """Admin view to get, update, and delete a specific user"""
    permission_classes = [IsAdminPermission]

    def get(self, request, user_id):
        """Get a specific user's profile"""
        try:
            user = User.objects.get(id=user_id)
            profile = user.profile
            serializer = UserProfileDetailSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, user_id):
        """Update a specific user's profile (full update)"""
        try:
            user = User.objects.get(id=user_id)
            profile = user.profile
            serializer = UserProfileUpdateSerializer(profile, data=request.data)
            if serializer.is_valid():
                serializer.save()
                
                # Sync updated profile to GHL
                try:
                    ghl_contact = sync_user_to_ghl(profile)
                    if ghl_contact:
                        logger.info(f"Successfully synced updated profile for user {user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync updated profile for user {user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing updated profile to GHL: {str(e)}")
                
                # Sync custom fields to GHL
                try:
                    ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                    if ghl_custom_fields:
                        logger.info(f"Successfully synced custom fields for user {user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync custom fields for user {user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing custom fields to GHL: {str(e)}")
                
                # Return updated profile
                updated_serializer = UserProfileDetailSerializer(profile)
                return Response(updated_serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

    def patch(self, request, user_id):
        """Update a specific user's profile (partial update)"""
        try:
            user = User.objects.get(id=user_id)
            profile = user.profile
            serializer = UserProfileUpdateSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                
                # Sync updated profile to GHL
                try:
                    ghl_contact = sync_user_to_ghl(profile)
                    if ghl_contact:
                        logger.info(f"Successfully synced updated profile for user {user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync updated profile for user {user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing updated profile to GHL: {str(e)}")
                
                # Sync custom fields to GHL
                try:
                    ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                    if ghl_custom_fields:
                        logger.info(f"Successfully synced custom fields for user {user.email} to GHL")
                    else:
                        logger.warning(f"Failed to sync custom fields for user {user.email} to GHL")
                except Exception as e:
                    # Log error but don't fail the update
                    logger.error(f"Error syncing custom fields to GHL: {str(e)}")
                
                # Return updated profile
                updated_serializer = UserProfileDetailSerializer(profile)
                return Response(updated_serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, user_id):
        """Delete a user"""
        try:
            user = User.objects.get(id=user_id)
            user_id_before_delete = user.id
            username_before_delete = user.username
            
            # Delete user within a transaction to ensure it's committed
            with transaction.atomic():
                # Delete token blacklist entries first if available
                if TOKEN_BLACKLIST_AVAILABLE:
                    try:
                        # Delete outstanding tokens for this user
                        OutstandingToken.objects.filter(user=user).delete()
                        logger.info(f"Deleted outstanding tokens for user {user_id_before_delete}")
                    except Exception as e:
                        logger.warning(f"Error deleting outstanding tokens: {str(e)}")
                
                # Delete the user (this will cascade delete the profile due to CASCADE)
                # Django's delete() will raise ProtectedError if there are protected relationships
                user.delete()
            
            # Verify deletion after transaction commits
            # This check happens after the transaction, so it should reflect the actual database state
            if User.objects.filter(id=user_id_before_delete).exists():
                logger.error(f"User {user_id_before_delete} still exists after deletion - possible database constraint issue")
                return Response(
                    {'error': 'User deletion may have failed. Please check the database.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            logger.info(f"User {user_id_before_delete} ({username_before_delete}) deleted successfully")
            return Response(
                {'message': 'User deleted successfully.'},
                status=status.HTTP_204_NO_CONTENT
            )
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ProtectedError as e:
            logger.error(f"ProtectedError deleting user {user_id}: {str(e)}")
            protected_objects = []
            if hasattr(e, 'protected_objects'):
                protected_objects = [str(obj) for obj in e.protected_objects[:5]]  # Limit to first 5
            error_msg = f'Cannot delete user. User is referenced by other objects.'
            if protected_objects:
                error_msg += f' Protected objects: {", ".join(protected_objects)}'
            return Response(
                {'error': error_msg},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while deleting the user: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WalletRechargeWebhookView(APIView):
    """Webhook endpoint to recharge wallet balance based on GHL contact ID"""
    permission_classes = [AllowAny]  # Webhook should be accessible without authentication
    
    def post(self, request):
        """
        Webhook to update wallet balance
        Expected payload:
        {
            "id": "ghl_contact_id",
            "amount": 100.50
        }
        """
        try:
            # Extract data from payload
            ghl_contact_id = request.data.get('id')
            amount = request.data.get('amount')
            
            # Validate required fields
            if not ghl_contact_id:
                return Response(
                    {'error': 'Missing required field: id (GHL contact ID)'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if amount is None:
                return Response(
                    {'error': 'Missing required field: amount'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate and convert amount to Decimal
            try:
                amount_decimal = Decimal(str(amount))
                if amount_decimal < 0:
                    return Response(
                        {'error': 'Amount must be a positive number'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except (InvalidOperation, ValueError, TypeError):
                return Response(
                    {'error': 'Invalid amount format. Amount must be a valid number'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Find user profile by GHL contact ID
            try:
                profile = UserProfile.objects.get(ghl_contact_id=ghl_contact_id)
            except UserProfile.DoesNotExist:
                logger.warning(f"Webhook: User profile not found for GHL contact ID: {ghl_contact_id}")
                return Response(
                    {'error': f'User profile not found for GHL contact ID: {ghl_contact_id}'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Update wallet balance within a transaction
            with transaction.atomic():
                old_balance = profile.wallet_balance
                profile.wallet_balance += amount_decimal
                profile.save(update_fields=['wallet_balance'])
                
                logger.info(
                    f"Wallet recharged for user {profile.user.email} (GHL ID: {ghl_contact_id}). "
                    f"Old balance: {old_balance}, Amount added: {amount_decimal}, New balance: {profile.wallet_balance}"
                )
                
                # Sync custom fields to GHL (especially wallet balance)
                try:
                    ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                    if ghl_custom_fields:
                        logger.info(f"Successfully synced custom fields after wallet recharge for user {profile.user.email}")
                    else:
                        logger.warning(f"Failed to sync custom fields after wallet recharge for user {profile.user.email}")
                except Exception as e:
                    # Log error but don't fail the webhook
                    logger.error(f"Error syncing custom fields after wallet recharge: {str(e)}")
            
            return Response({
                'success': True,
                'message': 'Wallet balance updated successfully',
                'ghl_contact_id': ghl_contact_id,
                'amount_added': str(amount_decimal),
                'previous_balance': str(old_balance),
                'new_balance': str(profile.wallet_balance),
                'user_email': profile.user.email
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error processing wallet recharge webhook: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while processing the webhook: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetRequestView(APIView):
    """View to request password reset OTP"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Request password reset OTP
        Expected payload:
        {
            "email": "user@example.com"
        }
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                
                # Create OTP
                otp_record = PasswordResetOTP.create_otp(user, email)
                
                # Get GHL contact ID from user profile if available
                ghl_contact_id = None
                try:
                    profile = user.profile
                    ghl_contact_id = profile.ghl_contact_id
                except UserProfile.DoesNotExist:
                    pass
                
                # Send OTP email and update GHL contact
                user_name = user.get_full_name() or user.username
                email_sent = send_password_reset_otp_email(
                    email=email,
                    otp_code=otp_record.otp,
                    user_name=user_name,
                    ghl_contact_id=ghl_contact_id
                )
                
                if email_sent:
                    logger.info(f"Password reset OTP sent to {email}")
                    return Response({
                        'message': 'If this email exists, an OTP has been sent to your email address.',
                        'otp_expires_in_minutes': 10
                    }, status=status.HTTP_200_OK)
                else:
                    logger.error(f"Failed to send password reset OTP email to {email}")
                    return Response({
                        'error': 'Failed to send OTP email. Please try again later.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
            except User.DoesNotExist:
                # Don't reveal if email exists or not for security
                logger.warning(f"Password reset requested for non-existent email: {email}")
                return Response({
                    'message': 'If this email exists, an OTP has been sent to your email address.',
                    'otp_expires_in_minutes': 10
                }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Error processing password reset request: {str(e)}", exc_info=True)
                return Response({
                    'error': 'An error occurred while processing your request. Please try again later.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """View to confirm password reset with OTP"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Reset password using OTP
        Expected payload:
        {
            "email": "user@example.com",
            "otp": "123456",
            "new_password": "newSecurePassword123",
            "confirm_password": "newSecurePassword123"
        }
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            otp_record = serializer.validated_data['otp_record']
            new_password = serializer.validated_data['new_password']
            
            try:
                # Update password
                user.set_password(new_password)
                user.save()
                
                # Mark OTP as used
                otp_record.is_used = True
                otp_record.save()
                
                # Invalidate all other unused OTPs for this user
                PasswordResetOTP.objects.filter(
                    user=user,
                    is_used=False
                ).update(is_used=True)
                
                logger.info(f"Password reset successful for user {user.email}")
                return Response({
                    'message': 'Password has been reset successfully. You can now login with your new password.'
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Error resetting password: {str(e)}", exc_info=True)
                return Response({
                    'error': 'An error occurred while resetting your password. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobWebhookView(APIView):
    """Webhook endpoint to receive jobs"""
    permission_classes = [AllowAny]  # Webhook should be accessible without authentication
    
    def post(self, request):
        """
        Webhook to receive and save jobs
        Expected payload:
        {
            "name": "Window Cleaning",
            "status": "pending",
            "price": 50.00
        }
        """
        try:
            serializer = JobWebhookSerializer(data=request.data)
            if serializer.is_valid():
                # Create job with status pending (unassigned)
                job = Job.objects.create(
                    name=serializer.validated_data['name'],
                    status=serializer.validated_data['status'],
                    price=serializer.validated_data['price'],
                    assigned_to=None  # Initially unassigned
                )
                
                logger.info(
                    f"Job created via webhook: {job.name} - Status: {job.status} - Price: {job.price}"
                )
                
                return Response({
                    'success': True,
                    'message': 'Job created successfully',
                    'job': JobSerializer(job).data
                }, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error processing job webhook: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while processing the webhook: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PendingJobsView(APIView):
    """View to get all pending jobs (unassigned jobs) excluding rejected ones"""
    permission_classes = [IsAuthenticatedUser]
    
    def get(self, request):
        """Get all pending jobs that are not assigned to any user and not rejected by current user"""
        try:
            # Get IDs of jobs rejected by current user
            rejected_job_ids = JobRejection.objects.filter(
                user=request.user
            ).values_list('job_id', flat=True)
            
            # Get all jobs that are pending, not assigned, and not rejected by current user
            pending_jobs = Job.objects.filter(
                status='pending',
                assigned_to__isnull=True
            ).exclude(id__in=rejected_job_ids).order_by('-created_at')
            
            serializer = JobSerializer(pending_jobs, many=True)
            return Response({
                'jobs': serializer.data,
                'count': pending_jobs.count()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching pending jobs: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while fetching pending jobs: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MyJobsView(APIView):
    """View to get all jobs assigned to the current user"""
    permission_classes = [IsAuthenticatedUser]
    
    def get(self, request):
        """Get all jobs assigned to the current user"""
        try:
            # Get all jobs assigned to the current user
            my_jobs = Job.objects.filter(
                assigned_to=request.user
            ).order_by('-created_at')
            
            serializer = JobSerializer(my_jobs, many=True)
            return Response({
                'jobs': serializer.data,
                'count': my_jobs.count()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching user jobs: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while fetching your jobs: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AcceptJobView(APIView):
    """View to accept a job (assign it to the current user and deduct price from wallet)"""
    permission_classes = [IsAuthenticatedUser]
    
    def post(self, request):
        """
        Accept a job
        Expected payload:
        {
            "job_id": 1
        }
        """
        try:
            serializer = AcceptJobSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            job_id = serializer.validated_data['job_id']
            
            # Get user profile first (outside transaction)
            try:
                profile = request.user.profile
            except UserProfile.DoesNotExist:
                return Response(
                    {'error': 'User profile not found. Please complete your profile.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Do initial validation checks (outside transaction)
            try:
                job = Job.objects.get(id=job_id)
            except Job.DoesNotExist:
                return Response(
                    {'error': 'Job not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if job status is pending
            if job.status != 'pending':
                return Response(
                    {'error': f'This job cannot be accepted. Current status: {job.status}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if user has sufficient wallet balance
            if profile.wallet_balance < job.price:
                return Response(
                    {
                        'error': 'Insufficient wallet balance.',
                        'required': str(job.price),
                        'current_balance': str(profile.wallet_balance)
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Accept the job and deduct price from wallet within a transaction
            with transaction.atomic():
                # Lock the job row to prevent race conditions
                job = Job.objects.select_for_update().get(id=job_id)
                
                # Re-check if job is already assigned (in case it was assigned between checks)
                if job.assigned_to is not None:
                    return Response(
                        {'error': 'This job has already been accepted by another user.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Re-check job status
                if job.status != 'pending':
                    return Response(
                        {'error': f'This job cannot be accepted. Current status: {job.status}'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Refresh profile to get latest wallet balance
                profile.refresh_from_db()
                
                # Re-check wallet balance (in case it changed)
                if profile.wallet_balance < job.price:
                    return Response(
                        {
                            'error': 'Insufficient wallet balance.',
                            'required': str(job.price),
                            'current_balance': str(profile.wallet_balance)
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Assign job to user and update status
                old_balance = profile.wallet_balance
                job.assigned_to = request.user
                job.status = 'accepted'
                job.save()
                
                # Deduct price from wallet
                profile.wallet_balance -= job.price
                profile.save(update_fields=['wallet_balance'])
                
                logger.info(
                    f"Job {job.id} ({job.name}) accepted by user {request.user.email}. "
                    f"Price deducted: {job.price}. Old balance: {old_balance}, New balance: {profile.wallet_balance}"
                )
                
                # Sync custom fields to GHL (especially wallet balance)
                try:
                    from .services import sync_profile_custom_fields_to_ghl
                    ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                    if ghl_custom_fields:
                        logger.info(f"Successfully synced custom fields after job acceptance for user {request.user.email}")
                    else:
                        logger.warning(f"Failed to sync custom fields after job acceptance for user {request.user.email}")
                except Exception as e:
                    # Log error but don't fail the job acceptance
                    logger.error(f"Error syncing custom fields after job acceptance: {str(e)}")
            
            return Response({
                'success': True,
                'message': 'Job accepted successfully',
                'job': JobSerializer(job).data,
                'wallet_balance': str(profile.wallet_balance),
                'amount_deducted': str(job.price)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error accepting job: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while accepting the job: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RejectJobView(APIView):
    """View to reject a job (mark it as rejected for the current user)"""
    permission_classes = [IsAuthenticatedUser]
    
    def post(self, request):
        """
        Reject a job
        Expected payload:
        {
            "job_id": 1
        }
        """
        try:
            serializer = RejectJobSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            job_id = serializer.validated_data['job_id']
            
            # Get the job
            try:
                job = Job.objects.get(id=job_id)
            except Job.DoesNotExist:
                return Response(
                    {'error': 'Job not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if job is already assigned
            if job.assigned_to is not None:
                return Response(
                    {'error': 'Cannot reject a job that has already been accepted.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if job status is pending
            if job.status != 'pending':
                return Response(
                    {'error': f'Cannot reject a job with status: {job.status}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if user has already rejected this job
            if JobRejection.objects.filter(job=job, user=request.user).exists():
                return Response(
                    {'error': 'You have already rejected this job.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create rejection record
            rejection = JobRejection.objects.create(
                job=job,
                user=request.user
            )
            
            logger.info(
                f"Job {job.id} ({job.name}) rejected by user {request.user.email}"
            )
            
            return Response({
                'success': True,
                'message': 'Job rejected successfully',
                'job_id': job.id,
                'job_name': job.name
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error rejecting job: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while rejecting the job: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UpdateJobStatusView(APIView):
    """View to update the status of an accepted job"""
    permission_classes = [IsAuthenticatedUser]
    
    def post(self, request):
        """
        Update job status
        Expected payload:
        {
            "job_id": 1,
            "status": "completed"  or "cancelled"
        }
        """
        try:
            serializer = UpdateJobStatusSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            job_id = serializer.validated_data['job_id']
            new_status = serializer.validated_data['status']
            
            # Get the job
            try:
                job = Job.objects.get(id=job_id)
            except Job.DoesNotExist:
                return Response(
                    {'error': 'Job not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if job is assigned to current user
            if job.assigned_to != request.user:
                return Response(
                    {'error': 'You can only update the status of jobs assigned to you.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if job is in accepted status (only accepted jobs can be updated)
            if job.status != 'accepted':
                return Response(
                    {
                        'error': f'Job status can only be updated from "accepted". Current status: {job.status}'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate status transition (only allow completed or cancelled)
            if new_status not in ['completed', 'cancelled']:
                return Response(
                    {
                        'error': f'Status can only be changed to "completed" or "cancelled". Provided: {new_status}'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Update job status
            old_status = job.status
            job.status = new_status
            job.save()
            
            logger.info(
                f"Job {job.id} ({job.name}) status updated from {old_status} to {new_status} by user {request.user.email}"
            )
            
            # If job is cancelled, refund the price to user's wallet
            if new_status == 'cancelled':
                try:
                    profile = request.user.profile
                    with transaction.atomic():
                        old_balance = profile.wallet_balance
                        profile.wallet_balance += job.price
                        profile.save(update_fields=['wallet_balance'])
                        
                        logger.info(
                            f"Job {job.id} cancelled. Refunded {job.price} to user {request.user.email}. "
                            f"Old balance: {old_balance}, New balance: {profile.wallet_balance}"
                        )
                        
                        # Sync custom fields to GHL (especially wallet balance)
                        try:
                            from .services import sync_profile_custom_fields_to_ghl
                            ghl_custom_fields = sync_profile_custom_fields_to_ghl(profile)
                            if ghl_custom_fields:
                                logger.info(f"Successfully synced custom fields after job cancellation for user {request.user.email}")
                            else:
                                logger.warning(f"Failed to sync custom fields after job cancellation for user {request.user.email}")
                        except Exception as e:
                            # Log error but don't fail the status update
                            logger.error(f"Error syncing custom fields after job cancellation: {str(e)}")
                        
                        return Response({
                            'success': True,
                            'message': 'Job status updated and amount refunded to wallet',
                            'job': JobSerializer(job).data,
                            'wallet_balance': str(profile.wallet_balance),
                            'amount_refunded': str(job.price)
                        }, status=status.HTTP_200_OK)
                        
                except UserProfile.DoesNotExist:
                    logger.warning(f"User profile not found for refund. Job status updated but refund failed.")
                    return Response({
                        'success': True,
                        'message': 'Job status updated, but refund failed (profile not found)',
                        'job': JobSerializer(job).data
                    }, status=status.HTTP_200_OK)
            
            return Response({
                'success': True,
                'message': 'Job status updated successfully',
                'job': JobSerializer(job).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error updating job status: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while updating job status: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )