from rest_framework import status
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import (
    LoginSerializer, UserSerializer, ServiceAreaSerializer, ServiceIndustrySerializer,
    UserSignupSerializer, UserLoginSerializer, UserProfileDetailSerializer, UserProfileUpdateSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer, JobSerializer, JobWebhookSerializer, 
    AcceptJobSerializer, RejectJobSerializer, UpdateJobStatusSerializer, BulkServiceAreaSerializer,
    BulkServiceIndustrySerializer
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
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


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
    """ViewSet for ServiceArea CRUD operations with filtering"""
    queryset = ServiceArea.objects.all()
    serializer_class = ServiceAreaSerializer
    permission_classes = [IsAdminPermission]

    def get_queryset(self):
        """
        Get queryset with filtering options:
        - is_active: Filter by active status (true/false)
        - search: Search by name (case-insensitive partial match)
        - ordering: Order by field (name, created_at, updated_at) with - prefix for descending
        Examples:
            ?is_active=true
            ?search=cleaning
            ?ordering=name
            ?ordering=-created_at
            ?is_active=true&search=area&ordering=name
        """
        queryset = ServiceArea.objects.all()
        
        # Filter by is_active
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by name (case-insensitive partial match)
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        # Ordering
        ordering = self.request.query_params.get('ordering', 'name')
        if ordering:
            # Validate ordering field to prevent SQL injection
            allowed_fields = ['name', 'created_at', 'updated_at', 'id']
            if ordering.lstrip('-') in allowed_fields:
                queryset = queryset.order_by(ordering)
        
        return queryset


class PublicServiceAreaListView(APIView):
    """Public endpoint to get service areas with filtering"""
    permission_classes = [AllowAny]

    def get(self, request):
        """
        Get service areas with filtering options:
        - is_active: Filter by active status (true/false, default: true)
        - search: Search by name (case-insensitive partial match)
        - ordering: Order by field (name, created_at, updated_at) with - prefix for descending
        Examples:
            ?is_active=true
            ?search=cleaning
            ?ordering=name
            ?is_active=true&search=area&ordering=-created_at
        """
        # Default to active only for public endpoint
        is_active_param = self.request.query_params.get('is_active', 'true')
        queryset = ServiceArea.objects.filter(is_active=is_active_param.lower() == 'true')
        
        # Search by name
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        # Ordering (default to name)
        ordering = self.request.query_params.get('ordering', 'name')
        allowed_fields = ['name', 'created_at', 'updated_at', 'id']
        if ordering.lstrip('-') in allowed_fields:
            queryset = queryset.order_by(ordering)
        else:
            queryset = queryset.order_by('name')
        
        serializer = ServiceAreaSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Service Industry CRUD Views
class ServiceIndustryViewSet(viewsets.ModelViewSet):
    """ViewSet for ServiceIndustry CRUD operations with filtering"""
    queryset = ServiceIndustry.objects.all()
    serializer_class = ServiceIndustrySerializer
    permission_classes = [IsAdminPermission]

    def get_queryset(self):
        """
        Get queryset with filtering options:
        - is_active: Filter by active status (true/false)
        - search: Search by name (case-insensitive partial match)
        - min_price: Filter by minimum price
        - max_price: Filter by maximum price
        - ordering: Order by field (name, price, created_at, updated_at) with - prefix for descending
        Examples:
            ?is_active=true
            ?search=cleaning
            ?min_price=50&max_price=200
            ?ordering=price
            ?ordering=-created_at
            ?is_active=true&search=inspection&min_price=100&ordering=name
        """
        queryset = ServiceIndustry.objects.all()
        
        # Filter by is_active
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by name (case-insensitive partial match)
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        # Filter by minimum price
        min_price = self.request.query_params.get('min_price', None)
        if min_price:
            try:
                queryset = queryset.filter(price__gte=Decimal(str(min_price)))
            except (ValueError, InvalidOperation):
                pass  # Ignore invalid min_price
        
        # Filter by maximum price
        max_price = self.request.query_params.get('max_price', None)
        if max_price:
            try:
                queryset = queryset.filter(price__lte=Decimal(str(max_price)))
            except (ValueError, InvalidOperation):
                pass  # Ignore invalid max_price
        
        # Ordering
        ordering = self.request.query_params.get('ordering', 'name')
        if ordering:
            # Validate ordering field to prevent SQL injection
            allowed_fields = ['name', 'price', 'created_at', 'updated_at', 'id']
            if ordering.lstrip('-') in allowed_fields:
                queryset = queryset.order_by(ordering)
        
        return queryset


class PublicServiceIndustryListView(APIView):
    """Public endpoint to get service industries with filtering"""
    permission_classes = [AllowAny]

    def get(self, request):
        """
        Get service industries with filtering options:
        - is_active: Filter by active status (true/false, default: true)
        - search: Search by name (case-insensitive partial match)
        - min_price: Filter by minimum price
        - max_price: Filter by maximum price
        - ordering: Order by field (name, price, created_at, updated_at) with - prefix for descending
        Examples:
            ?is_active=true
            ?search=cleaning
            ?min_price=50&max_price=200
            ?ordering=price
            ?is_active=true&search=inspection&min_price=100&ordering=-price
        """
        # Default to active only for public endpoint
        is_active_param = self.request.query_params.get('is_active', 'true')
        queryset = ServiceIndustry.objects.filter(is_active=is_active_param.lower() == 'true')
        
        # Search by name
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        # Filter by minimum price
        min_price = self.request.query_params.get('min_price', None)
        if min_price:
            try:
                queryset = queryset.filter(price__gte=Decimal(str(min_price)))
            except (ValueError, InvalidOperation):
                pass  # Ignore invalid min_price
        
        # Filter by maximum price
        max_price = self.request.query_params.get('max_price', None)
        if max_price:
            try:
                queryset = queryset.filter(price__lte=Decimal(str(max_price)))
            except (ValueError, InvalidOperation):
                pass  # Ignore invalid max_price
        
        # Ordering (default to name)
        ordering = self.request.query_params.get('ordering', 'name')
        allowed_fields = ['name', 'price', 'created_at', 'updated_at', 'id']
        if ordering.lstrip('-') in allowed_fields:
            queryset = queryset.order_by(ordering)
        else:
            queryset = queryset.order_by('name')
        
        serializer = ServiceIndustrySerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class BulkCreateServiceAreaView(APIView):
    """View to bulk create service areas"""
    permission_classes = [IsAdminPermission]
    
    def post(self, request):
        """
        Bulk create service areas
        Expected payload:
        {
            "service_areas": [
                {"name": "Area 1", "is_active": true},
                {"name": "Area 2", "is_active": true},
                {"name": "Area 3"}
            ]
        }
        """
        try:
            serializer = BulkServiceAreaSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            service_areas_data = serializer.validated_data['service_areas']
            created_areas = []
            errors = []
            
            with transaction.atomic():
                for item in service_areas_data:
                    try:
                        name = item['name']
                        is_active = item.get('is_active', True)
                        
                        # Check if service area already exists
                        if ServiceArea.objects.filter(name=name).exists():
                            errors.append({
                                'name': name,
                                'error': f'Service area with name "{name}" already exists'
                            })
                            continue
                        
                        # Create service area
                        service_area = ServiceArea.objects.create(
                            name=name,
                            is_active=is_active
                        )
                        created_areas.append(ServiceAreaSerializer(service_area).data)
                        
                    except Exception as e:
                        errors.append({
                            'name': item.get('name', 'unknown'),
                            'error': str(e)
                        })
                        logger.error(f"Error creating service area {item.get('name')}: {str(e)}")
            
            response_data = {
                'success': True,
                'created_count': len(created_areas),
                'created': created_areas
            }
            
            if errors:
                response_data['errors'] = errors
                response_data['error_count'] = len(errors)
            
            status_code = status.HTTP_201_CREATED if created_areas else status.HTTP_400_BAD_REQUEST
            
            logger.info(
                f"Bulk create service areas: {len(created_areas)} created, {len(errors)} errors"
            )
            
            return Response(response_data, status=status_code)
            
        except Exception as e:
            logger.error(f"Error in bulk create service areas: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while bulk creating service areas: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BulkCreateServiceIndustryView(APIView):
    """View to bulk create service industries"""
    permission_classes = [IsAdminPermission]
    
    def post(self, request):
        """
        Bulk create service industries
        Expected payload:
        {
            "service_industries": [
                {"name": "Industry 1", "price": 100.50, "is_active": true},
                {"name": "Industry 2", "price": 200.00, "is_active": true},
                {"name": "Industry 3", "price": 150.75}
            ]
        }
        """
        try:
            serializer = BulkServiceIndustrySerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            service_industries_data = serializer.validated_data['service_industries']
            created_industries = []
            errors = []
            
            with transaction.atomic():
                for item in service_industries_data:
                    try:
                        name = item['name']
                        # Price defaults to 0 if not provided
                        price = item.get('price', Decimal('0.00'))
                        is_active = item.get('is_active', True)
                        
                        # Validate price is not negative
                        if price < 0:
                            errors.append({
                                'name': name,
                                'error': 'Price must be a positive number'
                            })
                            continue
                        
                        # Check if service industry already exists
                        if ServiceIndustry.objects.filter(name=name).exists():
                            errors.append({
                                'name': name,
                                'error': f'Service industry with name "{name}" already exists'
                            })
                            continue
                        
                        # Create service industry
                        service_industry = ServiceIndustry.objects.create(
                            name=name,
                            price=price,
                            is_active=is_active
                        )
                        created_industries.append(ServiceIndustrySerializer(service_industry).data)
                        
                    except (InvalidOperation, ValueError, TypeError) as e:
                        errors.append({
                            'name': item.get('name', 'unknown'),
                            'error': f'Invalid price format: {str(e)}'
                        })
                        logger.error(f"Error creating service industry {item.get('name')}: {str(e)}")
                    except Exception as e:
                        errors.append({
                            'name': item.get('name', 'unknown'),
                            'error': str(e)
                        })
                        logger.error(f"Error creating service industry {item.get('name')}: {str(e)}")
            
            response_data = {
                'success': True,
                'created_count': len(created_industries),
                'created': created_industries
            }
            
            if errors:
                response_data['errors'] = errors
                response_data['error_count'] = len(errors)
            
            status_code = status.HTTP_201_CREATED if created_industries else status.HTTP_400_BAD_REQUEST
            
            logger.info(
                f"Bulk create service industries: {len(created_industries)} created, {len(errors)} errors"
            )
            
            return Response(response_data, status=status_code)
            
        except Exception as e:
            logger.error(f"Error in bulk create service industries: {str(e)}", exc_info=True)
            return Response(
                {'error': f'An error occurred while bulk creating service industries: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


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


@method_decorator(csrf_exempt, name='dispatch')
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


@method_decorator(csrf_exempt, name='dispatch')
class JobWebhookView(APIView):
    """Webhook endpoint to receive jobs"""
    permission_classes = [AllowAny]  # Webhook should be accessible without authentication
    
    def post(self, request):
        """
        Webhook to receive and save jobs
        Expected payload:
        {
            "Service Area": "Test Area 1",
            "Service Needed": "Chimney Inspection",
            "Service Request Message": "this is test message",
            "contact_id": "InZOJpwnZaAPxCpDpUH5",
            "first_name": "Test",
            "last_name": "test",
            "full_name": "Test test",
            "email": "tech@testtest.com",
            "phone": "+97192121234",
            "address1": "Texas Roadhouse, South 24th Street",
            "city": "Council Bluffs",
            "state": "Iowa",
            "country": "US",
            "postal_code": "51501",
            "company_name": "test business name"
        }
        """
        try:
            serializer = JobWebhookSerializer(data=request.data)
            if serializer.is_valid():
                validated_data = serializer.validated_data
                
                # Get service area and service needed
                service_area = validated_data.get('Service_Area', '')
                service_needed = validated_data.get('Service_Needed', '')
                
                # Find matching service industry by name
                service_industry = None
                price = Decimal('0.00')
                
                if service_needed:
                    try:
                        service_industry = ServiceIndustry.objects.get(name=service_needed, is_active=True)
                        price = service_industry.price
                    except ServiceIndustry.DoesNotExist:
                        logger.warning(f"Service industry '{service_needed}' not found. Using default price 0.00")
                    except ServiceIndustry.MultipleObjectsReturned:
                        # If multiple found, use the first one
                        service_industry = ServiceIndustry.objects.filter(name=service_needed, is_active=True).first()
                        if service_industry:
                            price = service_industry.price
                
                # Create job with all fields
                job = Job.objects.create(
                    name=service_needed or 'Unnamed Job',  # Use Service Needed as name
                    status='pending',
                    price=price,
                    assigned_to=None,  # Initially unassigned
                    service_area=service_area,
                    service_needed=service_needed,
                    service_request_message=validated_data.get('Service_Request_Message', ''),
                    contact_id=validated_data.get('contact_id', ''),
                    first_name=validated_data.get('first_name', ''),
                    last_name=validated_data.get('last_name', ''),
                    full_name=validated_data.get('full_name', ''),
                    email=validated_data.get('email', ''),
                    phone=validated_data.get('phone', ''),
                    address1=validated_data.get('address1', ''),
                    city=validated_data.get('city', ''),
                    state=validated_data.get('state', ''),
                    country=validated_data.get('country', ''),
                    postal_code=validated_data.get('postal_code', ''),
                    company_name=validated_data.get('company_name', ''),
                    service_industry=service_industry
                )
                
                logger.info(
                    f"Job created via webhook: {job.service_needed} - Service Area: {job.service_area} - Price: {job.price}"
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
    """View to get all pending jobs matching user's service areas, industries, and pincodes"""
    permission_classes = [IsAuthenticatedUser]
    
    def get(self, request):
        """Get all pending jobs that match user's criteria and not rejected by current user"""
        try:
            # Get user profile
            try:
                profile = request.user.profile
            except UserProfile.DoesNotExist:
                return Response(
                    {'error': 'User profile not found. Please complete your profile.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get IDs of jobs rejected by current user
            rejected_job_ids = JobRejection.objects.filter(
                user=request.user
            ).values_list('job_id', flat=True)
            
            # Get user's service areas, industries, and pincodes
            user_service_areas = profile.service_areas.values_list('name', flat=True)
            user_service_industries = profile.service_industries.values_list('name', flat=True)
            user_pincodes = [str(pincode) for pincode in profile.pincodes] if profile.pincodes else []
            
            # Start with pending, unassigned jobs, excluding rejected ones
            pending_jobs = Job.objects.filter(
                status='pending',
                assigned_to__isnull=True
            ).exclude(id__in=rejected_job_ids)
            
            # Filter jobs that match user's criteria
            matching_jobs = []
            for job in pending_jobs:
                # Check service area match
                service_area_match = False
                if job.service_area:
                    if job.service_area in user_service_areas:
                        service_area_match = True
                else:
                    # If job has no service area, consider it a match
                    service_area_match = True
                
                # Check service needed (industry) match
                service_needed_match = False
                if job.service_needed:
                    if job.service_needed in user_service_industries:
                        service_needed_match = True
                else:
                    # If job has no service needed, consider it a match
                    service_needed_match = True
                
                # Check postal code match
                postal_code_match = False
                if job.postal_code:
                    if job.postal_code in user_pincodes:
                        postal_code_match = True
                else:
                    # If job has no postal code, consider it a match
                    postal_code_match = True
                
                # Job matches if all criteria match (or are empty)
                if service_area_match and service_needed_match and postal_code_match:
                    matching_jobs.append(job)
            
            # Order by creation date (newest first)
            matching_jobs.sort(key=lambda x: x.created_at, reverse=True)
            
            serializer = JobSerializer(matching_jobs, many=True)
            return Response({
                'jobs': serializer.data,
                'count': len(matching_jobs)
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
            
            # Get the price from service industry (if available) or use job price
            job_price = job.price
            if job.service_industry:
                job_price = job.service_industry.price
                # Also verify the user has this service industry
                if job.service_industry not in profile.service_industries.all():
                    return Response(
                        {
                            'error': f'You do not have access to service industry: {job.service_industry.name}'
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Check if user has sufficient wallet balance
            if profile.wallet_balance < job_price:
                return Response(
                    {
                        'error': 'Insufficient wallet balance.',
                        'required': str(job_price),
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
                
                # Get the price from service industry (if available) or use job price
                job_price = job.price
                if job.service_industry:
                    job_price = job.service_industry.price
                
                # Re-check wallet balance (in case it changed)
                if profile.wallet_balance < job_price:
                    return Response(
                        {
                            'error': 'Insufficient wallet balance.',
                            'required': str(job_price),
                            'current_balance': str(profile.wallet_balance)
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Assign job to user and update status
                old_balance = profile.wallet_balance
                job.assigned_to = request.user
                job.status = 'accepted'
                job.save()
                
                # Deduct price from wallet (use service industry price)
                profile.wallet_balance -= job_price
                profile.save(update_fields=['wallet_balance'])
                
                logger.info(
                    f"Job {job.id} ({job.service_needed}) accepted by user {request.user.email}. "
                    f"Price deducted: {job_price} (from service industry: {job.service_industry.name if job.service_industry else 'N/A'}). "
                    f"Old balance: {old_balance}, New balance: {profile.wallet_balance}"
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
            
            # Get final price used
            final_price = job.service_industry.price if job.service_industry else job.price
            
            return Response({
                'success': True,
                'message': 'Job accepted successfully',
                'job': JobSerializer(job).data,
                'wallet_balance': str(profile.wallet_balance),
                'amount_deducted': str(final_price)
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
                f"Job {job.id} ({job.service_needed or job.name}) status updated from {old_status} to {new_status} by user {request.user.email}"
            )
            
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