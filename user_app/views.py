from rest_framework import status
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import LoginSerializer, UserSerializer, ServiceAreaSerializer, ServiceIndustrySerializer
from rest_framework.views import APIView
from rest_framework import viewsets
from .models import ServiceArea, ServiceIndustry



class IsAdminPermission(BasePermission):
    """Custom permission to only allow admins to access views"""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_staff
    


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