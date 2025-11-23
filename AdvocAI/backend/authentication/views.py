from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from mongoengine import DoesNotExist
from .models import User, ChatConversation, ChatMessage, LawyerProfile, LawyerConnectionRequest
import random
import cloudinary
import cloudinary.uploader

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserSerializer,
    GoogleAuthSerializer,
    ChatMessageSerializer,
    ChatConversationSerializer,
    VerifyOTPSerializer,
    ResendOTPSerializer,
    UserProfileSerializer,
    LawyerProfileSerializer,
    LawyerConnectionRequestSerializer,
    LawyerConnectionStatusSerializer,
    ForgotPasswordSerializer, # Import ForgotPasswordSerializer
    ResetPasswordSerializer,  # Import ResetPasswordSerializer
)
from datetime import datetime
from uuid import uuid4
from .otp_utils import create_and_send_otp, is_otp_valid, clear_otp

def get_tokens_for_user(user):
    """Generate JWT tokens for a MongoEngine user"""
    refresh = RefreshToken()
    refresh['user_id'] = str(user.id)
    refresh['email'] = user.email
    
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    """Register new user and send OTP for verification"""
    try:
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # User is not verified yet, send OTP
            user.is_verified = False
            user.save()
            
            # Generate and send OTP
            otp_sent = create_and_send_otp(user)
            
            if not otp_sent:
                return Response({
                    'error': 'Failed to send OTP. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            response_payload = {
                'message': 'Registration successful. OTP sent to your email. Please verify to continue.',
                'email': user.email,
                'requires_verification': True,
                'redirect': 'verify-otp',
                'role': user.role,
                'lawyer_verification_status': user.lawyer_verification_status,
            }
            if user.role == 'lawyer':
                response_payload['lawyer_message'] = 'Your lawyer profile is pending verification. Our team will review your credentials shortly.'
            return Response(response_payload, status=status.HTTP_201_CREATED)
        return Response({
            'error': 'Validation failed',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({
            'error': 'An error occurred during registration',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Login user with email and password"""
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    
    try:
        user = User.objects(email=email).first()
        if not user:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
    except DoesNotExist:
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Check if user registered with Google
    if user.auth_provider == 'google':
        return Response({
            'error': 'This account is registered with Google. Please use Google Sign In.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Authenticate user
    user = authenticate(email=email, password=password)
    if user is None:
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Check if user is verified
    if not user.is_verified:
        # Send OTP for verification
        otp_sent = create_and_send_otp(user)
        
        if not otp_sent:
            return Response({
                'error': 'Failed to send OTP. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'message': 'OTP sent to your email. Please verify to continue.',
            'email': user.email,
            'requires_verification': True,
            'redirect': 'verify-otp'
        }, status=status.HTTP_200_OK)
    
    # User is verified, return tokens
    tokens = get_tokens_for_user(user)
    user_data = UserSerializer(user).data
    
    return Response({
        'message': 'Login successful',
        'user': user_data,
        'tokens': tokens,
        'redirect': 'home'
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def google_auth_view(request):
    """Authenticate user with Google OAuth"""
    # Check if Google Client ID is configured
    if not settings.GOOGLE_CLIENT_ID:
        return Response({
            'error': 'Google Client ID is not configured. Please set the GOOGLE_CLIENT_ID environment variable in your .env file or system environment.',
            'solution': '1. Create a .env file in your project root\n2. Add GOOGLE_CLIENT_ID=your_client_id_here\n3. Restart your Django server'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    serializer = GoogleAuthSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    token = serializer.validated_data['token']
    
    try:
        # Verify the Google token
        idinfo = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            settings.GOOGLE_CLIENT_ID
        )
        
        # Get user info from Google
        email = idinfo.get('email')
        google_id = idinfo.get('sub')
        name = idinfo.get('name', '')
        
        if not email:
            return Response({
                'error': 'Email not provided by Google'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user exists
        user = None
        try:
            user = User.objects(email=email).first()
            if user:
                # Update Google ID if not set
                if not user.google_id:
                    user.google_id = google_id
                    user.auth_provider = 'google'
                    user.is_verified = True  # Google users are auto-verified
                    user.save()
        except DoesNotExist:
            user = None
        
        if not user:
            # Create new user
            username = email.split('@')[0]
            # Ensure username is unique
            base_username = username
            counter = 1
            while User.objects(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User.create_user(
                email=email,
                username=username,
                name=name,
                google_id=google_id,
                auth_provider='google',
                password='!'  # Unusable password for OAuth users
            )
            user.is_verified = True  # Google users are auto-verified
            user.save()
        
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        
        return Response({
            'message': 'Google authentication successful',
            'user': user_data,
            'tokens': tokens,
            'redirect': 'home'  # Frontend should redirect to home page
        }, status=status.HTTP_200_OK)
        
    except ValueError as e:
        error_message = str(e)
        if 'aud' in error_message:
            error_message = 'Invalid Google client ID'
        elif 'exp' in error_message:
            error_message = 'Google token has expired'
        return Response({
            'error': 'Invalid Google token',
            'details': error_message
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def profile_detail_update_view(request):
    """Get or update authenticated user profile"""
    user = request.user
    
    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    elif request.method == 'PATCH':
        data = request.data.copy() # Make a mutable copy of request.data
        
        # Handle profile picture upload
        profile_picture_file = request.FILES.get('profile_picture')
        if profile_picture_file:
            try:
                # Upload to Cloudinary
                upload_result = cloudinary.uploader.upload(profile_picture_file)
                data['profile_picture'] = upload_result['secure_url'] # Add the URL to the data for the serializer
            except Exception as e:
                return Response({
                    'error': f'Failed to upload profile picture: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Handle cover photo upload
        cover_photo_file = request.FILES.get('cover_photo')
        if cover_photo_file:
            try:
                # Upload to Cloudinary
                upload_result = cloudinary.uploader.upload(cover_photo_file)
                data['cover_photo'] = upload_result['secure_url'] # Add the URL to the data for the serializer
            except Exception as e:
                return Response({
                    'error': f'Failed to upload cover photo: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        # Handle other profile data (e.g., name)
        serializer = UserProfileSerializer(user, data=data, partial=True) # Pass the modified data
        if serializer.is_valid():
            serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp_view(request):
    """Verify OTP and activate user account"""
    serializer = VerifyOTPSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    otp = serializer.validated_data['otp_code']
    
    try:
        user = User.objects(email=email).first()
        if not user:
            return Response({
                'error': 'User not found.'
            }, status=status.HTTP_404_NOT_FOUND)
    except DoesNotExist:
        return Response({
            'error': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)
        
    if is_otp_valid(user, otp):
        user.is_verified = True
        user.save()
        clear_otp(user) # Clear OTP after successful verification
        
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        
        return Response({
            'message': 'Account verified successfully.',
            'user': user_data,
            'tokens': tokens,
            'redirect': 'home'
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Invalid or expired OTP.'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def resend_otp_view(request):
    """Resend OTP to user's email"""
    serializer = ResendOTPSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects(email=email).first()
        if not user:
            return Response({
                'error': 'User not found.'
            }, status=status.HTTP_404_NOT_FOUND)
    except DoesNotExist:
        return Response({
            'error': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)
        
    if user.is_verified:
        return Response({
            'message': 'User is already verified.' 
        }, status=status.HTTP_400_BAD_REQUEST)
        
    otp_sent = create_and_send_otp(user)
    
    if otp_sent:
        return Response({
            'message': 'New OTP sent to your email.'
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Failed to send OTP. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout user by blacklisting the refresh token"""
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def lawyer_list_view(request):
    """List approved lawyers with optional specialization filter"""
    specialization = request.query_params.get('specialization', '').strip()
    profiles = LawyerProfile.objects(verification_status='approved')
    
    if specialization:
        profiles = profiles.filter(specializations__icontains=specialization)
    
    serializer = LawyerProfileSerializer(profiles, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def lawyer_detail_view(request, lawyer_id):
    """Retrieve lawyer detail"""
    try:
        user = User.objects(id=lawyer_id, role='lawyer').first()
    except DoesNotExist:
        user = None
    if not user:
        return Response({'error': 'Lawyer not found.'}, status=status.HTTP_404_NOT_FOUND)

    profile = LawyerProfile.objects(user=user).first()
    if not profile:
        return Response({'error': 'Lawyer profile not found.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = LawyerProfileSerializer(profile)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def connect_with_lawyer_view(request, lawyer_id):
    """Create a connection request with a lawyer"""
    if str(request.user.id) == lawyer_id:
        return Response({'error': 'You cannot connect with yourself.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        lawyer = User.objects(id=lawyer_id, role='lawyer').first()
    except DoesNotExist:
        lawyer = None

    if not lawyer:
        return Response({'error': 'Lawyer not found.'}, status=status.HTTP_404_NOT_FOUND)

    profile = LawyerProfile.objects(user=lawyer).first()
    if not profile:
        return Response({'error': 'Lawyer is not available for connections yet.'}, status=status.HTTP_400_BAD_REQUEST)

    existing_request = LawyerConnectionRequest.objects(
        client=request.user, lawyer=lawyer, status='pending'
    ).first()
    if existing_request:
        serializer = LawyerConnectionRequestSerializer(existing_request)
        return Response({
            'message': 'You already have a pending connection request with this lawyer.',
            'request': serializer.data
        }, status=status.HTTP_200_OK)

    message = request.data.get('message', '').strip()
    preferred_method = request.data.get('preferred_contact_method', 'email')
    preferred_value = request.data.get('preferred_contact_value', request.user.email)
    preferred_time_str = request.data.get('preferred_time')
    meeting_link = request.data.get('meeting_link')

    preferred_time = None
    if preferred_time_str:
        try:
            preferred_time = datetime.fromisoformat(preferred_time_str.replace('Z', '+00:00'))
        except ValueError:
            return Response({'error': 'Invalid preferred time format. Use ISO 8601 format.'}, status=status.HTTP_400_BAD_REQUEST)

    if not meeting_link:
        meeting_link = f"https://meet.google.com/new?hs=224&authuser=0&advocai={uuid4().hex[:8]}"

    connection_request = LawyerConnectionRequest.objects.create(
        client=request.user,
        lawyer=lawyer,
        message=message,
        preferred_contact_method=preferred_method,
        preferred_contact_value=preferred_value,
        preferred_time=preferred_time,
        meeting_link=meeting_link,
    )

    serializer = LawyerConnectionRequestSerializer(connection_request)
    return Response({
        'message': 'Connection request submitted successfully.',
        'request': serializer.data,
        'meeting_link': meeting_link,
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def lawyer_dashboard_view(request):
    """Return dashboard information for a lawyer"""
    if not request.user.is_lawyer:
        return Response({'error': 'Access denied.'}, status=status.HTTP_403_FORBIDDEN)

    profile = LawyerProfile.objects(user=request.user).first()
    profile_data = LawyerProfileSerializer(profile).data if profile else None

    connection_requests = LawyerConnectionRequest.objects(lawyer=request.user).order_by('-created_at')
    connection_serializer = LawyerConnectionRequestSerializer(connection_requests, many=True)

    summary = {
        'total_requests': connection_requests.count(),
        'pending_requests': connection_requests.filter(status='pending').count(),
        'accepted_requests': connection_requests.filter(status='accepted').count(),
        'declined_requests': connection_requests.filter(status='declined').count(),
    }

    return Response({
        'profile': profile_data,
        'user': UserSerializer(request.user).data,
        'connections': connection_serializer.data,
        'summary': summary,
    }, status=status.HTTP_200_OK)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def lawyer_connection_update_view(request, connection_id):
    """Allow lawyer to update connection request status"""
    if not request.user.is_lawyer:
        return Response({'error': 'Access denied.'}, status=status.HTTP_403_FORBIDDEN)

    connection_request = LawyerConnectionRequest.objects(id=connection_id, lawyer=request.user).first()
    if not connection_request:
        return Response({'error': 'Connection request not found.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = LawyerConnectionStatusSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    new_status = serializer.validated_data['status']
    connection_request.status = new_status
    connection_request.message = serializer.validated_data.get('message', connection_request.message)
    connection_request.save()

    # Create chat conversation when lawyer accepts
    if new_status == 'accepted':
        existing_chat = ChatConversation.objects(
            connection_request=connection_request
        ).first()
        if not existing_chat:
            try:
                chat_conversation = ChatConversation.objects.create(
                    connection_request=connection_request,
                    client=connection_request.client,
                    lawyer=connection_request.lawyer,
                    is_active=True,
                )
                print(f"Created chat conversation {chat_conversation.id} for connection {connection_request.id}")
                
                # Send welcome message
                welcome_msg = f"Connection accepted! You can now chat with {connection_request.client.name or connection_request.client.username}."
                ChatMessage.objects.create(
                    conversation=chat_conversation,
                    sender=request.user,
                    message=welcome_msg,
                    message_type='system',
                )
                print(f"Created welcome message for conversation {chat_conversation.id}")
            except Exception as e:
                print(f"Error creating chat conversation: {e}")
                import traceback
                traceback.print_exc()

    response_serializer = LawyerConnectionRequestSerializer(connection_request)
    return Response({
        'message': f'Connection request {new_status}.',
        'request': response_serializer.data,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Send OTP for password reset"""
    serializer = ForgotPasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects(email=email).first()
        if not user:
            return Response({
                'error': 'User with this email does not exist.'
            }, status=status.HTTP_404_NOT_FOUND)
    except DoesNotExist:
        return Response({
            'error': 'User with this email does not exist.'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Check if user registered with Google
    if user.auth_provider == 'google':
        return Response({
            'error': 'This account is registered with Google. Please use Google Sign In. Password reset is not available for Google accounts.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate and send OTP for password reset
    otp_sent = create_and_send_otp(user)
    
    if not otp_sent:
        return Response({
            'error': 'Failed to send OTP. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({
        'message': 'OTP sent to your email for password reset.',
        'email': user.email
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    """Reset user password with OTP verification"""
    serializer = ResetPasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    otp = serializer.validated_data['otp_code']
    new_password = serializer.validated_data['new_password']
    
    try:
        user = User.objects(email=email).first()
        if not user:
            return Response({
                'error': 'User not found.'
            }, status=status.HTTP_404_NOT_FOUND)
    except DoesNotExist:
        return Response({
            'error': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Check if user registered with Google
    if user.auth_provider == 'google':
        return Response({
            'error': 'This account is registered with Google. Password reset is not available.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Verify OTP
    if not is_otp_valid(user, otp):
        return Response({
            'error': 'Invalid or expired OTP.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Reset password
    user.set_password(new_password)
    user.save()
    clear_otp(user)  # Clear OTP after successful reset
    
    return Response({
        'message': 'Password reset successfully. Please login with your new password.'
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_conversations_list_view(request):
    """List all chat conversations for the authenticated user"""
    user = request.user
    connection_request_id = request.query_params.get('connection_request_id')
    
    if connection_request_id:
        # Get conversation by connection request ID
        from .models import LawyerConnectionRequest
        try:
            connection_request = LawyerConnectionRequest.objects(id=connection_request_id).first()
            if not connection_request:
                return Response({'error': 'Connection request not found.'}, status=status.HTTP_404_NOT_FOUND)
            
            conversation = ChatConversation.objects(
                connection_request=connection_request,
                is_active=True
            ).first()
        except Exception as e:
            return Response({'error': f'Invalid connection request ID: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not conversation:
            if connection_request.status != 'accepted':
                return Response({'error': 'Connection request is not accepted yet.'}, status=status.HTTP_400_BAD_REQUEST)
            # Create the conversation on demand
            conversation = ChatConversation.objects.create(
                connection_request=connection_request,
                client=connection_request.client,
                lawyer=connection_request.lawyer,
                is_active=True,
            )
            ChatMessage.objects.create(
                conversation=conversation,
                sender=request.user,
                message='Conversation started.',
                message_type='system',
            )
        
        if not conversation:
            return Response({'error': 'Conversation not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user is part of the conversation
        if str(conversation.client.id) != str(user.id) and str(conversation.lawyer.id) != str(user.id):
            return Response({'error': 'Access denied.'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ChatConversationSerializer(conversation, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    # List all conversations for the user
    # Get all conversations and filter in Python (more reliable with MongoEngine ReferenceFields)
    all_conversations = ChatConversation.objects(is_active=True).order_by('-updated_at')
    user_conversations = []
    user_id_str = str(user.id)
    
    for conv in all_conversations:
        try:
            client_id = str(conv.client.id) if conv.client else None
            lawyer_id = str(conv.lawyer.id) if conv.lawyer else None
            
            if client_id == user_id_str or lawyer_id == user_id_str:
                user_conversations.append(conv)
        except Exception as e:
            # Skip conversations with invalid references
            print(f"Error processing conversation {conv.id}: {e}")
            continue
    
    serializer = ChatConversationSerializer(user_conversations, many=True, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def chat_messages_view(request, conversation_id):
    """Get messages for a conversation or send a new message"""
    conversation = ChatConversation.objects(id=conversation_id).first()
    if not conversation:
        return Response({'error': 'Conversation not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    # Check if user is part of the conversation
    user = request.user
    if str(conversation.client.id) != str(user.id) and str(conversation.lawyer.id) != str(user.id):
        return Response({'error': 'Access denied.'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.method == 'GET':
        messages = ChatMessage.objects(conversation=conversation).order_by('created_at')
        print(f"Found {messages.count()} messages for conversation {conversation_id}")
        
        serializer = ChatMessageSerializer(messages, many=True)
        print(f"Serialized {len(serializer.data)} messages")
        
        # Mark messages as read (exclude messages sent by current user)
        unread_messages = ChatMessage.objects(
            conversation=conversation,
            is_read=False
        )
        for msg in unread_messages:
            if str(msg.sender.id) != str(user.id):
                msg.is_read = True
                msg.save()
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    elif request.method == 'POST':
        message_text = request.data.get('message', '').strip()
        message_type = request.data.get('message_type', 'text')
        document_id = request.data.get('document_id', '')
        document_title = request.data.get('document_title', '')
        
        if not message_text and message_type != 'document':
            return Response({'error': 'Message cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if message_type == 'document' and not document_id:
            return Response({'error': 'Document ID is required for document messages.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            chat_message = ChatMessage.objects.create(
                conversation=conversation,
                sender=user,
                message=message_text or f'Shared document: {document_title}',
                message_type=message_type,
                document_id=document_id,
                document_title=document_title,
                is_read=False,
            )
            print(f"Created message {chat_message.id} in conversation {conversation_id}")
            print(f"Message content: {chat_message.message}")
            print(f"Sender: {chat_message.sender.id}")
            
            # Update conversation timestamp
            conversation.save()
            
            serializer = ChatMessageSerializer(chat_message)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"Error creating message: {e}")
            import traceback
            traceback.print_exc()
            return Response({'error': f'Failed to create message: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
