from rest_framework import serializers
from .models import User, LawyerProfile, LawyerConnectionRequest
from django.contrib.auth.password_validation import validate_password

class UserSerializer(serializers.Serializer):
    """Serializer for User MongoEngine Document"""
    id = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
    username = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)
    profile_picture = serializers.URLField(read_only=True)
    cover_photo = serializers.URLField(read_only=True) # Added cover_photo
    auth_provider = serializers.CharField(read_only=True)
    date_joined = serializers.DateTimeField(read_only=True)
    
    def to_representation(self, instance):
        """Convert MongoEngine document to dict"""
        return {
            'id': str(instance.id),
            'email': instance.email,
            'username': instance.username,
            'name': instance.name,
            'profile_picture': instance.profile_picture,
            'cover_photo': instance.cover_photo, # Added cover_photo
            'auth_provider': instance.auth_provider,
            'date_joined': instance.date_joined,
            'phone': instance.phone,
            'role': instance.role,
            'is_verified': instance.is_verified,
            'is_lawyer_verified': instance.is_lawyer_verified,
            'lawyer_verification_status': instance.lawyer_verification_status
        }

class RegisterSerializer(serializers.Serializer):
    """Serializer for user registration"""
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True, max_length=150)
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(choices=[('client', 'Client'), ('lawyer', 'Lawyer')], default='client')
    phone = serializers.CharField(required=False, allow_blank=True, max_length=20)
    license_number = serializers.CharField(required=False, allow_blank=True, max_length=120)
    bar_council_id = serializers.CharField(required=False, allow_blank=True, max_length=120)
    education = serializers.CharField(required=False, allow_blank=True, max_length=255)
    experience_years = serializers.IntegerField(required=False, min_value=0)
    law_firm = serializers.CharField(required=False, allow_blank=True, max_length=255)
    specializations = serializers.ListField(
        child=serializers.CharField(max_length=120),
        required=False,
        allow_empty=True
    )
    consultation_fee = serializers.CharField(required=False, allow_blank=True, max_length=120)
    bio = serializers.CharField(required=False, allow_blank=True)
    verification_documents = serializers.ListField(
        child=serializers.CharField(max_length=512),
        required=False,
        allow_empty=True
    )
    
    def validate_email(self, value):
        """Check if email already exists"""
        if User.objects(email=value).first():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate_username(self, value):
        """Check if username already exists"""
        if User.objects(username=value).first():
            raise serializers.ValidationError("A user with this username already exists.")
        return value
    
    def validate_specializations(self, value):
        if isinstance(value, str):
            items = [item.strip() for item in value.split(',') if item.strip()]
            return items
        return value or []

    def validate_verification_documents(self, value):
        if isinstance(value, str):
            items = [item.strip() for item in value.split(',') if item.strip()]
            return items
        return value or []

    def validate_experience_years(self, value):
        if value in (None, ''):
            return 0
        return value

    def validate(self, attrs):
        """Validate password match"""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        role = attrs.get('role', 'client')
        if role == 'lawyer':
            missing_fields = []
            mandatory_fields = {
                'license_number': attrs.get('license_number', '').strip(),
                'bar_council_id': attrs.get('bar_council_id', '').strip(),
            }
            if not mandatory_fields['license_number']:
                missing_fields.append('license_number')
            if not mandatory_fields['bar_council_id']:
                missing_fields.append('bar_council_id')
            if missing_fields:
                error_dict = {field: 'This field is required for lawyer registration.' for field in missing_fields}
                raise serializers.ValidationError(error_dict)
        return attrs
    
    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password2')
        role = validated_data.pop('role', 'client')
        phone = validated_data.pop('phone', '')
        license_number = validated_data.pop('license_number', '')
        bar_council_id = validated_data.pop('bar_council_id', '')
        education = validated_data.pop('education', '')
        experience_years = validated_data.pop('experience_years', 0)
        law_firm = validated_data.pop('law_firm', '')
        specializations = validated_data.pop('specializations', []) or []
        consultation_fee = validated_data.pop('consultation_fee', '')
        bio = validated_data.pop('bio', '')
        verification_documents = validated_data.pop('verification_documents', []) or []

        user = User.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            name=validated_data.get('name', ''),
            password=validated_data['password'],
            role=role,
            phone=phone,
        )

        if role == 'lawyer':
            user.lawyer_verification_status = 'pending'
            user.is_lawyer_verified = False
            user.save()
            LawyerProfile.objects(user=user).delete()
            LawyerProfile.objects.create(
                user=user,
                phone=phone,
                education=education,
                experience_years=experience_years or 0,
                law_firm=law_firm,
                specializations=specializations,
                license_number=license_number,
                bar_council_id=bar_council_id,
                consultation_fee=consultation_fee,
                bio=bio,
                verification_documents=verification_documents,
                verification_status='pending',
            )
        else:
            user.lawyer_verification_status = 'not_applicable'
            user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class GoogleAuthSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp_code = serializers.CharField(required=True, max_length=6, min_length=6)

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class UserProfileSerializer(serializers.Serializer):
    """Serializer for updating user profile"""
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    profile_picture = serializers.URLField(required=False, allow_blank=True, max_length=255)
    cover_photo = serializers.URLField(required=False, allow_blank=True, max_length=255) # Added cover_photo

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
        instance.cover_photo = validated_data.get('cover_photo', instance.cover_photo) # Added cover_photo
        instance.save()
        return instance


class LawyerProfileSerializer(serializers.Serializer):
    """Serializer for lawyer public profile"""

    id = serializers.CharField(read_only=True)
    user = UserSerializer(read_only=True)
    phone = serializers.CharField(read_only=True)
    education = serializers.CharField(read_only=True)
    experience_years = serializers.IntegerField(read_only=True)
    law_firm = serializers.CharField(read_only=True)
    specializations = serializers.ListField(child=serializers.CharField(), read_only=True)
    license_number = serializers.CharField(read_only=True)
    bar_council_id = serializers.CharField(read_only=True)
    consultation_fee = serializers.CharField(read_only=True)
    bio = serializers.CharField(read_only=True)
    verification_status = serializers.CharField(read_only=True)
    verification_notes = serializers.CharField(read_only=True)

    def to_representation(self, instance):
        user_data = UserSerializer(instance.user).data if instance.user else None
        return {
            'id': str(instance.id),
            'user': user_data,
            'phone': instance.phone,
            'education': instance.education,
            'experience_years': instance.experience_years,
            'law_firm': instance.law_firm,
            'specializations': instance.specializations,
            'license_number': instance.license_number,
            'bar_council_id': instance.bar_council_id,
            'consultation_fee': instance.consultation_fee,
            'bio': instance.bio,
            'verification_status': instance.verification_status,
            'verification_notes': instance.verification_notes,
            'verification_documents': instance.verification_documents,
        }


class LawyerConnectionRequestSerializer(serializers.Serializer):
    """Serializer for lawyer connection requests"""

    id = serializers.CharField(read_only=True)
    client = UserSerializer(read_only=True)
    lawyer = UserSerializer(read_only=True)
    message = serializers.CharField(required=False, allow_blank=True)
    status = serializers.CharField(read_only=True)
    preferred_contact_method = serializers.CharField(required=False, allow_blank=True)
    preferred_contact_value = serializers.CharField(required=False, allow_blank=True)
    preferred_time = serializers.DateTimeField(required=False, allow_null=True)
    meeting_link = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    def to_representation(self, instance):
        return {
            'id': str(instance.id),
            'client': UserSerializer(instance.client).data if instance.client else None,
            'lawyer': UserSerializer(instance.lawyer).data if instance.lawyer else None,
            'message': instance.message,
            'status': instance.status,
            'preferred_contact_method': instance.preferred_contact_method,
            'preferred_contact_value': instance.preferred_contact_value,
            'preferred_time': instance.preferred_time.isoformat() if instance.preferred_time else None,
            'meeting_link': instance.meeting_link,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'updated_at': instance.updated_at.isoformat() if instance.updated_at else None,
        }


class LawyerConnectionStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=['accepted', 'declined'])
    message = serializers.CharField(required=False, allow_blank=True)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp_code = serializers.CharField(required=True, max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "New passwords didn't match."})
        return attrs


class ChatMessageSerializer(serializers.Serializer):
    """Serializer for chat messages"""
    id = serializers.CharField(read_only=True)
    sender = serializers.SerializerMethodField()
    message = serializers.CharField()
    message_type = serializers.CharField()
    document_id = serializers.CharField(allow_blank=True)
    document_title = serializers.CharField(allow_blank=True)
    is_read = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    
    def get_sender(self, obj):
        from .models import User
        try:
            # Try to get sender from the object
            if hasattr(obj, 'sender') and obj.sender:
                sender = obj.sender
                # If it's a reference, fetch it
                if hasattr(sender, 'id'):
                    return {
                        'id': str(sender.id),
                        'name': sender.name or sender.username or 'Unknown',
                        'username': sender.username or 'unknown',
                    }
            # Fallback: try to get by ID if sender is stored as ID
            if hasattr(obj, 'sender_id') and obj.sender_id:
                sender = User.objects(id=obj.sender_id).first()
                if sender:
                    return {
                        'id': str(sender.id),
                        'name': sender.name or sender.username or 'Unknown',
                        'username': sender.username or 'unknown',
                    }
        except Exception as e:
            print(f"Error getting sender: {e}")
        return {'id': 'unknown', 'name': 'Unknown', 'username': 'unknown'}
    
    def to_representation(self, instance):
        """Ensure all keys are strings and properly serialize data"""
        data = super().to_representation(instance)
        # Ensure all keys are strings and handle datetime serialization
        result = {}
        for k, v in data.items():
            key = str(k)
            # Handle datetime objects that might not be serialized
            if hasattr(v, 'isoformat'):
                result[key] = v.isoformat() if v else None
            elif isinstance(v, dict):
                # Recursively ensure nested dict keys are strings
                result[key] = {str(k2): v2 for k2, v2 in v.items()}
            else:
                result[key] = v
        return result


class ChatConversationSerializer(serializers.Serializer):
    """Serializer for chat conversations"""
    id = serializers.CharField(read_only=True)
    connection_request_id = serializers.SerializerMethodField()
    client = serializers.SerializerMethodField()
    lawyer = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    
    def get_connection_request_id(self, obj):
        if hasattr(obj, 'connection_request') and obj.connection_request:
            return str(obj.connection_request.id)
        return None
    
    def get_client(self, obj):
        from .models import User
        client = obj.client if hasattr(obj, 'client') else User.objects(id=obj.client).first()
        if client:
            return {
                'id': str(client.id),
                'name': client.name or client.username,
                'username': client.username,
            }
        return None
    
    def get_lawyer(self, obj):
        from .models import User
        lawyer = obj.lawyer if hasattr(obj, 'lawyer') else User.objects(id=obj.lawyer).first()
        if lawyer:
            return {
                'id': str(lawyer.id),
                'name': lawyer.name or lawyer.username,
                'username': lawyer.username,
            }
        return None
    
    def get_last_message(self, obj):
        from .models import ChatMessage
        last_msg = ChatMessage.objects(conversation=obj).order_by('-created_at').first()
        if last_msg:
            serializer = ChatMessageSerializer(last_msg)
            return serializer.data
        return None
    
    def get_unread_count(self, obj):
        from .models import ChatMessage
        request = self.context.get('request')

        if request and request.user:
            unread = ChatMessage.objects(
                conversation=obj,
                is_read=False,
                sender__ne=request.user
            ).count()
            return unread

        return 0

    
    def to_representation(self, instance):
        """Ensure all keys are strings and handle nested structures"""
        data = super().to_representation(instance)
        # Ensure all keys are strings and handle nested structures
        result = {}
        for k, v in data.items():
            key = str(k)
            # Handle datetime objects
            if hasattr(v, 'isoformat'):
                result[key] = v.isoformat() if v else None
            elif isinstance(v, dict):
                # Recursively ensure nested dict keys are strings
                result[key] = {str(k2): v2 for k2, v2 in v.items()}
            elif isinstance(v, list):
                # Handle lists that might contain dicts
                result[key] = [
                    {str(k2): v2 for k2, v2 in item.items()} if isinstance(item, dict) else item
                    for item in v
                ]
            else:
                result[key] = v
        return result
