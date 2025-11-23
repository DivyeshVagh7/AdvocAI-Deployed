from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.conf import settings
from .models import DocumentSession, ChatMessage
from authentication.models import User
import fitz  # PyMuPDF for PDF
from docx import Document
from mongoengine import DoesNotExist

import google.generativeai as genai # Import Google Generative AI client

# Initialize Gemini client
def get_gemini_client():
    if not settings.GEMINI_API_KEY:
        class MockPart:
            def __init__(self, text):
                self.text = text
        class MockContent:
            def __init__(self, text):
                self.parts = [MockPart(text)]
        class MockCandidate:
            def __init__(self, text):
                self.content = MockContent(text)
        class MockGenerateContentResponse:
            def __init__(self, text="This is a mock response from the AI."):
                self.candidates = [MockCandidate(text)]
        class MockGenerativeModel:
            def generate_content(self, contents, **kwargs):
                return MockGenerateContentResponse()
        class MockGenai:
            def __init__(self):
                self.GenerativeModel = MockGenerativeModel
        return MockGenai()
        
    genai.configure(api_key=settings.GEMINI_API_KEY)
    return genai

def extract_text_from_file(uploaded_file):
    """Extract text depending on file type."""
    if uploaded_file.name.endswith('.pdf'):
        try:
            text = ""
            with fitz.open(stream=uploaded_file.read(), filetype="pdf") as doc:
                for page in doc:
                    text += page.get_text()
            return text
        except fitz.FileDataError as e:
            return None
        except Exception as e:
            raise Exception(f"Error extracting text from PDF: {str(e)}")

    elif uploaded_file.name.endswith('.docx'):
        doc = Document(uploaded_file)
        return "\n".join([p.text for p in doc.paragraphs])

    elif uploaded_file.name.endswith('.txt'):
        return uploaded_file.read().decode('utf-8')

    else:
        return None

def summarize_legal_doc(text):
    """Use Gemini API to summarize legal text."""
    try:
        genai_client = get_gemini_client()
        model = genai_client.GenerativeModel('gemini-flash-lite-latest')
        
        messages = [
            {"role": "user", "parts": [f"You are a legal assistant. Summarize legal documents clearly and concisely, focusing on key clauses, parties involved, and any obligations or penalties. Summarize the following legal document:\n\nDocument:\n{text[:10000]}"]} # limit input
        ]

        chat_completion = model.generate_content(
            messages,
            generation_config=genai_client.types.GenerationConfig(
                temperature=0.0, # Lower temperature for summarization
                max_output_tokens=1000, # Limit summary length
            ),
            request_options={'timeout': 60} # Increase timeout to 60 seconds
        )
        return chat_completion.candidates[0].content.parts[0].text
    except Exception as e:
        raise Exception(f"Error generating summary with Gemini API: {str(e)}")

def chat_with_document(session, user_message):
    """Use Gemini API to answer questions about the document."""
    try:
        genai_client = get_gemini_client()
        model = genai_client.GenerativeModel('gemini-flash-lite-latest')
        
        # Get chat history for context
        recent_messages = ChatMessage.objects(session=session).order_by('created_at')[:10]
        
        messages = [
            {"role": "user", "parts": [f"""You are a legal assistant helping a user understand a legal document.
Original Document (first 5000 characters):
{session.document_text[:5000]}
Document Summary:
{session.summary}
Please provide a helpful, accurate response based on the document content and summary.
If the question cannot be answered from the document, politely state that.
Keep your response clear and concise.
"""]}
        ]
        
        for msg in recent_messages:
            role = 'user' if msg.is_user else 'model' # Gemini uses 'model' for assistant
            messages.append({"role": role, "parts": [msg.message]})
            
        messages.append({"role": "user", "parts": [user_message]})

        chat_completion = model.generate_content(
            messages,
            generation_config=genai_client.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=500, # Limit response length
            ),
            request_options={'timeout': 60} # Increase timeout to 60 seconds
        )
        return chat_completion.candidates[0].content.parts[0].text
    except Exception as e:
        raise Exception(f"Error generating response with Gemini API: {str(e)}")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def summarize_document(request):
    """API endpoint for document summarization"""
    try:
        uploaded_file = request.FILES.get('document')
        if not uploaded_file:
            return Response({
                'error': 'Please upload a document'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check file size (limit to 10MB)
        if uploaded_file.size > 10 * 1024 * 1024:
            return Response({
                'error': 'File size exceeds 10MB limit.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Reset file pointer to beginning for reading content
        uploaded_file.seek(0)

        try:
            text = extract_text_from_file(uploaded_file)
            if text is None:
                return Response({
                    'error': 'Error extracting text from file.'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': f'Error extracting text from file: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        if not text:
            return Response({
                'error': 'Unsupported file type. Please upload PDF, DOCX, or TXT'
            }, status=status.HTTP_400_BAD_REQUEST)

        summary = summarize_legal_doc(text)
        
        # Get user from JWT token (request.user is already a User object from MongoEngineJWTAuthentication)
        user = request.user
        
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Create a new document session
        session = DocumentSession(
            user=user,
            document_text=text[:10000],  # Store first 10k chars
            summary=summary
        )
        session.save()
        
        return Response({
            'success': True,
            'summary': summary,
            'session_id': str(session.id),
            'filename': uploaded_file.name
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.views.decorators.csrf import csrf_exempt # Added csrf_exempt import

# ...

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def chat_message(request):
    """Handle chat messages"""
    try:
        user_message = request.data.get('message')
        session_id = request.data.get('session_id')
        
        if not user_message or not session_id:
            return Response({
                'error': 'Missing message or session_id'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get user from JWT token (request.user is already a User object)
        user = request.user
        
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get the document session and verify ownership
        try:
            session = DocumentSession.objects(id=session_id).first()
            if not session:
                return Response({
                    'error': 'Session not found'
                }, status=status.HTTP_404_NOT_FOUND)
                
            if str(session.user.id) != str(user.id):
                return Response({
                    'error': 'Access denied'
                }, status=status.HTTP_403_FORBIDDEN)
        except DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Save user message
        user_msg = ChatMessage(
            session=session,
            message=user_message,
            is_user=True
        )
        user_msg.save()
        
        # Get AI response
        ai_response = chat_with_document(session, user_message)
        
        # Save AI response
        ai_msg = ChatMessage(
            session=session,
            message=ai_response,
            is_user=False
        )
        ai_msg.save()
        
        return Response({
            'response': ai_response,
            'message_id': str(ai_msg.id)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_history(request, session_id):
    """Get chat history for a session"""
    try:
        # Get user from JWT token (request.user is already a User object)
        user = request.user
        
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        try:
            session = DocumentSession.objects(id=session_id).first()
            if not session:
                return Response({
                    'error': 'Session not found'
                }, status=status.HTTP_404_NOT_FOUND)
                
            if str(session.user.id) != str(user.id):
                return Response({
                    'error': 'Access denied'
                }, status=status.HTTP_403_FORBIDDEN)
        except DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        messages = ChatMessage.objects(session=session).order_by('created_at')
        
        messages_data = [
            {
                'id': str(msg.id),
                'message': msg.message,
                'is_user': msg.is_user,
                'timestamp': msg.created_at.isoformat()
            }
            for msg in messages
        ]
        
        return Response({
            'messages': messages_data,
            'session': {
                'id': str(session.id),
                'summary': session.summary,
                'created_at': session.created_at.isoformat()
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_sessions(request):
    """Get user's document sessions"""
    try:
        # Get user from JWT token (request.user is already a User object)
        user = request.user
        
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        sessions = DocumentSession.objects(user=user).order_by('-created_at')
        
        # Get message count for each session
        sessions_data = []
        for session in sessions:
            message_count = ChatMessage.objects(session=session).count()
            sessions_data.append({
                'id': str(session.id),
                'summary_preview': session.summary[:150] + '...' if len(session.summary) > 150 else session.summary,
                'created_at': session.created_at.isoformat(),
                'message_count': message_count,
                'document_preview': session.document_text[:100] + '...' if len(session.document_text) > 100 else session.document_text
            })
        
        return Response({
            'sessions': sessions_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def session_detail(request, session_id):
    """View a specific session with chat"""
    try:
        # Get user from JWT token (request.user is already a User object)
        user = request.user
        
        if not user:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        try:
            session = DocumentSession.objects(id=session_id).first()
            if not session:
                return Response({
                    'error': 'Session not found'
                }, status=status.HTTP_404_NOT_FOUND)
                
            if str(session.user.id) != str(user.id):
                return Response({
                    'error': 'Access denied'
                }, status=status.HTTP_403_FORBIDDEN)
        except DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        chat_messages = ChatMessage.objects(session=session).order_by('created_at')
        
        messages_data = [
            {
                'id': str(msg.id),
                'message': msg.message,
                'is_user': msg.is_user,
                'timestamp': msg.created_at.isoformat()
            }
            for msg in chat_messages
        ]
        
        return Response({
            'session': {
                'id': str(session.id),
                'summary': session.summary,
                'document_text': session.document_text,
                'created_at': session.created_at.isoformat()
            },
            'messages': messages_data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
