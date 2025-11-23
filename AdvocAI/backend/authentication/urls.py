from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    signup_view, 
    login_view, 
    google_auth_view, 
    logout_view,
    verify_otp_view,
    resend_otp_view,
    profile_detail_update_view,  # Combined view
    lawyer_list_view,
    lawyer_detail_view,
    connect_with_lawyer_view,
    lawyer_dashboard_view,
    lawyer_connection_update_view,
    forgot_password_view,         # From HEAD
    reset_password_view,          # From HEAD
    chat_conversations_list_view, # From remote
    chat_messages_view,           # From remote
)

urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('google/', google_auth_view, name='google_auth'),
    path('verify-otp/', verify_otp_view, name='verify_otp'),
    path('resend-otp/', resend_otp_view, name='resend_otp'),
    path('profile/', profile_detail_update_view, name='profile'),
    path('logout/', logout_view, name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Lawyer-related routes
    path('lawyers/', lawyer_list_view, name='lawyer_list'),
    path('lawyers/<str:lawyer_id>/', lawyer_detail_view, name='lawyer_detail'),
    path('lawyers/<str:lawyer_id>/connect/', connect_with_lawyer_view, name='connect_lawyer'),
    path('lawyer/dashboard/', lawyer_dashboard_view, name='lawyer_dashboard'),
    path('lawyer/connections/<str:connection_id>/', lawyer_connection_update_view, name='lawyer_connection_update'),

    # Password reset routes
    path('forgot-password/', forgot_password_view, name='forgot_password'),
    path('reset-password/', reset_password_view, name='reset_password'),

    # Chat routes
    path('chat/conversations/', chat_conversations_list_view, name='chat_conversations'),
    path('chat/conversations/<str:conversation_id>/messages/', chat_messages_view, name='chat_messages'),
]
