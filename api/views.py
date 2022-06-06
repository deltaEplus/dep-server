from rest_framework import generics
from .models import UserDetails
from .serializers import UserDetailSerializer
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
import os

print(os.environ.get("GOOGLE_REDIRECT_URI"))


class UserDetailList(generics.ListCreateAPIView):
    queryset = UserDetails.objects.all()
    serializer_class = UserDetailSerializer


class UserDetails(generics.RetrieveDestroyAPIView):
    queryset = UserDetails.objects.all()
    serializer_class = UserDetailSerializer


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = os.environ.get("GOOGLE_REDIRECT_URI")
    client_class = OAuth2Client


class FacebookLogin(SocialLoginView):
    adapter_class = FacebookOAuth2Adapter
