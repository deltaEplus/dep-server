from django.http import HttpResponse
import requests
from rest_framework import generics
from .models import UserDetails
from .serializers import UserDetailSerializer, WeatherDetailSerializer
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
import os


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


class WeatherView(generics.GenericAPIView):
    serializer_class = WeatherDetailSerializer

    def post(self, request):
        try:
            if request.user.is_authenticated:
                latitude = request.data.get('latitude')
                longitude = request.data.get('longitude')
                appid = os.environ.get("WEATHER_API_KEY")
                response = requests.get(
                    'https://api.openweathermap.org/data/2.5/weather?lat={}&lon={}&units=metric&appid={}'.format(
                        latitude, longitude, appid))
                django_response = HttpResponse(
                    content=response.content,
                    status=response.status_code,
                    content_type=response.headers['Content-Type']
                )
                return django_response
            else:
                return HttpResponse(status=401)
        except Exception as e:
            return HttpResponse(status=500)
