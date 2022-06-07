from django.urls import path
from .views import UserDetails, UserDetailList, GoogleLogin, FacebookLogin, WeatherView

app_name = 'api'

urlpatterns = [
    path('auth/google/', GoogleLogin.as_view(), name='google_login'),
    path('auth/facebook/', FacebookLogin.as_view(), name='facebook_login'),
    path('userdetails/<int:pk>/', UserDetails.as_view(), name='detailcreate'),
    path('userdetails/', UserDetailList.as_view(), name='listcreate'),
    path('weather/', WeatherView.as_view(), name='weather'),
]
