import json
import os

from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.views.generic import TemplateView
from django.shortcuts import render
import logging

from api.decorators.response import JsonResponseDecorator
from api.helpers.response_helpers import error_response
from api.helpers.user_helpers import *
from api.models import User
from api.helpers.email_helpers import *

logger = logging.getLogger(__name__)


@method_decorator(JsonResponseDecorator, name='dispatch')
class LoginFormView(View):

    def post(self, request):
        """
        Authenticates and log in a valid user
        Disconnect with all the previous sessions of the user
        """
        email = request.POST.get('email')
        password = request.POST.get('password')

        check_pragyan = False
        try:
            user = User.objects.get(email=email)
            if user.is_pragyan is True:
                check_pragyan = True
            if user.is_DAuth:
                logger.info(
                    'User(email={}) has logged in using DAuth'.format(email))
                return error_response("Login using DAuth")
        except User.DoesNotExist:
            check_pragyan = True

        if check_pragyan is True:
            response = authenticatePragyanUser(email=email, password=password)
            if response['status_code'] != 200:
                return error_response(response['message'])
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist as e:
                if(str(os.environ.get('EVENT_OVER')) == 'True'):
                    return error_response("The event is over and registrations are closed. Be sure to come back next year!")
                name = response['message']['user_fullname']
                country = response['message']['user_country']
                user = register_user(email=email, name=name, password=password, country='in',
                                     is_pragyan=True)
        else:
            user = authenticate(username=email, password=password)

        if user is not None:
            remove_existing_sessions(user.user_id)
            login(request, user)
            request.session['user_id'] = user.user_id
            response = {
                'email': user.email,
                'name': user.name,
            }
            logger.info('{} Login successful'.format(user))
            return response
        else:
            try:
                user_obj = User.objects.get(email=email)
                if user_obj.is_active == 0:
                    logger.info(
                        'User(email={}) Verification pending'.format(email))
                    return error_response(
                        "Email verification pending. Please check your inbox to activate your account")
                else:
                    logger.info(
                        'User(email={}) Password incorrect'.format(email))
                    return error_response("User password incorrect")
            except User.DoesNotExist:
                logger.info(
                    'User(email={}) User email not found'.format(email))
                return error_response("User email not found! Register to play.")


@method_decorator(JsonResponseDecorator, name='dispatch')
class LogoutView(View):

    def post(self, request):
        """
        Logs out user
        Deletes his session
        """

        user = request.session.get('user_id')

        if user is not None:
            del request.session['user_id']
            logger.info('{} Logged out successfully'.format(user))
            return "Logged out successfully!"
        else:
            logger.info('{} Logout error'.format(user))
            return error_response("Logout error!")


@method_decorator(JsonResponseDecorator, name='dispatch')
class RegisterFormView(View):
    def post(self, request):
        """
        Check if the credentials are in proper format
        Check if the user with provided email already exists
        Register a user with default game data if it passes the above 2 test
        """
        if(str(os.environ.get('EVENT_OVER')) == 'True'):
            return error_response("The event is over and registrations are closed. Be sure to come back next year!")
        email = request.POST.get('email')
        password = request.POST.get('password')
        name = request.POST.get('name')
        country = request.POST.get('country')

        if validate_email(email) and len(password) >= 8 and name is not None:
            if not User.objects.filter(email=email).exists():
                is_pragyan = False
                response = authenticatePragyanUser(email, password)
                if response['status_code'] == 500:
                    return error_response(response['message'])
                if response['status_code'] != 400:
                    logger.info(
                        'User(email={}) Email already registered in pragyan'.format(email))
                    return error_response("Email has already been registered in pragyan site. Use those credentials to login.")
                register_user(email, name, password, country, is_pragyan)
                logger.info(
                    'User(email={}) Registration successful'.format(email))
                return "Registration Successful!"
            else:
                if User.objects.filter(email=email).first().is_DAuth:
                    logger.info(
                        'User(email={}) Registration error'.format(email))
                    return error_response("Registration error! User already registered using DAuth")
                logger.info(
                    'User(email={}) Account already exists'.format(email))
                return error_response("An account already exists under the email address")
        else:
            logger.info('email={} Invalid user details')
            return error_response("Invalid user details")


class ActivateAccountView(TemplateView):
    def get(self, request):
        """
        Activates account based on email verification
        """
        token = request.GET.get('token')
        UI_BASE_URL = os.environ.get('UI_BASE_URL')

        try:
            user = User.objects.get(token=token)
        except User.DoesNotExist:
            logger.info('Token({}): Invalid token'.format(token))
            return render(request, 'email_verification.html', {'ui_base_url': UI_BASE_URL, 'activation_success': False})

        if user is not None:
            assign_game_to_new_user(user)
            user.is_active = True
            new_token = generate_auth_token(50)
            user.token = new_token
            user.save()
            logger.info('{} Successfully verified'.format(user))
            return render(request, 'email_verification.html', {'ui_base_url': UI_BASE_URL, 'activation_success': True})


@method_decorator(JsonResponseDecorator, name='dispatch')
class ResendActivateAccountView(View):
    def post(self, request):
        """
        Resend activation link
        """
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
            if (user.is_active == 0):
                auth_token = user.token
                url = ('{APP_BASE_URL}/api/user/verify_email/?token={auth_token}').format(
                    APP_BASE_URL=os.environ.get('APP_BASE_URL'),
                    auth_token=auth_token
                )
                send_verification_email(email, url)
                logger.info('{} Verification email resent'.format(email))
                return "Resent verification email."
            else:
                logger.debug('{} Account already verified'.format(email))
                return error_response("Account already verified.")

        except User.DoesNotExist:
            logger.info('{} User does not exist'.format(email))
            return error_response("User does not exist. Please register!")


@method_decorator(JsonResponseDecorator, name='dispatch')
class ResetPassRequest(View):
    def post(self, request):
        """
        Gets the email and mails the user a reset link
        """

        user_email = request.POST.get('email')

        response = authenticatePragyanUser(user_email, 'dummy')
        if response['status_code'] == 500:
            return error_response(response['message'])
        if response['status_code'] != 400:
            logger.info('{} Registered in pragyan site'.format(user_email))
            return error_response("Given email registered in pragyan site. Visit pragyan.org to reset password.")

        try:
            user = User.objects.get(email=user_email)
            token = user.token
        except:
            logger.info('{} Email does not exist'.format(user_email))
            return error_response("Given email does not exist. Please register first.")

        if user is not None:
            if user.is_active:
                reset_url = ('{APP_BASE_URL}/api/user/pass_reset/?token={token}').format(
                    APP_BASE_URL=os.environ.get('APP_BASE_URL'),
                    token=token
                )
                send_password_reset_email(user_email, reset_url)
                logger.info(
                    '{} Password reset request successful'.format(user_email))
                return "Password reset request processed"
            else:
                logger.info('{} Account not verified'.format(user_email))
                return error_response("Your account hasn't been verified yet. Please verify and try again.")
        else:
            logger.info('{} Password reset request failed'.format(user_email))
            return error_response("Password reset request failed")


@method_decorator(JsonResponseDecorator, name='dispatch')
class ResetPassUpdate(View):
    def post(self, request):
        new_pass = request.POST.get('new_password')
        token = request.POST.get('token')

        try:
            user = User.objects.get(token=token)
        except:
            logger.info('Token({}): Invalid token'.format(token))
            return error_response("Invalid Token")

        user.set_password(new_pass)
        new_token = generate_auth_token(50)
        user.token = new_token
        user.save()
        logger.info('{} Password reset successful'.format(user))
        return "Password successfully reset!"


@method_decorator(JsonResponseDecorator, name='dispatch')
class DAuthFormView(View):
    def post(self, request):
        """
        DAuth login form
        """

        client_id = str(os.environ.get('CLIENT_ID'))
        client_secret = str(os.environ.get('CLIENT_SECRET'))
        redirect_uri = str(os.environ.get('REDIRECT_URI'))
        try:
            auth_code = request.POST.get('code')
            resp = requests.post(
                'https://auth.delta.nitt.edu/api/oauth/token',
                headers={'Content-type': 'application/x-www-form-urlencoded'},
                data={'client_id': client_id,
                      'client_secret': client_secret,
                      'redirect_uri': redirect_uri,
                      'grant_type': 'authorization_code',
                      'code': auth_code
                      })
            acc_token = json.loads(resp.text)['access_token']
            user_data = requests.post(
                'https://auth.delta.nitt.edu/api/resources/user',
                headers={'Content-type': 'application/x-www-form-urlencoded'},
                data={'access_token': acc_token}
            )
        except Exception as e:
            logger.error(
                'DAuth authentication request failed due to {}'.format(e))
            return error_response("DAuth authentication request failed")

        email = json.loads(user_data.text)['email']
        name = json.loads(user_data.text)['name']
        if not User.objects.filter(email=email).exists():
            is_pragyan = False
            is_DAuth = True
            country = "in"

            register_user_DAuth(email, name, country, is_pragyan, is_DAuth)
            logger.info('User(email={}) Registration successful'.format(email))

        user = User.objects.get(email=email)
        if not user.is_DAuth:
            user.is_DAuth = True
            user.save()
            logger.info('{} DAuth authentication successful'.format(email))
            return "DAuth authentication successful"

        remove_existing_sessions(user.user_id)
        login(request, user)
        request.session['user_id'] = user.user_id
        response = {
            'email': user.email,
            'name': user.name,
        }
        logger.info('{} Login successful'.format(user))
        return response
