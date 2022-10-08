import json
import random
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login as django_login, logout
from django.views.decorators.http import require_GET, require_POST
from rest_framework import status
from .. secrets import generate_secret
from django.db import transaction, IntegrityError
from ..models import User, PasswordResetToken
from ..utils import require_anonymous, require_logged_in
from .. import validators
from .. serializers import UserSerializer
from .. mail import MailBodyTemplate, send_mail

@require_GET
@require_logged_in
def user(request):
    user = User.objects.get(username=request.user)

    return JsonResponse({
        "success": True,
        "errors": None,
        "details": UserSerializer(user).data,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)


# POST /api/login
@csrf_exempt
@require_POST
@require_anonymous
def login(request):
    # Attempt to validate the request.body according to "/login" route body requirements
    validation = validators.validate(request, "/login")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    request_body = json.loads(request.body)
    password = request_body["password"]
    username = ''  # Username's value will be assigned depending on whether the user supplied "username" or "email" fields

    if 'email' in request_body:
        # Assign the username value by querying the DB using email
        try:
            user = User.objects.get(email=request_body["email"])
            username = user.username
        except User.DoesNotExist:
            return JsonResponse({
                "success": False,
                "details": "Login failed, please check your email and/or password",
                "errors": ["Login failed, please check your email and/or password"],
                "status_code": status.HTTP_401_UNAUTHORIZED,
            }, status=status.HTTP_401_UNAUTHORIZED)

    elif 'username' in request_body:
        # Just use the variable directly
        username = request_body["username"]

    # Call the django authenticate function with above variables
    user = authenticate(request, username=username, password=password)
    if user is not None:
        # all gucci
        django_login(request, user)

        # return res
        return JsonResponse({
            "success": True,
            "details": "Login succeeded",
            "errors": None,
            "status_code": status.HTTP_200_OK,
        }, status=status.HTTP_200_OK)

    else:
        # username or password is incorrect
        return JsonResponse({
            "success": False,
            "details": "Login failed, please check your email and/or password",
            "errors": ["Login failed, please check your email and/or password"],
            "status_code": status.HTTP_401_UNAUTHORIZED,
        }, status=status.HTTP_401_UNAUTHORIZED)

# POST /api/register


@csrf_exempt
@require_POST
@require_anonymous
def register(request):
    # Attempt to validate the request.body according to "/register" route body requirements
    validation = validators.validate(request, "/register")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body username, email and password fields
    request_body = json.loads(request.body)
    username = request_body["username"]
    email = request_body["email"]
    password = request_body["password"]

    try:
        # Create a new user
        new_user = User.objects.create_user(
            username=username, password=password, email=email)
        # Return res
        return JsonResponse({
            "success": True,
            "details": "Account created!",
            "errors": None,
            "status_code": status.HTTP_201_CREATED,
        }, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        # Model.username and email fields are both unique, which is why IntegrityError is raised
        return JsonResponse({
            "success": False,
            "details": "This user with this username and/or email already exists",
            "errors": ["This user with this username and/or email already exists"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)


# GET /api/signout
@require_GET
@require_logged_in
def signout(request):
    # call the django logout func
    logout(request)
    return JsonResponse({
        "success": True,
        "details": "Signed out",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)


# POST /api/change-username
@csrf_exempt
@require_POST
@require_logged_in
def change_username(request):
    # Attempt to validate the request.body according to "/change-username" route body requirements
    validation = validators.validate(request, "/change_username")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body new username and password fields
    request_body = json.loads(request.body)
    new_username = request_body["newUsername"]
    password = request_body["password"]

    # Validate the user's submitted password
    password_validation = validators.validate_password(request, password)
    if not password_validation["success"]:
        # errors and info and stuff will be returned in the 'password_validation' dict
        return JsonResponse(password_validation, status=password_validation["status_code"])

    # usernames are unique. we use below logic to make sure they stay unique and handle if username is duplicated
    try:
        # try to fetch a user with the new usernae
        user_with_requested_new_username = User.objects.get(
            username=new_username)
        # If the user is fetched, that means this username already exists
        return JsonResponse({
            "success": False,
            "details": "This username already exists, please try another username",
            "errors": ["This username already exists, please try another username"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)
    except User.DoesNotExist:
        # here everything is gucci and we can proceed
        user = User.objects.get(username=request.user)
        user.username = new_username
        user.save()
        return JsonResponse({
            "success": True,
            "details": "Your username has been changed successfully",
            "errors": ["Your username has been changed successfully"],
            "status_code": status.HTTP_200_OK,
        }, status=status.HTTP_200_OK)

# POST /api/request-reset-password


@csrf_exempt
@transaction.atomic
@require_POST
def request_reset_password(request):
    # Attempt to validate the request.body according to "/request-reset-password" route body requirements
    validation = validators.validate(request, "/request_reset_password")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body email field
    request_body = json.loads(request.body)
    email = request_body["email"]

    # Generate a random number to be used to sleep this request
    randnum = random.random()

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Fake out an API request to prevent timing attacks
        time.sleep(randnum * 2)

        # End execution
        return JsonResponse({
            "success": True,
            "details": "If your email was correct, you will be receiving an email to reset your password shortly",
            "errors": None,
            "status_code": status.HTTP_200_OK,
        }, status=status.HTTP_200_OK)

    # If there are existing tokens for this user; invalidate them
    PasswordResetToken.objects.filter(user=user).update(is_valid=False)

    # Fake out an API request to prevent timing attacks (this time with lesser duration to account for the mail provider api request)
    time.sleep(randnum)

    # Generate an 80 char secret
    secret = generate_secret()

    # Create a new token instance and save it to the DB
    token = PasswordResetToken(user=user, token=secret)
    token.save()

    # Create a new password reset email template
    mail_template = MailBodyTemplate()
    mail_body = mail_template.password_reset(secret, email)

    # Send the email to the user
    send_mail(user.email, "Password reset", mail_body)

    return JsonResponse({
        "success": True,
        "details": "If your email was correct, you will be receiving an email to reset your password shortly",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)


# POST /api/verify-reset-password-token
@csrf_exempt
@require_POST
def verify_reset_password_token(request):
    # Attempt to validate the request.body according to "/verify-reset-password-token" route body requirements
    validation = validators.validate(request, "/verify_reset_password_token")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body token and email fields
    request_body = json.loads(request.body)
    secret = request_body["secret"]
    email = request_body["email"]

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({
            "success": False,
            "details": "This token does not exist",
            "errors": ["This token does not exist"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        token = PasswordResetToken.objects.get(token=secret, user=user)
    except PasswordResetToken.DoesNotExist:
        return JsonResponse({
            "success": False,
            "details": "This token does not exist",
            "errors": ["This token does not exist"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    if not token.is_token_valid():
        return JsonResponse({
            "success": False,
            "details": "This token is invalid",
            "errors": ["This token is invalid"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    return JsonResponse({
        "success": True,
        "details": "Token is valid",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)

# POST /api/reset-password


@csrf_exempt
@transaction.atomic
@require_POST
def reset_password(request):
    # Attempt to validate the request.body according to "/reset-password" route body requirements
    validation = validators.validate(request, "/reset_password")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body token and email fields
    request_body = json.loads(request.body)
    secret = request_body["secret"]
    email = request_body["email"]
    new_password = request_body["newPassword"]

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Do not share sensitive information in error message (such as "a user with this email does not exist")
        return JsonResponse({
            "success": False,
            "details": "This token does not exist",
            "errors": ["This token does not exist"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        token = PasswordResetToken.objects.get(token=secret, user=user)
    except PasswordResetToken.DoesNotExist:
        return JsonResponse({
            "success": False,
            "details": "This token does not exist",
            "errors": ["This token does not exist"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    if not token.is_token_valid():
        return JsonResponse({
            "success": False,
            "details": "This token is invalid",
            "errors": ["This token is invalid"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    # Invalidate the token
    token.is_valid = False
    token.save()

    # Update the user's password
    user.set_password(new_password)
    user.save()

    return JsonResponse({
        "success": True,
        "details": "Your password has been changed successfully",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)


@csrf_exempt
@require_POST
@require_logged_in
def change_password(request):
    # Attempt to validate the request.body according to "/change-password" route body requirements
    validation = validators.validate(request, "/change_password")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body new password and current password fields
    request_body = json.loads(request.body)
    new_password = request_body["newPassword"]
    password = request_body["password"]

    # Validate the user's submitted password
    password_validation = validators.validate_password(request, password)
    if not password_validation["success"]:
        # errors and info and stuff will be returned in the 'password_validation' dict
        return JsonResponse(password_validation, status=password_validation["status_code"])

    user = User.objects.get(username=request.user)

    user.set_password(new_password)
    user.save()

    """
    Because changing a password terminates the session (logs out the 
    user) we want to log the user again to keep the session going
    """
    django_login(request, user)

    return JsonResponse({
        "success": True,
        "details": "Your password has been changed successfully",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)


# POST /api/destroy-account
@csrf_exempt
@require_POST
@require_logged_in
def destory_account(request):
    # Attempt to validate the request.body according to "/change-password" route body requirements
    validation = validators.validate(request, "/destroy_account")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body password field
    request_body = json.loads(request.body)
    password = request_body["password"]

    # Validate the user's submitted password
    password_validation = validators.validate_password(request, password)
    if not password_validation["success"]:
        # errors and info and stuff will be returned in the 'password_validation' dict
        return JsonResponse(password_validation, status=password_validation["status_code"])

    user = User.objects.get(username=request.user)
    user.delete()
    # TODO: We also need to make sure the user's diary entries are also being deleted
    return JsonResponse({
        "success": True,
        "details": "Your account was deleted successfully",
        "errors": None,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK)
