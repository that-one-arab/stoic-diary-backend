from . import serializers
from rest_framework import status
from django.contrib.auth import authenticate
import json

"""
TODO: Lot's of duplicate code in login and register validators. Might just
remove all that and add the Serializers to the switcher dict directly instead of these functions
"""
# if validate_for = "/login"


def login(req, res, method):
    validation = serializers.LoginSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors

    if not 'username' in req and not 'email' in req:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = [
            "Please supply one of 'username' or 'email' fields in your request"]

    return res

# if validate_for = "/register"


def register(req, res, method):
    validation = serializers.RegisterSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors

    if "@" in req["username"]:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = [{"username": "your username cannot contain '@' sign"}]

    return res

# if validate_for = "/change_username"


def change_username(req, res, method):
    validation = serializers.ChangeUsernameSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def request_reset_password(req, res, method):
    validation = serializers.RequestResetPasswordSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def verify_reset_password_token(req, res, method):
    validation = serializers.VerifyResetPasswordTokenSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def reset_password(req, res, method):
    validation = serializers.ResetPasswordSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def change_password(req, res, method):
    validation = serializers.ChangePasswordSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def destroy_account(req, res, method):
    validation = serializers.DestroyAccountSerializer(data=req)
    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def pages(req, res, method):
    # Declare the object
    validation = None

    if method == 'POST':
        validation = serializers.POSTPagesSerializer(data=req)
    elif method == 'PUT':
        validation = serializers.PUTPagesSerializer(data=req)

    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
    return res


def autocomplete(req, res, method):
    validation = serializers.AutocompleteSerializer(data=req)

    if validation.is_valid():
        res["success"] = True
    else:
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = validation.errors
        return res

    # Check if sectionName value is correct so that it can be correctly parsed into its respective number identifier
    section_name = req['sectionName']
    if section_name != 'whatWentWrong' and section_name != 'whatWentRight' and section_name != 'whatCanBeImproved':
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Bad Request Body"
        res["errors"] = [
            "'sectionName' field must be one of the following values: ('whatWentWrong', 'whatWentRight' , 'whatCanBeImproved')"]

    return res


""" 
Validator factory.
Handles validating the request.body object is a valid json object,
then calls and returns another validator function depending on value of validate_for arg
"""


def validate(request, validate_for):
    # initialize the return values.
    res = {}
    res["success"] = True
    res["status_code"] = status.HTTP_200_OK
    res["errors"] = None
    res["details"] = None

    req = {}

    # Attempt to load the json object from request.body
    try:
        req = json.loads(request.body.decode("utf-8"))
    # Return an early validation dict if request.body isn't loaded
    except Exception as e:
        print(e)
        res["success"] = False
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        res["details"] = "Invalid request body"
        return res

    # HTTP request method type
    method = request.method

    # Declare the switcher that will handle returning validation dict
    switcher = {
        "/login": login,
        "/register": register,
        "/change_username": change_username,
        "/request_reset_password": request_reset_password,
        "/verify_reset_password_token": verify_reset_password_token,
        "/reset_password": reset_password,
        "/change_password": change_password,
        "/destroy_account": destroy_account,
        "/pages": pages,
        "/autocomplete": autocomplete
    }

    # Access the key through the validate_for variable and immediatly call then return the result of the function
    return switcher[validate_for](req, res, method)


def validate_password(request, password):
    user = authenticate(request, username=request.user, password=password)
    if user is not None:
        return {
            "success": True,
            "details": "Your password is correct",
            "errors": None,
            "status_code": 200,
        }
    return {
        "success": False,
        "details": "Your password is invalid, please double check your password",
        "errors": ["Your password is invalid, please double check your password"],
        "status_code": 401,
    }
