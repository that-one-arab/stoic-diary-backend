import json
from django.http import JsonResponse
import logging
import traceback


def log_err(): logging.error(traceback.format_exc())


def require_anonymous(func):
    def inner(*args, **kwargs):

        # we assume the first element in the tuple is the request object
        request = args[0]

        if request.user.is_authenticated:
            return JsonResponse({
                "success": False,
                "details": "You are already logged in",
                "errors": ["You are already logged in"],
                "status_code": 403,
            }, status=403)
        else:
            return func(*args, **kwargs)

    return inner


def require_logged_in(func):
    def inner(*args, **kwargs):

        # we assume the first element in the tuple is the request object
        request = args[0]

        if not request.user.is_authenticated:
            return JsonResponse({
                "success": False,
                "details": "Please authenticate yourself by logging in",
                "errors": ["Please authenticate yourself by logging in"],
                "status_code": 403,
            }, status=403)

        else:
            return func(*args, **kwargs)

    return inner


"""
TODO: delete this
Handles validating if the request contains a json object in it's body, and validating
if a set of keys exist in the body
request = HttpRequest
requiredKeysDict = dict
"""
def valid_json_body_required(request, required_keys_dict):
    """
    handles parsing a message that conveys the required keys in the json object
    """
    print('***** in valid_json_body_required 1')

    def required_keys_err_message_parser(keys):
        # start the message with 'please provide'
        message = 'Please provide '
        for i, key in enumerate(keys):
            # if the first key
            if i == 0:
                message = message + '"' + key + '" '
            # if the last key
            elif i + 1 == len(keys):
                message = message + ' and "' + key + '" '
            # if not the first key and last key
            else:
                message = message + ', "' + key + '" '

        # end the message with ' fields in your JSON object'
        message = message + ' fields in your JSON object'
        return message

    def decorator(func):
        print('***** in valid_json_body_required 2')

        def inner():
            print('***** in valid_json_body_required 3')
            # check if body is not falsy
            if not request.body:
                return HttpResponse('Please provide a JSON object', status=422)

            # convert the required keys dictionary to a set
            required_keys_set = set(required_keys_dict)
            # check if the required keys exist in the json body
            if not required_keys_set <= json.loads(request.body).keys():
                err_message = required_keys_err_message_parser(
                    required_keys_set)
                return HttpResponse(err_message, status=422)

            return func()

        return inner

    return decorator


"""
TODO: delete this
handles verifying that the user's password is correct, returns status 401 if not
request = HttpRequest!
opts_dict = dictionary! => a dictionary of options
opts_dict["json_password_field_name"] = string! => the json password field/key name where the password value is stored
"""
def authenticate_password(request, opts_dict):
    print('***** in authenticate_password 1')
    password = json.loads(request.body)[opts_dict["json_password_field_name"]]

    def decorator(func):
        print('***** in authenticate_password 2')

        def inner():
            print('***** in authenticate_password 3')
            user = authenticate(
                request, username=request.user, password=password)
            if user is not None:
                return func()
            return HttpResponse('Your password is wrong', 401)

        return inner

    return decorator
