import json
import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from rest_framework import status
from ..models import DiaryPage, Line
from ..utils import require_logged_in
from .. serializers import PagesSerializer
from .. import validators


@csrf_exempt
@require_http_methods(["POST", "PUT"])
@require_logged_in
def pages(request):
    def POST_handler():
        def handle_return_page(user, date, what_went_wrong, what_went_right, what_can_be_improved):
            # Create a new page object
            page = DiaryPage(user=user, date=date)

            # Save it in the db
            page.save()

            # for each line in the diary section
            for line in what_went_wrong:
                # Add the line and it's section type to the created page.
                page.line_set.create(
                    text=line, section_type=1, user=request.user)
            for line in what_went_right:
                page.line_set.create(
                    text=line, section_type=2, user=request.user)
            for line in what_can_be_improved:
                page.line_set.create(
                    text=line, section_type=3, user=request.user)

            return JsonResponse({
                "success": True,
                "details": "Your diary page entry has been successfully created",
                "errors": None,
                "status_code": status.HTTP_201_CREATED,
            }, status=status.HTTP_201_CREATED)

        # Attempt to validate the request.body according to "/pages" route body requirements
        validation = validators.validate(request, "/pages")
        if not validation["success"]:
            # errors and info and stuff will be returned in the 'validation' dict
            return JsonResponse(validation, status=validation["status_code"])

        # Unload the request.body date, what went wrong, what went right and what can be improved fields
        request_body = json.loads(request.body)
        date = request_body["date"]
        what_went_wrong = request_body["whatWentWrong"]
        what_went_right = request_body["whatWentRight"]
        what_can_be_improved = request_body["whatCanBeImproved"]

        try:
            """
            Dates cannot be duplicate (can't have 2 diary entries for the same date.) so if
            an object with request.body.date is fetched, return an error 
            """
            no_duplicate_date_validation = DiaryPage.objects.get(
                user=request.user, date=date)

            if not no_duplicate_date_validation.is_page_empty():
                return JsonResponse({
                    "success": False,
                    "details": "A diary page for this date already exists",
                    "errors": ["A diary page for this date already exists"],
                    "status_code": status.HTTP_403_FORBIDDEN,
                }, status=status.HTTP_403_FORBIDDEN)
            return handle_return_page(request.user, date, what_went_wrong, what_went_right, what_can_be_improved)
        except DiaryPage.DoesNotExist:
            return handle_return_page(request.user, date, what_went_wrong, what_went_right, what_can_be_improved)


    def PUT_handler():
        # Attempt to validate the request.body according to "/pages" route body requirements
        validation = validators.validate(request, "/pages")
        if not validation["success"]:
            # errors and info and stuff will be returned in the 'validation' dict
            return JsonResponse(validation, status=validation["status_code"])

        # Unload the request.body date, what went wrong, what went right and what can be improved fields
        request_body = json.loads(request.body)
        date = request_body["date"]
        what_went_wrong = request_body["whatWentWrong"]
        what_went_right = request_body["whatWentRight"]
        what_can_be_improved = request_body["whatCanBeImproved"]

        try:
            # Get the diary from the DB according to the provided date
            page = DiaryPage.objects.get(user=request.user, date=date)

            # Remove all the current diary section lines (this is an overwrite logic)
            Line.objects.filter(diary_page=page, user=request.user).delete()

            # Add the new lines
            for line in what_went_wrong:
                page.line_set.create(
                    text=line, section_type=1, user=request.user)

            for line in what_went_right:
                page.line_set.create(
                    text=line, section_type=2, user=request.user)

            for line in what_can_be_improved:
                page.line_set.create(
                    text=line, section_type=3, user=request.user)

            return JsonResponse({
                "success": True,
                "details": "Your diary page entry has been successfully updated",
                "errors": None,
                "status_code": status.HTTP_200_OK,
            }, status=status.HTTP_200_OK)
        except DiaryPage.DoesNotExist:
            return JsonResponse({
                "success": False,
                "details": "A diary page for this date does not exist",
                "errors": ["A diary page for this date does not exist"],
                "status_code": status.HTTP_403_FORBIDDEN,
            }, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'POST':
        return POST_handler()
    elif request.method == 'PUT':
        return PUT_handler()


@require_GET
@require_logged_in
def page(request):
    # Get the date from request query param
    date = request.GET.get('date', None)
    if not date:
        return JsonResponse({
            "success": False,
            "details": "Please provide a 'date' query parameter in your request header",
            "errors": ["Please provide a 'date' query parameter in your request header"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        # Attempt to validate the date
        datetime.datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return JsonResponse({
            "success": False,
            "details": "Incorrect data format, should be YYYY-MM-DD",
            "errors": ["Incorrect data format, should be YYYY-MM-DD"],
            "status_code": status.HTTP_403_FORBIDDEN,
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        # Attempt to validate whether the page for this specific date exists
        page = DiaryPage.objects.get(user=request.user, date=date)
    except DiaryPage.DoesNotExist:
        return JsonResponse({
            "success": False,
            "details": "Your diary page for this date does not exist",
            "errors": ["Your diary page for this date does not exist"],
            "status_code": status.HTTP_404_NOT_FOUND,
        }, status=status.HTTP_404_NOT_FOUND)

    # There are cases where the page might have been submitted in the past, but each section is empty
    if page.is_page_empty():
        return JsonResponse({
            "success": False,
            "details": "Your diary page for this date does not exist",
            "errors": ["Your diary page for this date does not exist"],
            "status_code": status.HTTP_404_NOT_FOUND,
        }, status=status.HTTP_404_NOT_FOUND)

    # Return a serialized JSON of the requested page
    return JsonResponse({
        "success": True,
        "errors": None,
        "details": PagesSerializer(page).data,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK, safe=False)


@require_POST
@csrf_exempt
@require_logged_in
def autocomplete(request):
    # Attempt to validate the request.body according to "/pages" route body requirements
    validation = validators.validate(request, "/autocomplete")
    if not validation["success"]:
        # errors and info and stuff will be returned in the 'validation' dict
        return JsonResponse(validation, status=validation["status_code"])

    # Unload the request.body autocomplete_string field
    request_body = json.loads(request.body)
    autocomplete_string = request_body["autocompleteString"]

    # Define a function that translated the section's name into its respective number identifier
    def translate_section_type(section_name):
        if section_name == 'whatWentWrong':
            return 1
        elif section_name == 'whatWentRight':
            return 2
        elif section_name == 'whatCanBeImproved':
            return 3
    section_type = translate_section_type(request_body["sectionName"])

    # Get the lines query set using the above autocomplete_string to find sentences that are similar, and make sure
    # there are no duplicates
    linesQueryset = Line.objects.filter(text__icontains=autocomplete_string, user=request.user, section_type=section_type).distinct('text')

    # Map over the queryset to return only text and store it into a list
    lines = list(map(lambda line: {"value": line.text, "id": line.id}, linesQueryset))

    # Return the lines list
    
    return JsonResponse({
        "success": True,
        "errors": None,
        "details": lines,
        "status_code": status.HTTP_200_OK,
    }, status=status.HTTP_200_OK, safe=False)
