from rest_framework import serializers


class UserSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.CharField()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    password = serializers.CharField(required=True)


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)


class ChangeUsernameSerializer(serializers.Serializer):
    newUsername = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class RequestResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class VerifyResetPasswordTokenSerializer(serializers.Serializer):
    secret = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)


class ResetPasswordSerializer(serializers.Serializer):
    secret = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    newPassword = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    newPassword = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class DestroyAccountSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)


class POSTPagesSerializer(serializers.Serializer):
    date = serializers.DateField(required=True)
    whatWentWrong = serializers.ListField(
        child=serializers.CharField(), required=True)
    whatWentRight = serializers.ListField(
        child=serializers.CharField(), required=True)
    whatCanBeImproved = serializers.ListField(
        child=serializers.CharField(), required=True)


class PUTPagesSerializer(serializers.Serializer):
    date = serializers.DateField(required=True)
    whatWentWrong = serializers.ListField(child=serializers.CharField())
    whatWentRight = serializers.ListField(child=serializers.CharField())
    whatCanBeImproved = serializers.ListField(child=serializers.CharField())


class SectionSerializer(serializers.Serializer):
    text = serializers.CharField()
    id = serializers.IntegerField()


class PagesSerializer(serializers.Serializer):
    date = serializers.DateField(required=True)
    what_went_wrong = serializers.ListField(child=SectionSerializer())
    what_went_right = serializers.ListField(child=SectionSerializer())
    what_can_be_improved = serializers.ListField(child=SectionSerializer())


class AutocompleteSerializer(serializers.Serializer):
    autocompleteString = serializers.CharField(required=True)
    sectionName = serializers.CharField(required=True)
