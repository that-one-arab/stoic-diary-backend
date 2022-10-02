from django.urls import path

from .controller import user, diary

urlpatterns = [
    # USER RELATED URLS
    path('user', user.user, name='user'),
    path('login', user.login, name='login'),
    path('register', user.register, name='register'),
    path('signout', user.signout, name='sign out'),
    path('change-username', user.change_username, name='change username'),
    path('request-reset-password', user.request_reset_password, name='request reset password'),
    path('verify-reset-password-token', user.verify_reset_password_token, name='verify reset password token'),
    path('reset-password', user.reset_password, name='reset password'),
    path('change-password', user.change_password, name='change password'),
    path('destroy-account', user.destory_account, name='destory account'),
    # DIARY RELATED URLS
    path('pages', diary.pages, name='pages'),
    path('page', diary.page, name='page'),
    path('autocomplete', diary.autocomplete, name='autocomplete')
]
