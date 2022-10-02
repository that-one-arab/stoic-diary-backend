import datetime
from tkinter.tix import Tree
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    email = models.EmailField(unique=True)


def get_expiry_date():
    return timezone.now() + datetime.timedelta(minutes=10)


class PasswordResetToken(models.Model):
    is_valid = models.BooleanField(default=True)
    token = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    # Set to expire 10 minutes after creation
    expiry_date = models.DateTimeField(default=get_expiry_date)

    def is_token_valid(self):
        if self.is_valid == False:
            return False

        if timezone.now() > self.expiry_date:
            return False

        return True

    def __str__(self):
        return "{} is_valid: {}".format(self.token, self.is_valid)


class DiaryPage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)

    def what_went_wrong(self):
        lines = Line.objects.filter(
            user=self.user, section_type=1, diary_page=self.id)
        return list(lines.values())

    def what_went_right(self):
        lines = Line.objects.filter(
            user=self.user, section_type=2, diary_page=self.id)
        return list(lines.values())

    def what_can_be_improved(self):
        lines = Line.objects.filter(
            user=self.user, section_type=3, diary_page=self.id)
        return list(lines.values())

    def is_page_empty(self):
        what_went_wrong = self.what_went_wrong()
        what_went_right = self.what_went_right()
        what_can_be_improved = self.what_can_be_improved()

        if len(what_went_wrong) == 0 and len(what_went_right) == 0 and len(what_can_be_improved) == 0:
            return True

        return False

    def __str__(self):
        return "{}".format(self.date)


SECTION_TYPES = [
    (1, 'What Went Wrong'),
    (2, 'What Went Right'),
    (3, 'What Can Be Improved'),
]


class Line(models.Model):
    text = models.CharField(max_length=100)
    diary_page = models.ForeignKey(DiaryPage, on_delete=models.CASCADE)
    section_type = models.CharField(max_length=1, choices=SECTION_TYPES)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.text
