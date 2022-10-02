# import smtplib

# from email.mime.text import MIMEText

# msg = MIMEText('Testing some Mailgun awesomness')
# msg['Subject'] = "Hello"
# msg['From']    = "foo@YOUR_DOMAIN_NAME"
# msg['To']      = "bar@example.com"

# s = smtplib.SMTP('smtp.mailgun.org', 587)

# s.login('postmaster@YOUR_DOMAIN_NAME', '3kh9umujora5')
# s.sendmail(msg['From'], msg['To'], msg.as_string())
# s.quit()

# class Mail:
#     msg

#     def __init__(self, subject, body, to):
#         self.msg = MIMEText(body)
#         self.msg['Subject'] = subject
#         self.msg['From'] = "mail.stoicdiary.app"
#         self.msg['To'] = to

#     def sendMail(self):
#         s = smtplib.SMTP('smtp.mailgun.org', 587)
#         s.login('postmaster@YOUR_DOMAIN_NAME', '3kh9umujora5')
#         s.sendmail(self.msg['From'], self.msg['To'], self.msg.as_string())
#         s.quit()

import requests
import environ

env = environ.Env()

class MailBodyTemplate:
    def password_reset(self, secret, email):
        url = '%s/verify-reset-password-secret?secret=%s&email=%s' % (env('CLIENT_HOST'), secret, email)
        return 'Please click on the following link to reset your password for stoic diary: %s Please keep in mind that this link is only valid for 10 minutes. if you did not request a password reset then please ignore this message' % url


def send_mail(recipient, subject, body):
    return requests.post(
        "https://api.eu.mailgun.net/v3/mail.stoicdiary.app/messages",
        auth=("api", env('MAILGUN_API_KEY')),
        data={"from": "Stoic Diary Support help@mail.stoicdiary.app",
              "to": [recipient],
              "subject": subject,
              "text": body})
