import string
import secrets

def generate_secret(): return ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(80))