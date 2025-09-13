import re
from rest_framework.exceptions import ValidationError

phone_regex = re.compile(r'^(?:\+998|998|0)?9\d{8}$')
email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


username_regex = re.compile(r'^[A-Za-z][A-Za-z0-9._]{7,}$')

def valid_username(username : str) -> bool:
    return re.fullmatch(username_regex, username) is not None


def check_email_or_phone_number(user_input):
    if re.fullmatch(phone_regex, user_input):
        data = 'phone_number'
    elif re.fullmatch(email_regex, user_input):
        data = 'email'
    else:
        data = {
            'succes':False,
            'msg':'Siz xato email yoki telefon raqam kiritdingiz'
        }
        raise ValidationError(data)
    return data