from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from home.utility import check_email_or_phone_number
from .models import CustomUser, CodeVerified, VIA_EMAIL, VIA_PHONE
from django.core.mail import send_mail
from django.conf import settings

class SignUnSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    auth_type = serializers.CharField(required=False, read_only=True)
    auth_status = serializers.CharField(required=False, read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'auth_type', 'auth_status']

    def create(self, validated_data):
        user = super(SignUnSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_mail(
                subject="Tasdiqlash kodi",
                message=f"Sizning tasdiqlash kodingiz: {code}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            # send_phone(user.phone, code)
        user.save()
        return user

    def validate(self, data):
        super().validate(data)
        data = self.auth_validate(data)
        return data

    def validate_email_phone_number(self, data):
        if data and CustomUser.objects.filter(email=data).exists():
            raise ValidationError("Bu email mavjud")
        elif data and CustomUser.objects.filter(phone_number=data).exists():
            raise ValidationError('Bu telefon raqam mavjud')
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()
        auth_type = check_email_or_phone_number(user_input)

        if auth_type == 'email':
            data = {
                'auth_type' : VIA_EMAIL,
                'email' : user_input
            }
        elif auth_type == 'phone_number':
            data = {
                'auth_type' : VIA_PHONE,
                'phone_number' : user_input
            }
        else:
            data = {
                'succes' : False,
                'msg' : 'siz telefon raqam yoki email kiritishingiz kerak'
            }
            raise ValidationError(data)
        return data

    def to_representation(self, instance):
        data = super(SignUnSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data
