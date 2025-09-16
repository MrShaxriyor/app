from ckeditor_uploader.views import upload
from django.contrib.auth import authenticate
from django.core.validators import FileExtensionValidator
from django.db.models import Q
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from home.utility import check_email_or_phone_number, valid_username
from .models import CustomUser, CodeVerified, VIA_EMAIL, VIA_PHONE, CODE_VERIFIED, DONE, PHOTO_DONE, NEW
from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
# import requests
# from shared.sms_service import send_phone



class SignUpSerializer(serializers.ModelSerializer):
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
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_mail(
                subject="Tasdiqlash kodi",
                message=f"Sizning tasdiqlash kodingiz: {code}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"VIA_EMAIL CODE: {code}")
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_phone(user.phone_number, code)
            print(f"VIA_PHONE CODE: {code}")
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
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data


class ChangeInfoUserSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if data.get('password') != data.get('password_confirm'):
            raise ValidationError('parollar mos emas')

        # current_user = CustomUser.objects.filter(username=data.get('username')).exists()
        #
        # if current_user:
        #     raise ValidationError('Bu username mavjud!')

        if not valid_username(data.get("username")):
            raise ValidationError("Username mukamal emas")


        return data



    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username')
        instance.password = validated_data.get('password', None)
        if instance.password:
            instance.set_password(validated_data.get('password'))

        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

class CreatePhotoUserSerializer(TokenObtainSerializer):
    photo = serializers.ImageField(
        required=True,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])]
    )

    def update(self, instance, validated_data):
        photo = validated_data.get("photo")
        if photo and instance.auth_status in [DONE, PHOTO_DONE]:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        else:
            raise ValidationError(
                {
                    'msg': 'Siz hali toliq ro‘yxatdan o‘tmadingiz',
                    'status': status.HTTP_400_BAD_REQUEST
                }
            )
        return instance

class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=124)

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['user_input'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('user_input')
        if valid_username(user_input):
            username = user_input
        elif check_email_or_phone_number(user_input) == 'email':
            user = CustomUser.objects.filter(email__iexact=user_input).first()
            username = user.username
        elif check_email_or_phone_number(user_input) == 'phone_number':
            user = CustomUser.objects.filter(phone_number__iexact=user_input).first()
            username = user.username
        else:
            raise ValidationError('Siz emael/usename/phone xato kiriting')

        user = authenticate(username=username, password=data.get('password'))
        if user is None:
            raise ValidationError('Siz notogri login/parol kiritdingiz')
        self.user = user

    def validate(self, data):
        self.auth_validate(data)
        refresh_token = RefreshToken.for_user(self.user)
        data = {
            'msg':'Login qildingiz',
            'refresh_token': str(refresh_token),
            'access_token': str(refresh_token.access_token),
            'status': status.HTTP_200_OK

        }
        return data

class LogOutSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=540)


class ForgotPasswordSerializer(serializers.Serializer):
    phone_email = serializers.CharField(required=True, write_only=True)

    def auth_validate(self, data):
        user_input = data.get('phone_email')
        user = CustomUser.objects.filter(Q(email__iexact=user_input) | Q(phone_number=user_input)).first()
        if user is None:
            raise ValidationError('Siz notogri email yoki telefon raqam kiritdingiz ')

        if user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError('siz hali toliq royxatdan otmadingiz')


        data['user'] = user

        return data

    def validate(self, data):
        self.auth_validate(data)
        super(ForgotPasswordSerializer, self).validate(data)
        return data

class ResetPasswordSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        if password != confirm_password:
            raise ValidationError('Parollar mos emas')

        return attrs

    def update(self, instance, validated_data):
        password = validated_data.pop(' password')
        instance.set_password(password)
        super(ResetPasswordSerializer, self).update(validated_data)



class UpdatePasswordSerializer(serializers.Serializer):
    old_pass  = serializers.CharField(required=True)
    new_pass = serializers.CharField(required=True)
    confirm_new_pass = serializers.CharField(required=True)

    def validate(self, data):
        old_pass = data.get('old_pass')
        new_pass = data.get('new_pass')
        confirm_new_pass = data.get('confirm_new_pass')

        if new_pass == old_pass:
            raise ValidationError('Yangi va eski parollar bir-xil bolmasligi kerak')
        elif confirm_new_pass != new_pass:
            raise ValidationError('Yangi parollar mos emas')
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('new_pass')
        instance.set_password(password)
        super(UpdatePasswordSerializer, self).update(validated_data)


