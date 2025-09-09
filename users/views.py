from datetime import datetime
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.shortcuts import render
from .serializers import SignUnSerializer, ChangeInfoUserSerializer, CreatePhotoUserSerializer
from .models import CustomUser, CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE
from rest_framework.generics import ListCreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.


class SignUpView(ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = SignUnSerializer
    permission_classes = [AllowAny, ]


class VerifyCodeApiView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        code = self.request.data.get('code')
        user = self.request.user

        self.check_verify(user, code)
        data = {
            'succes':True,
            'code_status':user.verify_codes.filter(code=code).first().code_status,
            "auth_status":user.auth_status,
            'access_token':user.token()['access_token'],
            'refresh_token':user.token()['refresh_token']
        }
        return Response(data=data, status=status.HTTP_200_OK)

    @staticmethod
    def check_verify(user, code):
        verify = user.verify_codes.filter(code=code, code_status=False, expiration_time__gte=datetime.now())
        if not verify.exists():
            data = {
                'succes':False,
                'msg':'Kodingiz eski yoki xato'
            }
            raise ValidationError(data)
        else:
            verify.update(code_status=True)

        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True

class GetNewCodeVerify(APIView):
    def get(self, request, *args, **kwargs):
        user = self.request.user

        self.check_verification(user)
        if user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            #send_phone(user.phone_number, code)
            print(f"VIA_PHONE CODE {code}")
        elif user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            # send_mail(user.email, code)
            print(f"VIA_EMAIL CODE {code}")
        else:
            raise ValidationError("Telefon yoki email xato")

        data = {
            'status':status.HTTP_200_OK,
            'msg':"Kod email yoki phone ga yuborildi",
            'access_token': user.token()['access_token'],
            'refresh_token': user.token()['refresh_token']

        }
        return Response(data)


    @staticmethod
    def check_verification(user):
        verify = user.verify_codes.filter(expiration_time__gte=datetime.now(), code_status=False)
        if verify.exists():
            data = {
                'msg':'Sizda active code bor shundan foydalaning yoki 2 daqiqadan song yangi kod oling',
                'status':status.HTTP_400_BAD_REQUEST
            }
            raise ValidationError(data)
        return True


class TokenRefreshApi(APIView):
    permission_classes = [AllowAny, ]
    def post(self, request):
        data = request.data
        try:
            token = RefreshToken(data['refresh'])
            return Response({
                "access":str(token.access_token),
                "status":status.HTTP_201_CREATED
            })
        except Exception as e:
            return Response({
                "err": str(e),
                "status":status.HTTP_400_BAD_REQUEST
            })




class ChangeInfoUserApi(UpdateAPIView):
    serializer_class = ChangeInfoUserSerializer
    http_method_names = ['put', 'patch']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeInfoUserApi, self).update(request, *args, **kwargs)
        data = {
            'msg':"Malumotlar yangilandi",
            'status':status.HTTP_200_OK
        }
        return Response(data)
    
    def partial_update(self, request, *args, **kwargs):
        super(ChangeInfoUserApi, self).partial_update(request, *args, **kwargs)
        data = {
            'msg':"Malumotlar yangilandi",
            'status':status.HTTP_200_OK
        }
        return Response(data)

class CreatePhotoUserApi(UpdateAPIView):
    serializer_class = CreatePhotoUserSerializer
    http_method_names = ['patch']

    def get_object(self):
        return self.request.user

    def partial_update(self, request, *args, **kwargs):
        super(CreatePhotoUserApi, self).partial_update(request, *args, **kwargs)
        data = {
            'msg':"Rasm yaratildi",
            'status':status.HTTP_201_CREATED
        }
        return Response(data)