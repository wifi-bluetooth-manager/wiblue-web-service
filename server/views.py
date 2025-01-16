from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from .serializers import UserSerializer
from pprint import pprint

@api_view(['POST'])
def signup(request):
    if User.objects.filter(username=request.data['username']).exists():
        return Response(
            {"message": "User exists"},
            status=status.HTTP_400_BAD_REQUEST
        )

    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.set_password(request.data['password'])
        user.save()

        token = Token.objects.create(user=user)

        user_data = serializer.data
        user_data.pop('password', None)

        res = {'token': token.key, 'message': { 'user': user_data}}
        pprint(res)

        return Response(res)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def login_username(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username:
        res = {"message": "Username is required."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    if not password:
        res = {"message": "Password is required."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(username=username).first()

    if not user:
        res = {"message": "User with this username does not exist."}
        pprint(res)
        return Response(res, status=status.HTTP_404_NOT_FOUND)

    if not user.check_password(password):
        res = {"message": "Incorrect password."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)

    user_data = serializer.data
    user_data.pop('password', None)

    res = {'token': token.key, 'message': {'user': user_data}}
    pprint(res)
    return Response(res)

@api_view(['POST'])
def login_email(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email:
        res = {"message": "Email is required."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    if not password:
        res = {"message": "Password is required."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email=email).first()

    if not user:
        res = {"message": "User with this username does not exist."}
        pprint(res)
        return Response(res, status=status.HTTP_404_NOT_FOUND)

    if not user.check_password(password):
        res = {"message": "Incorrect password."}
        pprint(res)
        return Response(res, status=status.HTTP_400_BAD_REQUEST)

    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)

    user_data = serializer.data
    user_data.pop('password', None)

    res = {'token': token.key, 'message': {'user': user_data}}
    pprint(res)
    return Response(res)


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed for {}".format(request.user.email))

@api_view(['GET'])
def halo(request):
    return Response("helo")
