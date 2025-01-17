from fnmatch import filter

from rest_framework.request import Request
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from server.models import Network

from .serializers import NetworkSerializer, UserSerializer
from pprint import pprint


@api_view(['POST'])
def add_seen_networks(request):
    pprint(request.data)

    for network in request.data.get('networks', []):
        serializer = NetworkSerializer(data=network)
        if not serializer.is_valid():
            if "bssid" in serializer.errors and "unique" in str(serializer.errors["bssid"]):
                continue
            return Response({'message': 'error while serializing networks'}, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()

    all_networks = Network.objects.all()
    all_networks_serializer = NetworkSerializer(all_networks, many=True)

    res = {
        'message': all_networks_serializer.data,
    }
    pprint(res)
    return Response(res)

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

        res = {'message': { 'user': user_data, 'token': token.key}}
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

    res = {'message': {'user': user_data, 'token': token.key}}
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

    res = {'message': {'user': user_data, 'token': token.key}}
    pprint(res)
    return Response(res)


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    pprint(request)
    return Response("passed for {}".format(request.user.email))

@api_view(['GET'])
def halo(request):
    return Response("helo")



@api_view(['POST'])
def get_user_by_token(request):
    token_key = request.data.get('token')

    if not token_key:
        return Response({"message": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = Token.objects.get(key=token_key)
        user = token.user

        # Serialize the user information
        serializer = UserSerializer(user)
        user_data = serializer.data
        user_data.pop('password', None)

        return Response({"user": user_data}, status=status.HTTP_200_OK)

    except Token.DoesNotExist:
        return Response({"message": "Invalid token."}, status=status.HTTP_404_NOT_FOUND)
