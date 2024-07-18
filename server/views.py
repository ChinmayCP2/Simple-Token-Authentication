from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from .serializers import UserSerializer
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated

@api_view(['POST'])
def login(request):
    # Get the user object or return 404 if not found
    user = get_object_or_404(User, username=request.data.get('username'))

    # Check if the provided password matches
    if not user.check_password(request.data.get('password')):
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    # If password is correct, generate or retrieve the token
    token, created = Token.objects.get_or_create(user=user)

    # Serialize the user data to include in the response
    serializer = UserSerializer(instance=user)

    # Return the token and serialized user data in the response
    return Response({"token": token.key, "user": serializer.data})


@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = User.objects.get(username=request.data['username'])
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({"token": token.key, "user" : serializer.data})
    return Response({serializer.errors, status.HTTP_400_BAD_REQUEST})



@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response({"passed for {}".format(request.user.email)})