from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from medicarrier.models import MediCard

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'nickname']

    def create(self, validated_data):
        username = validated_data['username']
        password = validated_data['password']
        nickname = validated_data.get('nickname', '')

        user = User(username=username, nickname=nickname)
        user.set_password(password)
        user.save()

        # 기본 메디카드 생성
        countries = ['한국', '영국']
        languages = ['ko', 'en']

        for country, language in zip(countries, languages):
            MediCard.objects.get_or_create(
                user=user,
                country=country,
                defaults={'language': language}
            )

        return user
    
class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=128)
    password = serializers.CharField(max_length=128, write_only=True)

    def validate(self, data):
        username = data.get('username', None)
        password = data.get('password', None)

        if User.objects.filter(username=username).exists():
            user = User.objects.get(username=username)

            if not user.check_password(password):
                raise serializers.ValidationError('잘못된 비밀번호입니다.')
            else:
                token = RefreshToken.for_user(user)
                refresh = str(token)
                access = str(token.access_token)

                data = {
                    'id': user.id,
                    'username': user.username,
                    'access_token': access,
                    'nickname': user.nickname
                }
                return data 

        raise serializers.ValidationError('사용자가 존재하지 않습니다.')
