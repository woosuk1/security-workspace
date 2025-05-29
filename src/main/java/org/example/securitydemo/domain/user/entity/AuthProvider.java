package org.example.securitydemo.domain.user.entity;

public enum AuthProvider {
    LOCAL, // 로컬 사용자
    GOOGLE, // 구글 OAuth2 사용자
    KAKAO, // 카카오 OAuth2 사용자
}
