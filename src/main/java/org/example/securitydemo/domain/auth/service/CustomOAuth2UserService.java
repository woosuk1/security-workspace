package org.example.securitydemo.domain.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserDetailsServiceImpl usersService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oauthUser = delegate.loadUser(userRequest);

        String registrationId =
                userRequest.getClientRegistration().getRegistrationId();  // "google" or "kakao"
        Map<String, Object> attrs = oauthUser.getAttributes();

        String email;
        if ("kakao".equals(registrationId)) {
            // 1) kakao_account 맵 꺼내고
            Map<String, Object> kakaoAccount =
                    (Map<String, Object>) attrs.get("kakao_account");
            if (kakaoAccount == null || kakaoAccount.get("email") == null) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_user_info"),
                        "카카오에서 이메일을 가져올 수 없습니다."
                );
            }
            email = (String) kakaoAccount.get("email");

        } else {
            // Google 등 OIDC 표준 프로바이더
            email = (String) attrs.get("email");
            if (email == null) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_user_info"),
                        "Provider에서 이메일을 가져올 수 없습니다."
                );
            }
        }


        // 1) 내부 DB에 사용자 조회 또는 신규 가입
//        usersService.processOAuth2User(email, oauthUser.getAttributes("kakao_account"));
        usersService.processOAuth2User(email, attrs);

        return oauthUser;
    }
}