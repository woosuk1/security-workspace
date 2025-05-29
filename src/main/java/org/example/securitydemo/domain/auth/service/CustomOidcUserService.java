package org.example.securitydemo.domain.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService
        implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserDetailsServiceImpl usersService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest)
            throws OAuth2AuthenticationException {

        OidcUserService delegate = new OidcUserService();
        OidcUser oidcUser = delegate.loadUser(userRequest);

        String registrationId =
                userRequest.getClientRegistration().getRegistrationId();  // "google" or "kakao"
        Map<String, Object> attrs = oidcUser.getAttributes();

        String email;
        if ("kakao".equals(registrationId)) {
            email = (String) attrs.get("email");
            if (email == null) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_user_info"),
                        "카카오에서 이메일을 가져올 수 없습니다." + attrs.toString()
                );
            }
        } else {
            // Google 등 OIDC 표준 프로바이더
            email = (String) attrs.get("email");
            if (email == null) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_user_info"),
                        "구글에서 이메일을 가져올 수 없습니다."
                );
            }
        }

        usersService.processOAuth2User(email, attrs);


        return oidcUser;
    }
}
