package org.example.securitydemo.domain.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.securitydemo.domain.auth.service.TokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException {
        OAuth2AuthenticationToken oauthToken =
                (OAuth2AuthenticationToken) authentication;
        String email = oauthToken.getPrincipal().getAttribute("email");
        List<String> roles = oauthToken.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        // 토큰 발급
        tokenService.issueTokens(email, roles, response);

        // 프론트엔드에 리디렉트
        response.sendRedirect("/");
    }
}
