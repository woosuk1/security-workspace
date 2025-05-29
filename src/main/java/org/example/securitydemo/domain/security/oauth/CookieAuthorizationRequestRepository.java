package org.example.securitydemo.domain.security.oauth;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.util.WebUtils;
import java.util.Base64;

import java.io.*;

/**
 * OAuth2AuthorizationRequest 를 세션 대신 암호화된 쿠키에 저장/로드/제거합니다.
 */
public class CookieAuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String COOKIE_NAME = "oauth2_auth_request";
    private static final int COOKIE_MAX_AGE = 300; // 5분

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, COOKIE_NAME);
        if (cookie == null) return null;

        byte[] data = Base64.getUrlDecoder().decode(cookie.getValue());
//        byte[] data = base64Decoder(cookie.getValue());
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (OAuth2AuthorizationRequest) ois.readObject();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize OAuth2AuthorizationRequest", e);
        }
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authRequest == null) {
            expireCookie(response);
            return;
        }

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(authRequest);
            String serialized = Base64.getUrlEncoder().encodeToString(bos.toByteArray());

            Cookie cookie = new Cookie(COOKIE_NAME, serialized);
            cookie.setHttpOnly(true);
//            cookie.setSecure(true);          // HTTPS 환경이라면 true
            cookie.setPath("/");
            cookie.setMaxAge(COOKIE_MAX_AGE);
            response.addCookie(cookie);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to serialize OAuth2AuthorizationRequest", e);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        OAuth2AuthorizationRequest req = loadAuthorizationRequest(request);
        expireCookie(response);
        return req;
    }

    private void expireCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}