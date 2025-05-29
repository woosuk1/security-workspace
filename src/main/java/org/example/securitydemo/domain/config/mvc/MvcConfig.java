package org.example.securitydemo.domain.config.mvc;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // 1) API 전용 테스트 페이지
        // /oauth2.html 로 직접 접근시키거나, /auth/login 을 여기로 포워드
        registry.addViewController("/auth/login")
                .setViewName("forward:/oauth2.html");
        // 만약 루트(/)도 여기로 보내서 SPA 테스트 페이지를 기본으로 쓰고 싶다면:
        registry.addViewController("/")
                .setViewName("forward:/oauth2.html");

        // 2) OAuth2 실패 콜백에도 같은 곳으로
        //    쿼리는 무시되므로, 아예 /auth/login 으로만 보내면 됩니다.
        registry.addViewController("/auth/login?error")
                .setViewName("forward:/oauth2.html");
    }
}