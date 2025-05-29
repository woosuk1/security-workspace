package org.example.securitydemo.domain.security.filter;


import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class RedisRateLimitingFilter extends OncePerRequestFilter {

    private final LettuceBasedProxyManager<String> bucketManager;
//    private final ProxyManager<String> bucketManager;
    // 익명용/IP, 인증용/유저+IP, 로그인용 세 가지 리미터
    private final Bandwidth anonSliding = Bandwidth.classic(10, Refill.greedy(1, Duration.ofSeconds(10)));
    private final Bandwidth userLoginSliding = Bandwidth.classic(10, Refill.greedy(1, Duration.ofSeconds(5)));
    private final Bandwidth userSliding = Bandwidth.classic(10, Refill.greedy(1, Duration.ofSeconds(5)));


//    public RedisRateLimitingFilter(ProxyManager<String> bucketManager) {
//        this.bucketManager = bucketManager;
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {

        String ip = req.getRemoteAddr();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isRefresh = req.getRequestURI().endsWith("/auth/oauth/refresh");

        // 키 계산
        String bucketKey;
        Bandwidth limit;
        if (isRefresh && auth != null && auth.isAuthenticated()) {
            bucketKey = "rl:refresh:user:" + auth.getName() + ":" + ip;
            limit = userSliding;
        } else if (isRefresh) {
            bucketKey = "rl:refresh:anon:" + ip;
            limit = anonSliding;
        } else {
            // 로그인 시도
            String user = Optional.ofNullable(req.getParameter("username")).orElse("anon");
            bucketKey = "rl:login:" + user + ":" + ip;
            limit = userLoginSliding;  // 로그인은 좀 더 느슨하게?
        }

        Bucket bucket = bucketManager.builder().build(
                bucketKey,
                () -> BucketConfiguration.builder().addLimit(limit).build()
        );
        if (!bucket.tryConsume(1)) {
            res.setStatus(429);
            res.setHeader("Retry-After", String.valueOf(Duration.ofNanos(limit.getRefillPeriodNanos()).getSeconds()));
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.getWriter().write("{\"error\":\"TOO_MANY_REQUESTS\"}");
            return;
        }

        chain.doFilter(req, res);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        // /auth/oauth2/login, /auth/refresh 두 경로만 필터링 대상
        return !(
                (req.getMethod().equals("POST") && req.getRequestURI().equals("/auth/oauth2/refresh")) ||
                (req.getMethod().equals("POST") && req.getRequestURI().equals("/auth/login"))
        );
    }

}