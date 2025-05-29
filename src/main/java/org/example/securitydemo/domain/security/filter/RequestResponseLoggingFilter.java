package org.example.securitydemo.domain.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static java.util.Collections.list;

@Component
@Slf4j
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // 래핑
        var wrappedReq  = new ContentCachingRequestWrapper(request);
        var wrappedRes  = new ContentCachingResponseWrapper(response);

        long start = System.currentTimeMillis();
        chain.doFilter(wrappedReq, wrappedRes);
        long duration = System.currentTimeMillis() - start;

        // 요청 로그
        String reqBody = new String(wrappedReq.getContentAsByteArray(), StandardCharsets.UTF_8);
        var headerNames = wrappedReq.getHeaderNames();
        String reqHeaders = headerNames != null ?
            list(headerNames).stream()
                .map(name -> name + ": " + wrappedReq.getHeader(name))
                .collect(Collectors.joining(", "))
            : "";
//        log.info("[REQUEST] {} {} headers=[{}] body=[{}]",
//                wrappedReq.getMethod(), wrappedReq.getRequestURI(),
//                reqHeaders, reqBody);

        // 응답 로그
        String resBody = new String(wrappedRes.getContentAsByteArray(), StandardCharsets.UTF_8);
//        log.info("[RESPONSE] status={} duration={}ms body=[{}]",
//                wrappedRes.getStatus(), duration, resBody);

        // 복원해서 실제 전송
        wrappedRes.copyBodyToResponse();
    }
}