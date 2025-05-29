package org.example.securitydemo.domain.global.exception;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class RestExceptionHandler {
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthFail(AuthenticationException ex, HttpServletRequest req) {
        return error(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_FAILED", ex.getMessage(), req);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDenied(AccessDeniedException ex, HttpServletRequest req) {
        return error(HttpStatus.FORBIDDEN, "ACCESS_DENIED", ex.getMessage(), req);
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<?> handleJwt(JwtException ex, HttpServletRequest req) {
        return error(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", ex.getMessage(), req);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleOther(Exception ex, HttpServletRequest req) {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", ex.getMessage(), req);
    }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String code, String msg, HttpServletRequest req) {
        Map<String,Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", code,
                "message", msg,
                "path", req.getRequestURI()
        );
        return ResponseEntity.status(status).body(body);
    }
}
