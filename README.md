# 스프링 시큐리티(내 입맛대로)

언젠가는 재사용을 할 것이라 생각하고, 완전 무상태(stateless)에 확장성 있는 구조로 설계 및 구현했다.

### 주요 기능

1. 로컬 로그인
2. 카카오, 구글 OIDC 로그인
3. 토큰 갱신
4. 로그아웃(Redis 리프레시 토큰 삭제 + 쿠키 만료)
5. 회원가입

---

인증·인가 구조

- 액세스 토큰
  - JWT, HttpOnly 쿠키, SameSite=Lax, 1시간 만료

- 리프레시 토큰
  - JWT, HttpOnly 쿠키, SameSite=Lax, 30일 만료
  - Redis에 JTI 저장 → 토큰 회전(Rotation) 및 강제 만료 관리

---

### 요청 처리 필터 체인
1. RequestResponseLoggingFilter
  - 모든 요청·응답 로그를 남김

2. RedisRateLimitingFilter
  - 로그인·리프레시 엔드포인트에 Bucket4j 기반 분산 속도 제한 적용

3. CsrfFilter
  - Double-submit 전략 + CookieCsrfTokenRepository 사용하여 이중 CSRF 방어

5. JwtAuthenticationFilter
  - access_token 쿠키에서 JWT 추출·검증 → SecurityContext 설정

5. OAuth2Login DSL
  - authorizationRequestRepository를 커스텀하여 무상태 인가 요청 관리
  - OIDC 표준 및 카카오 API 모두 지원
  - 로그인 성공 시 JWT 발급 + 신규 사용자 DB 자동 등록
  - 로그인 실패 시 에러 로깅 후 SPA 진입점(/auth/login)으로 리다이렉트
