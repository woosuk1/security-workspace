package org.example.securitydemo.domain.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.securitydemo.domain.user.entity.AuthProvider;
import org.example.securitydemo.domain.user.entity.UserRole;
import org.example.securitydemo.domain.user.entity.Users;
import org.example.securitydemo.domain.user.repository.UsersRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

//import static org.example.securitydemo.domain.entity.UserRole.ROLE_USER;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Users user = usersRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .roles(user.getUserRole().name()) // 또는 .authorities(...) 도 가능
                .build();
    }

    @Transactional
    public void registerUser(String email, String rawPassword) {
        if (usersRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }
        Users user = Users.builder()
                .email(email)
                .password(passwordEncoder.encode(rawPassword))
                .userRole(UserRole.USER) // 기본 역할 설정
                .provider(AuthProvider.LOCAL) // enum 필드: LOCAL, GOOGLE, KAKAO
                .build();
        usersRepository.save(user);
    }

    @Transactional
    public Users processOAuth2User(String email, Map<String, Object> attributes) {
        Optional<Users> existingUser = usersRepository.findByEmail(email);
        if(existingUser.isPresent()){
            return existingUser.get();
        }

        log.info("신규 OAuth2 사용자 등록: {}", email);

        // 신규 사용자 처리
        Users newUser = Users.builder()
                .email(email)
                .password(passwordEncoder.encode("defaultPassword")) // OAuth2 사용자에게는 기본 비밀번호 설정
                .userRole(UserRole.USER) // 기본 역할 설정
                .provider(AuthProvider.GOOGLE) // enum 필드: LOCAL, GOOGLE, KAKAO
                .providerId((String) attributes.get("sub")) // google 고유 id
                .build();

        return usersRepository.save(newUser);
    }
}
