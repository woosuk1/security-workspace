package org.example.securitydemo.domain.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Table(name = "USERS")
@Entity
@Builder
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String name;

    @Column(nullable = false, unique = true, length = 30)
    private String email;

    @Column(nullable = false)
    private String password = "";

    private String phoneNum;

    @Column(name = "user_role", nullable = false)
    @Enumerated(EnumType.STRING)
    private UserRole userRole = UserRole.USER;

    @Column(name = "provider", nullable = false)
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    @Column(name = "provider_id")
    private String providerId;

    private LocalDate createdAt;


    //== 패스워드 암호화 ==//
    public void encodePassword(PasswordEncoder passwordEncoder){
        this.password = passwordEncoder.encode(password);
    }

}
