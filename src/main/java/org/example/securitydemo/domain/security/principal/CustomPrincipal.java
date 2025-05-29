package org.example.securitydemo.domain.security.principal;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class CustomPrincipal {
//    private final Long id;
    private final String email;
//    private final String name;
//    private final Collection<? extends GrantedAuthority> authorities;
}
