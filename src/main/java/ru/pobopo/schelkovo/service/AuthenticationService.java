package ru.pobopo.schelkovo.service;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.pobopo.schelkovo.dto.AuthenticatedUser;
import ru.pobopo.schelkovo.jwt.JwtTokenUtil;

import java.util.List;

import static ru.pobopo.schelkovo.controller.filter.SecurityFilter.USER_COOKIE_NAME;

@Getter
@Service
@Slf4j
public class AuthenticationService {
    private final User admin;

    // seconds
    @Value("${app.token.ttl:3600}")
    private long tokenTtl;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    public AuthenticationService(
            @Value("${app.admin.username}") String username,
            @Value("${app.admin.password}") String password,
            PasswordEncoder passwordEncoder
    ) {
        if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Admin username and login are required!");
        }

        this.admin = new User(username, passwordEncoder.encode(password), List.of());
    }

    public boolean isAdmin(AuthenticatedUser user) {
        return StringUtils.equals(user.getUsername(), admin.getUsername());
    }

    public ResponseEntity<AuthenticatedUser> authenticate(Authentication authentication) {
        AuthenticatedUser authenticatedUser = AuthenticatedUser.fromDetails((UserDetails) authentication.getPrincipal());
        String token = jwtTokenUtil.doGenerateToken("user", authenticatedUser.toClaims(), tokenTtl);
        log.info("Generated new JWT token for {}", authenticatedUser.getName());

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, buildCookie(token).toString());
        return new ResponseEntity<>(authenticatedUser, headers, HttpStatus.OK);
    }

    private ResponseCookie buildCookie(String token) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(
                        USER_COOKIE_NAME,
                        token
                )
                .path("/")
                .maxAge(tokenTtl)
                .httpOnly(true);
        return builder.build();
    }
}
