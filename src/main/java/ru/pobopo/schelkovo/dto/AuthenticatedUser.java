package ru.pobopo.schelkovo.dto;

import io.jsonwebtoken.Claims;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Getter
@RequiredArgsConstructor
public class AuthenticatedUser implements Serializable, Principal {
    private static final String USERNAME_CLAIM = "username";

    private final String username;

    public static AuthenticatedUser fromClaims(Claims claims) {
        return new AuthenticatedUser(claims.get(USERNAME_CLAIM, String.class));
    }

    public static AuthenticatedUser fromDetails(UserDetails userDetails) {
        return new AuthenticatedUser(userDetails.getUsername());
    }

    public Map<String, Object> toClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put(USERNAME_CLAIM, username);
        return claims;
    }


    @Override
    public String getName() {
        return username;
    }
}
