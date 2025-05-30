package ru.pobopo.schelkovo.controller.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;
import ru.pobopo.schelkovo.dto.AuthenticatedUser;
import ru.pobopo.schelkovo.jwt.JwtTokenUtil;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityFilter extends OncePerRequestFilter {
    public static final String USER_COOKIE_NAME = "SchlkJWT";
    private static final String USER_TOKEN_HEADER = "User-Token";

    private final JwtTokenUtil jwtTokenUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Cookie cookie = WebUtils.getCookie(request, USER_COOKIE_NAME);
        String token = StringUtils.firstNonBlank(
                cookie != null ? cookie.getValue() : null,
                request.getHeader(USER_TOKEN_HEADER)
        );
        if (StringUtils.isNotBlank(token)) {
            try {
                if (jwtTokenUtil.isTokenExpired(token)) {
                    throw new AccessDeniedException("Token expired!");
                }
                Claims claims = jwtTokenUtil.getAllClaimsFromToken(token);
                AuthenticatedUser authenticatedUser = AuthenticatedUser.fromClaims(claims);
                setUserDetailsToContext(authenticatedUser, request);
            } catch (Exception e) {
                log.error("Token validation failed: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private void setUserDetailsToContext(AuthenticatedUser authenticatedUser, HttpServletRequest request) {
        if (authenticatedUser == null) {
            return;
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                authenticatedUser,
            "",
                List.of()
        );
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
