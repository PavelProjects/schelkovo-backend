package ru.pobopo.schelkovo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.pobopo.schelkovo.dto.AuthRequest;
import ru.pobopo.schelkovo.dto.AuthenticatedUser;
import ru.pobopo.schelkovo.service.AuthenticationService;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final AuthenticationService authenticationService;

    @GetMapping
    public AuthenticatedUser authenticatedUser(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        return authenticatedUser;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticatedUser> authenticateUser(
            @RequestBody AuthRequest request
    ) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        if (!auth.isAuthenticated()) {
            throw new BadCredentialsException("Wrong user credits");
        }
        return authenticationService.authenticate(auth);
    }
}
