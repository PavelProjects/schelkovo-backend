package ru.pobopo.schelkovo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final AuthenticationService authenticationService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User admin = authenticationService.getAdmin();
        if (admin.getUsername().equals(username)) {
            return new User(admin.getUsername(), admin.getPassword(), List.of());
        }
        throw new UsernameNotFoundException("User with username " + username + " not found");
    }
}
