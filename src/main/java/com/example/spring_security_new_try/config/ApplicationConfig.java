package com.example.spring_security_new_try.config;

import com.example.spring_security_new_try.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// @Configuration indicates that this class contains Spring configuration.
@Configuration
// @RequiredArgsConstructor is a Lombok annotation that generates a constructor with required final fields.
@RequiredArgsConstructor
public class ApplicationConfig {

    // Spring will inject the UserRepository bean we created earlier.
    private final UserRepository userRepository;

    /**
     * Defines how to load user details. This is the bridge between our user data and Spring Security.
     * @return An implementation of UserDetailsService.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // We provide a lambda implementation. Given a username, it uses our UserRepository
        // to find the user. If the user isn't found, it throws a standard Spring Security exception.
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }

    /**
     * Defines the password encoder. We must use a strong hashing algorithm.
     * @return A BCryptPasswordEncoder instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the main authentication provider. This bean brings together the user details service
     * and the password encoder.
     * @return A configured DaoAuthenticationProvider.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // Set the service that will be used to fetch user details.
        authProvider.setUserDetailsService(userDetailsService());
        // Set the password encoder that will be used to verify passwords.
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Exposes the AuthenticationManager as a bean. This is the main component that
     * processes an authentication request. We will need this for our login endpoint later.
     * @param config The authentication configuration.
     * @return The AuthenticationManager.
     * @throws Exception If an error occurs.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

