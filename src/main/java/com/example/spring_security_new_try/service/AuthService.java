package com.example.spring_security_new_try.service;

import com.example.spring_security_new_try.DTO.AuthRequest;
import com.example.spring_security_new_try.DTO.AuthResponse;
import com.example.spring_security_new_try.DTO.RegisterRequest;
import com.example.spring_security_new_try.entity.User;
import com.example.spring_security_new_try.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// This service contains the business logic for user registration and authentication.
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new user.
     * @param request The registration request containing user details.
     * @return An AuthenticationResponse containing the JWT.
     */
    public AuthResponse register(RegisterRequest request) {
        // Create a new User entity from the request.
        var user = User.builder()
                .username(request.getUsername())
                // IMPORTANT: Always encode the password before saving.
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        // Save the new user to the database.
        userRepository.save(user);

        // Generate a JWT for the newly registered user.
        var jwtToken = jwtService.generateToken(user);

        // Return the token in the response.
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    /**
     * Authenticates an existing user.
     * @param request The authentication request containing credentials.
     * @return An AuthenticationResponse containing the JWT.
     */
    public AuthResponse authenticate(AuthRequest request) {
        // The AuthenticationManager will use our UserDetailsService and PasswordEncoder
        // to validate the credentials. It throws an exception if authentication fails.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // If authentication is successful, find the user to generate a token.
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(); // Should not fail if authentication succeeded.

        // Generate the JWT.
        var jwtToken = jwtService.generateToken(user);

        // Return the token.
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }
}
