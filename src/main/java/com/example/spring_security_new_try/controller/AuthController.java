package com.example.spring_security_new_try.controller;
import com.example.spring_security_new_try.DTO.RegisterRequest;
import com.example.spring_security_new_try.DTO.AuthRequest;
import com.example.spring_security_new_try.DTO.AuthResponse;
import com.example.spring_security_new_try.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// This controller exposes the public endpoints for registration and authentication.
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint for user registration.
     * @param request The registration request body.
     * @return A ResponseEntity containing the JWT.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Endpoint for user authentication (login).
     * @param request The authentication request body.
     * @return A ResponseEntity containing the JWT.
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthResponse> authenticate(@RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
