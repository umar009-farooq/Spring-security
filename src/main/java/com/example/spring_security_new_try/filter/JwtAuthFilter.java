package com.example.spring_security_new_try.filter;

import com.example.spring_security_new_try.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// @Component marks this as a Spring component, making it eligible for dependency injection.
// @RequiredArgsConstructor generates a constructor for our final fields.
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    // Injecting our JwtService and UserDetailsService.
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // This is the main method where the filtering logic happens.
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Check for the Authorization header.
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // If the header is missing or doesn't start with "Bearer ", pass the request to the next filter.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract the token from the header (it's after "Bearer ").
        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);

        // 3. Validate the token.
        // If we have a username and the user is not already authenticated...
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load the user details from the database.
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Check if the token is valid for this user.
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // If the token is valid, create an authentication token.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // Credentials are not needed as the user is already authenticated by the token.
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Update the SecurityContextHolder with the new authentication token.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // Pass the request along to the next filter in the chain.
        filterChain.doFilter(request, response);
    }
}
