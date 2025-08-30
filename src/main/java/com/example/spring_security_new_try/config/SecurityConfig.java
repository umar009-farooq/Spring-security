package com.example.spring_security_new_try.config;
import com.example.spring_security_new_try.filter.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration and @EnableWebSecurity are essential for activating Spring Security.
@Configuration
@EnableWebSecurity
// @RequiredArgsConstructor injects our final fields via a constructor.
@RequiredArgsConstructor
public class SecurityConfig {

    // Injecting the custom JWT filter and the authentication provider we created earlier.
    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * This bean defines the entire security filter chain, which acts as the firewall for our application.
     * @param http The HttpSecurity object to configure.
     * @return The configured SecurityFilterChain.
     * @throws Exception If an error occurs.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Disable CSRF (Cross-Site Request Forgery) protection. This is common for stateless REST APIs.
                .csrf(csrf -> csrf.disable())

                // 2. Define authorization rules for different endpoints.
                .authorizeHttpRequests(auth -> auth
                        // Allow unauthenticated access to the registration and authentication endpoints.
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        // All other requests must be authenticated.
                        .anyRequest().authenticated()
                )

                // 3. Configure session management to be stateless. This is the core of JWT authentication.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 4. Set the custom authentication provider.
                .authenticationProvider(authenticationProvider)

                // 5. Add our custom JWT filter to the chain, ensuring it runs before the standard username/password filter.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
