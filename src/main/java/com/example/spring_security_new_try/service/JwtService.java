package com.example.spring_security_new_try.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// @Service marks this as a Spring component, making it available for dependency injection.
@Service
public class JwtService {

    // This is a CRITICAL component. It's a secret key used to sign the JWTs.
    // It MUST be a Base64-encoded string and at least 256 bits (32 bytes) long for the HS256 algorithm.
    // You should store this securely, e.g., in application properties or an environment variable.
    private static final String SECRET_KEY = "NDQ1ZjNkNDc1N2FmNDI0NDc1MjI5NzgzMmM1ZjY2Mjk1NDE1NzY0MmY0NjYyNjE1ZTI0NzI2YzM0MzU0NzMzNTc=";

    /**
     * Extracts the username (subject) from the JWT.
     * @param token The JWT.
     * @return The username.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }


    /* A generic method to extract any information (a "claim") from the token.
     * @param token The JWT.
     * @param claimsResolver A function to extract a specific claim.
     * @param <T> The type of the claim.
     * @return The claim value.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a new JWT for a given user.
     * @param userDetails The user details object.
     * @return The generated JWT.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a new JWT with extra claims.
     * @param extraClaims Additional claims to include in the token.
     * @param userDetails The user details object.
     * @return The generated JWT.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Token valid for 24 hours
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates a token. Checks if the username in the token matches the UserDetails
     * and if the token has not expired.
     * @param token The JWT.
     * @param userDetails The user details to validate against.
     * @return True if the token is valid, false otherwise.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Parses the token to extract all its claims.
     * @param token The JWT.
     * @return The claims.
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Decodes the Base64 secret key and prepares it for signing.
     * @return The signing key.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
