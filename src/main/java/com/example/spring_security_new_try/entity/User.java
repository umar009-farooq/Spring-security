package com.example.spring_security_new_try.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
@Entity
@Table(name = "_user")
// @Data is a Lombok annotation that generates getters, setters, toString(), equals(), and hashCode() methods.
@Data
// @Builder provides the builder design pattern for creating instances of this class.
@Builder
// @NoArgsConstructor and @AllArgsConstructor are Lombok annotations to generate the respective constructors.
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    // @Id marks this field as the primary key.
    @Id
    // @GeneratedValue specifies how the primary key should be generated. IDENTITY means it's auto-incremented by the database.
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // A unique username for the user.
    private String username;

    // The user's hashed password.
    private String password;

    // The user's role, which will be used for authorization.
    private String role;


    // --- UserDetails Methods ---
    // These methods are required by Spring Security. They provide user details to the framework.

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // This method must return a collection of roles/permissions.
        // We create a SimpleGrantedAuthority from our user's role string.
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getPassword() {
        // Returns the user's password.
        return password;
    }

    @Override
    public String getUsername() {
        // Returns the user's username.
        return username;
    }

    // The following methods can be used to control account status. For now, we'll hard-code them to true.
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}