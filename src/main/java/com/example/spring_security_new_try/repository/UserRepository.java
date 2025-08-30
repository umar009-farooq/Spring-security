package com.example.spring_security_new_try.repository;

import com.example.spring_security_new_try.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// @Repository marks this interface as a Spring component, making it eligible for dependency injection.
public interface UserRepository extends JpaRepository<User, Long> {

    // JpaRepository<User, Long> means this repository will work with the User entity,
    // and the type of the primary key is Long.

    Optional<User> findByUsername(String username);
}
