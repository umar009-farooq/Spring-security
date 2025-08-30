package com.example.spring_security_new_try.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// This controller contains a single endpoint that is protected by our JWT security configuration.
@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {

    /**
     * This endpoint can only be accessed by an authenticated user.
     * @return A success message.
     */
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from a secured endpoint!");
    }
}
