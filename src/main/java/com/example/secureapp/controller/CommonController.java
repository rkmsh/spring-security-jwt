package com.example.secureapp.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@RestController
public class CommonController {
    final JwtUtil jwtUtil;

    public CommonController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/hello")
    public ResponseEntity<?> hello() {
        return ResponseEntity.ok().body(Map.of("message", "Hello World!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        String token = jwtUtil.generateToken(loginRequest.username());
        return ResponseEntity.status(HttpStatus.FOUND).body(Map.of("token", token));
    }
}

record LoginRequest(String username, String password) {
}

@Component
class JwtUtil {
    @Value("${SECRET_KEY:secretkey}")
    private String secretKey;


    String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setClaims(Map.of("sub", username,"ROLE", "USER"))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*60*10))
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }
}
