package com.example.secureapp.controller;

import com.example.secureapp.config.JwtService;
import com.example.secureapp.service.UserManagement;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
public class CommonController {

    private final AuthenticationManager authenticationManager;
    private final UserManagement userManagement;
    private final JwtService  jwtService;

    public CommonController(AuthenticationManager authenticationManager, UserManagement userManagement, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.userManagement = userManagement;
        this.jwtService = jwtService;
    }

    @GetMapping("/hello")
    public ResponseEntity<?> hello(){
        return ResponseEntity.ok().body(Map.of("message", "Hello World!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
        Authentication authenticationRespponse = null;
        try {
            authenticationRespponse  = authenticationManager.authenticate(authenticationRequest);
        } catch (BadCredentialsException e) {
            return  ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        final UserDetails userDetails = userManagement.loadUserByUsername(authenticationRespponse.getName());
        String[] rolesArray = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
        final String token = jwtService.createToken(userDetails.getUsername(), rolesArray);
        return ResponseEntity.ok().body(Map.of("token", token));
    }
}

record LoginRequest(String username, String password) {
}
