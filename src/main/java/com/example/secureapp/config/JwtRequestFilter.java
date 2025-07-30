package com.example.secureapp.config;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtRequestFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        token = token.substring(7);
        DecodedJWT decodedJWT = jwtService.verifyToken(token);
        if (decodedJWT == null || decodedJWT.getSubject() == null) {
            filterChain.doFilter(request, response);
            return;
        }

        var context = SecurityContextHolder.createEmptyContext();
        log.info("Decoded username: {}, roles: {}", decodedJWT.getSubject(), decodedJWT.getClaim("roles"));
        final UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                decodedJWT.getSubject(), null, AuthorityUtils.createAuthorityList(decodedJWT.getClaim("roles").asList(String.class))
        );
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request,response);
    }
}
