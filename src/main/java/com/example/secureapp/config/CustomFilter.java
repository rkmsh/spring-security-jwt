package com.example.secureapp.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;

public class CustomFilter extends OncePerRequestFilter {
    @Value("${SECRET_KEY:secretkey}")
    private String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(!request.getRequestURI().startsWith("/login")) {
            String fullToken = request.getHeader("Authorization");
            String token = fullToken.substring(7);
            JwtParser parser = Jwts.parser().setSigningKey(secretKey).build();

            var claims = parser.parseClaimsJws(token);
            {
                System.out.println("Claims ==>> " + claims);
            }
            if(true) {
                response.getWriter().write(token.toString());
                response.setStatus(HttpServletResponse.SC_OK);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
