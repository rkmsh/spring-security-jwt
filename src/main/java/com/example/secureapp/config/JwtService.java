package com.example.secureapp.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

@Slf4j
@Component
public class JwtService {

    private final Algorithm hmac256;
    private final JWTVerifier jwtVerifier;

    public JwtService(@Value("${SECRET_KEY:secretkey}") String secretKey) {
        this.hmac256 = Algorithm.HMAC256(secretKey);
        this.jwtVerifier = JWT.require(hmac256).build();
    }

    public String createToken(String username, String[] roles){

        return JWT.create()
                .withIssuer("secureapp")
                .withSubject(username)
                .withArrayClaim("roles", roles)
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
                .sign(hmac256);
    }

    DecodedJWT verifyToken(String token){
        try {
            return jwtVerifier.verify(token);
        } catch (JWTVerificationException e) {
            log.error("JWT verification failed ==> {}", e.getMessage());
            return null;
        }
    }
}
