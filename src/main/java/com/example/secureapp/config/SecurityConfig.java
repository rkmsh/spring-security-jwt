package com.example.secureapp.config;

import com.example.secureapp.service.UserManagement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    JwtRequestFilter jwtRequestFilter(final JwtService jwtService) {
        return new JwtRequestFilter(jwtService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/login", "/h2-console/**").permitAll();
                    authorize.anyRequest().authenticated();
                })
                .headers(httpHeaders -> {
                    httpHeaders.frameOptions(frameOptions -> frameOptions.disable());
                })
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtRequestFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserManagement userManagement) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userManagement);

        return new ProviderManager(Arrays.asList(daoAuthenticationProvider));
    }
}
