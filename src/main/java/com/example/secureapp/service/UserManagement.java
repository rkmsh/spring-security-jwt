package com.example.secureapp.service;

import com.example.secureapp.config.JwtUserDetail;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class UserManagement implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserManagement(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void saveUser(String email, String password, String role) {
        userRepository.findByEmail(email).ifPresentOrElse(user -> {
            throw new RuntimeException("User exists");
                },
        () -> {
            userRepository.save(new UserInfo().setEmail(email).setPassword(passwordEncoder.encode(password)).setRoles(role));
        });
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserInfo user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority(user.getRoles()));
        return new JwtUserDetail(user.getId(), user.getEmail(), user.getPassword(), grantedAuthorities);
    }
}

interface UserRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByEmail(String email);
}

@Entity
@Table(name = "userinfo")
@Getter
@Setter
@NoArgsConstructor
@Accessors(chain = true)
class UserInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String password;
    private String email;
    private String roles;
}
