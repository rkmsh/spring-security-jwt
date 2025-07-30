package com.example.secureapp;

import com.example.secureapp.service.UserManagement;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecureappApplication {
	private final UserManagement userManagement;

    public SecureappApplication(UserManagement userManagement) {
        this.userManagement = userManagement;
    }

    public static void main(String[] args) {
		SpringApplication.run(SecureappApplication.class, args);
	}

	@PostConstruct
	public void init(){
		String[] emails = {"email1@em.in", "email2@em.in", "email3@em.in"};
		String[] passwords = {"password1", "password2", "password3"};
		String[] roles = {"admin", "user", "user"};

		for(int i = 0; i < emails.length; i++){
			userManagement.saveUser(emails[i], passwords[i], roles[i]);
		}
	}
}
