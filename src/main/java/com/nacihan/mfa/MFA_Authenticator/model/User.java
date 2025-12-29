package com.nacihan.mfa.MFA_Authenticator.model;

import jakarta.persistence.*;
import jakarta.persistence.GeneratedValue;
import org.springframework.boot.context.properties.bind.Name;

@Entity
@Table(name = "APP_USER")

public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;



    private String username;
    private String password;
    private String mfaSecret;

    public User() {}

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        this.mfaSecret = null;
    }

    public Long getId() {return id;}
    public void setId(Long id) {this.id = id;}
    public String getUsername() {return username;}
    public void setUsername(String username) {this.username = username;}
    public String getPassword() {return password;}
    public void setPassword(String password) {this.password = password;}
    public String getMfaSecret() {return mfaSecret;}
    public void setMfaSecret(String mfaSecret) {this.mfaSecret = mfaSecret;}
}


