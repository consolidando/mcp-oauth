package com.emp.oauth;

public class GoogleIdToken {

    private final String subject;
    private final String email;
    private final Boolean emailVerified;

    public GoogleIdToken(String subject, String email, Boolean emailVerified) {
        this.subject = subject;
        this.email = email;
        this.emailVerified = emailVerified;
    }

    public String getSubject() {
        return subject;
    }

    public String getEmail() {
        return email;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }
}
