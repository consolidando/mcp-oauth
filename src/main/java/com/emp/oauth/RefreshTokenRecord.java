package com.emp.oauth;

import java.time.Instant;

public class RefreshTokenRecord {

    private final String token;
    private final String clientId;
    private final String userId;
    private final String scope;
    private final String resource;
    private final Instant expiresAt;
    private Instant usedAt;
    private String rotatedTo;

    public RefreshTokenRecord(String token, String clientId, String userId, String scope, String resource,
            Instant expiresAt) {
        this.token = token;
        this.clientId = clientId;
        this.userId = userId;
        this.scope = scope;
        this.resource = resource;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return token;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserId() {
        return userId;
    }

    public String getScope() {
        return scope;
    }

    public String getResource() {
        return resource;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public String getRotatedTo() {
        return rotatedTo;
    }

    public void markUsed(Instant now, String rotatedTo) {
        this.usedAt = now;
        this.rotatedTo = rotatedTo;
    }
}
