package com.emp.oauth;

import java.time.Instant;

public class AuthRequestRecord {

    private final String id;
    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final String resource;
    private final String codeChallenge;
    private final String codeChallengeMethod;
    private final String originalState;
    private final String userId;
    private final Instant expiresAt;

    public AuthRequestRecord(String id, String clientId, String redirectUri, String scope, String resource,
            String codeChallenge, String codeChallengeMethod, String originalState, String userId, Instant expiresAt) {
        this.id = id;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.resource = resource;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.originalState = originalState;
        this.userId = userId;
        this.expiresAt = expiresAt;
    }

    public String getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getResource() {
        return resource;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public String getOriginalState() {
        return originalState;
    }

    public String getUserId() {
        return userId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
