package com.emp.oauth;

import java.time.Instant;

public class AuthorizationCodeRecord {

    private final String code;
    private final String clientId;
    private final String userId;
    private final String redirectUri;
    private final String scope;
    private final String resource;
    private final String codeChallenge;
    private final String codeChallengeMethod;
    private final Instant expiresAt;
    private Instant usedAt;

    public AuthorizationCodeRecord(String code, String clientId, String userId, String redirectUri, String scope,
            String resource, String codeChallenge, String codeChallengeMethod, Instant expiresAt) {
        this.code = code;
        this.clientId = clientId;
        this.userId = userId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.resource = resource;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAt = expiresAt;
    }

    public String getCode() {
        return code;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserId() {
        return userId;
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

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public void markUsed(Instant now) {
        this.usedAt = now;
    }

}
