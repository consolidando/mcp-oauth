package com.emp.oauth;

import java.time.Instant;
import java.util.List;

public class ClientRecord {

    private final String clientId;
    private final String clientName;
    private final List<String> redirectUris;
    private final String tokenEndpointAuthMethod;
    private final Instant createdAt;

    public ClientRecord(String clientId, String clientName, List<String> redirectUris,
            String tokenEndpointAuthMethod, Instant createdAt) {
        this.clientId = clientId;
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.createdAt = createdAt;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
