package com.emp.oauth;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class InMemoryClientStore {

    private final ConcurrentMap<String, ClientRecord> clients = new ConcurrentHashMap<>();

    public void save(ClientRecord client) {
        clients.put(client.getClientId(), client);
    }

    public Optional<ClientRecord> findById(String clientId) {
        return Optional.ofNullable(clients.get(clientId));
    }

    public boolean isRedirectUriAllowed(String clientId, String redirectUri) {
        return findById(clientId)
                .map(client -> client.getRedirectUris().contains(redirectUri))
                .orElse(false);
    }
}
