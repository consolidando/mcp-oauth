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

    public void updateLastUsedAt(String clientId, java.time.Instant lastUsedAt) {
        ClientRecord existing = clients.get(clientId);
        if (existing == null) {
            return;
        }
        ClientRecord updated = new ClientRecord(
                existing.getClientId(),
                existing.getClientName(),
                existing.getRedirectUris(),
                existing.getTokenEndpointAuthMethod(),
                existing.getCreatedAt(),
                lastUsedAt);
        clients.put(clientId, updated);
    }

    public int cleanupInactive(java.time.Instant cutoff) {
        int removed = 0;
        for (var entry : clients.entrySet()) {
            ClientRecord record = entry.getValue();
            java.time.Instant lastUsedAt = record.getLastUsedAt() == null
                    ? record.getCreatedAt()
                    : record.getLastUsedAt();
            if (lastUsedAt.isBefore(cutoff)) {
                clients.remove(entry.getKey());
                removed++;
            }
        }
        return removed;
    }
}
