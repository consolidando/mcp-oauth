package com.emp.oauth;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class InMemoryRefreshTokenStore {

    private final ConcurrentMap<String, RefreshTokenRecord> tokens = new ConcurrentHashMap<>();

    public void save(RefreshTokenRecord record) {
        tokens.put(record.getToken(), record);
    }

    public Optional<RefreshTokenRecord> find(String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    public void markUsed(String token, String rotatedTo) {
        RefreshTokenRecord record = tokens.get(token);
        if (record == null) {
            return;
        }
        record.markUsed(Instant.now(), rotatedTo);
    }

    public int cleanup(java.time.Instant now) {
        int removed = 0;
        for (var entry : tokens.entrySet()) {
            RefreshTokenRecord record = entry.getValue();
            if (record.getUsedAt() != null || record.getExpiresAt().isBefore(now)) {
                tokens.remove(entry.getKey());
                removed++;
            }
        }
        return removed;
    }
}
