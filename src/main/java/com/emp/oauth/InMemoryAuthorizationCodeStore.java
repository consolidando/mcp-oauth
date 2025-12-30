package com.emp.oauth;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class InMemoryAuthorizationCodeStore {

    private final ConcurrentMap<String, AuthorizationCodeRecord> codes = new ConcurrentHashMap<>();

    public void save(AuthorizationCodeRecord record) {
        codes.put(record.getCode(), record);
    }

    public Optional<AuthorizationCodeRecord> find(String code) {
        return Optional.ofNullable(codes.get(code));
    }

    public int cleanup(java.time.Instant now) {
        int removed = 0;
        for (var entry : codes.entrySet()) {
            AuthorizationCodeRecord record = entry.getValue();
            if (record.getUsedAt() != null || record.getExpiresAt().isBefore(now)) {
                codes.remove(entry.getKey());
                removed++;
            }
        }
        return removed;
    }
}
