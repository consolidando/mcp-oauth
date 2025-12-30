package com.emp.oauth;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class InMemoryAuthRequestStore {

    private final ConcurrentMap<String, AuthRequestRecord> requests = new ConcurrentHashMap<>();

    public void save(AuthRequestRecord record) {
        requests.put(record.getId(), record);
    }

    public Optional<AuthRequestRecord> find(String id) {
        return Optional.ofNullable(requests.get(id));
    }

    public void remove(String id) {
        requests.remove(id);
    }

    public void updateUserId(String id, String userId) {
        AuthRequestRecord existing = requests.get(id);
        if (existing == null) {
            return;
        }
        AuthRequestRecord updated = new AuthRequestRecord(
                existing.getId(),
                existing.getClientId(),
                existing.getRedirectUri(),
                existing.getScope(),
                existing.getResource(),
                existing.getCodeChallenge(),
                existing.getCodeChallengeMethod(),
                existing.getOriginalState(),
                userId,
                existing.getExpiresAt());
        requests.put(id, updated);
    }

    public int cleanupExpired(java.time.Instant now) {
        int removed = 0;
        for (var entry : requests.entrySet()) {
            if (entry.getValue().getExpiresAt().isBefore(now)) {
                requests.remove(entry.getKey());
                removed++;
            }
        }
        return removed;
    }
}
