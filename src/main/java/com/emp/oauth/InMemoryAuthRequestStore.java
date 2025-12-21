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
}
