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
}
