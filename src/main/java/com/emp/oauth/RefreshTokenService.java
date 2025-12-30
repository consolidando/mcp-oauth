package com.emp.oauth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class RefreshTokenService {

    @ConfigProperty(name = "emp.oauth.refresh-token-ttl-seconds", defaultValue = "2592000")
    long refreshTokenTtlSeconds;

    @Inject
    RefreshTokenStoreService refreshTokenStoreService;

    public String issueToken(String clientId, String userId, String scope, String resource) {
        String token = generateToken();
        RefreshTokenRecord record = new RefreshTokenRecord(
                token,
                clientId,
                userId,
                scope,
                resource,
                Instant.now().plusSeconds(refreshTokenTtlSeconds));
        refreshTokenStoreService.save(record);
        return token;
    }

    private String generateToken() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
