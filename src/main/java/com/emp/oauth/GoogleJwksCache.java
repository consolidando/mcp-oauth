package com.emp.oauth;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.databind.ObjectMapper;

@ApplicationScoped
public class GoogleJwksCache {

    private static final Duration CACHE_TTL = Duration.ofMinutes(30);

    @ConfigProperty(name = "emp.oauth.google.jwks-uri")
    String jwksUri;

    @Inject
    ObjectMapper objectMapper;

    private Instant lastFetch;
    private Map<String, RSAPublicKey> cachedKeys = new HashMap<>();

    public Optional<RSAPublicKey> getKey(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return Optional.empty();
        }
        if (isExpired() || !cachedKeys.containsKey(keyId)) {
            refresh();
        }
        return Optional.ofNullable(cachedKeys.get(keyId));
    }

    private boolean isExpired() {
        return lastFetch == null || lastFetch.plus(CACHE_TTL).isBefore(Instant.now());
    }

    private synchronized void refresh() {
        if (!isExpired()) {
            return;
        }
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder(URI.create(jwksUri)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Unable to fetch Google JWKS: " + response.statusCode());
            }
            Map<?, ?> json = objectMapper.readValue(response.body(), Map.class);
            Object keysValue = json.get("keys");
            if (!(keysValue instanceof List<?> keys)) {
                throw new IllegalStateException("Invalid JWKS payload");
            }
            Map<String, RSAPublicKey> next = new HashMap<>();
            for (Object entry : keys) {
                if (!(entry instanceof Map<?, ?> key)) {
                    continue;
                }
                Object kidObj = key.get("kid");
                Object nObj = key.get("n");
                Object eObj = key.get("e");
                if (kidObj instanceof String kid && nObj instanceof String n && eObj instanceof String e) {
                    next.put(kid, toPublicKey(n, e));
                }
            }
            cachedKeys = next;
            lastFetch = Instant.now();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to refresh Google JWKS", e);
        }
    }

    private RSAPublicKey toPublicKey(String n, String e) throws Exception {
        byte[] modulus = Base64.getUrlDecoder().decode(n);
        byte[] exponent = Base64.getUrlDecoder().decode(e);
        BigInteger mod = new BigInteger(1, modulus);
        BigInteger exp = new BigInteger(1, exponent);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
