package com.emp.oauth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class AuthorizationCodeService {

    @ConfigProperty(name = "emp.oauth.auth-code-ttl-seconds", defaultValue = "300")
    long authCodeTtlSeconds;

    @Inject
    InMemoryAuthorizationCodeStore codeStore;

    public String issueCode(String clientId, String redirectUri, String scope, String resource, String codeChallenge,
            String codeChallengeMethod, String userId) {
        String code = generateCode();
        AuthorizationCodeRecord record = new AuthorizationCodeRecord(
                code,
                clientId,
                userId,
                redirectUri,
                scope,
                resource,
                codeChallenge,
                codeChallengeMethod,
                Instant.now().plusSeconds(authCodeTtlSeconds));
        codeStore.save(record);
        return code;
    }

    private String generateCode() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
