package com.emp.oauth;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.databind.ObjectMapper;

@ApplicationScoped
public class GoogleOidcClient {

    private static final String ISSUER_HTTPS = "https://accounts.google.com";
    private static final String ISSUER_PLAIN = "accounts.google.com";
    private static final long CLOCK_SKEW_SECONDS = 300;

    @ConfigProperty(name = "emp.oauth.google.client-id")
    String clientId;

    @ConfigProperty(name = "emp.oauth.google.client-secret")
    String clientSecret;

    @ConfigProperty(name = "emp.oauth.google.redirect-uri")
    String redirectUri;

    @ConfigProperty(name = "emp.oauth.google.auth-endpoint")
    String authEndpoint;

    @ConfigProperty(name = "emp.oauth.google.token-endpoint")
    String tokenEndpoint;

    @ConfigProperty(name = "emp.oauth.google.scope")
    String scope;

    @Inject
    ObjectMapper objectMapper;

    @Inject
    GoogleJwksCache jwksCache;

    public URI buildAuthorizationUrl(String state) {
        String query = "response_type=code"
                + "&client_id=" + urlEncode(clientId)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&scope=" + urlEncode(scope)
                + "&state=" + urlEncode(state)
                + "&access_type=offline"
                + "&include_granted_scopes=true"
                + "&prompt=consent";
        return URI.create(authEndpoint + "?" + query);
    }

    public GoogleIdToken exchangeCode(String code) {
        String body = "code=" + urlEncode(code)
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&grant_type=authorization_code";
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Google token exchange failed: " + response.statusCode());
            }
            Map<?, ?> payload = objectMapper.readValue(response.body(), Map.class);
            Object idToken = payload.get("id_token");
            if (!(idToken instanceof String token)) {
                throw new IllegalStateException("Google token response missing id_token");
            }
            return verifyIdToken(token);
        } catch (Exception e) {
            throw new IllegalStateException("Google token exchange failed", e);
        }
    }

    public GoogleIdToken verifyIdToken(String idToken) {
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalStateException("Invalid id_token");
        }
        try {
            Map<String, Object> header = decodePart(parts[0]);
            Map<String, Object> claims = decodePart(parts[1]);
            String kid = Optional.ofNullable(header.get("kid")).map(Object::toString).orElse(null);
            String alg = Optional.ofNullable(header.get("alg")).map(Object::toString).orElse(null);
            if (!"RS256".equals(alg)) {
                throw new IllegalStateException("Unsupported id_token alg");
            }
            RSAPublicKey publicKey = jwksCache.getKey(kid)
                    .orElseThrow(() -> new IllegalStateException("Unknown id_token key id"));
            String signingInput = parts[0] + "." + parts[1];
            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signature)) {
                throw new IllegalStateException("Invalid id_token signature");
            }
            validateClaims(claims);
            String sub = claims.get("sub").toString();
            String email = claims.containsKey("email") ? claims.get("email").toString() : null;
            Boolean emailVerified = claims.containsKey("email_verified")
                    ? Boolean.valueOf(claims.get("email_verified").toString())
                    : null;
            return new GoogleIdToken(sub, email, emailVerified);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid id_token", e);
        }
    }

    private void validateClaims(Map<String, Object> claims) {
        String iss = Optional.ofNullable(claims.get("iss")).map(Object::toString).orElse("");
        if (!ISSUER_HTTPS.equals(iss) && !ISSUER_PLAIN.equals(iss)) {
            throw new IllegalStateException("Invalid issuer");
        }
        String aud = Optional.ofNullable(claims.get("aud")).map(Object::toString).orElse("");
        if (!clientId.equals(aud)) {
            throw new IllegalStateException("Invalid audience");
        }
        long now = Instant.now().getEpochSecond();
        long exp = Long.parseLong(claims.get("exp").toString());
        long iat = Long.parseLong(claims.get("iat").toString());
        if (now > exp + CLOCK_SKEW_SECONDS) {
            throw new IllegalStateException("Token expired");
        }
        if (iat - CLOCK_SKEW_SECONDS > now) {
            throw new IllegalStateException("Invalid iat");
        }
    }

    private Map<String, Object> decodePart(String part) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(part);
        return objectMapper.readValue(decoded, LinkedHashMap.class);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
