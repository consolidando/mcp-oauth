package com.emp.oauth;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.SetOptions;

@ApplicationScoped
public class FirestoreAuthorizationCodeStore {

    @ConfigProperty(name = "emp.oauth.firestore.auth-codes-collection", defaultValue = "authCodes")
    String collectionName;

    @Inject
    Firestore firestore;

    public void save(AuthorizationCodeRecord record) {
        Map<String, Object> data = new java.util.HashMap<>();
        data.put("code", record.getCode());
        data.put("clientId", record.getClientId());
        data.put("userId", record.getUserId());
        data.put("redirectUri", record.getRedirectUri());
        if (record.getScope() != null) {
            data.put("scope", record.getScope());
        }
        if (record.getResource() != null) {
            data.put("resource", record.getResource());
        }
        data.put("codeChallenge", record.getCodeChallenge());
        data.put("codeChallengeMethod", record.getCodeChallengeMethod());
        data.put("expiresAt", Timestamp.ofTimeSecondsAndNanos(
                record.getExpiresAt().getEpochSecond(), record.getExpiresAt().getNano()));
        if (record.getUsedAt() != null) {
            data.put("usedAt", Timestamp.ofTimeSecondsAndNanos(
                    record.getUsedAt().getEpochSecond(), record.getUsedAt().getNano()));
        }
        try {
            firestore.collection(collectionName)
                    .document(record.getCode())
                    .set(data, SetOptions.merge())
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save auth code", e);
        }
    }

    public Optional<AuthorizationCodeRecord> find(String code) {
        try {
            DocumentSnapshot snapshot = firestore.collection(collectionName).document(code).get().get();
            if (!snapshot.exists()) {
                return Optional.empty();
            }
            Instant expiresAt = Optional.ofNullable(snapshot.getTimestamp("expiresAt"))
                    .map(ts -> Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos()))
                    .orElse(Instant.now());
            AuthorizationCodeRecord record = new AuthorizationCodeRecord(
                    code,
                    snapshot.getString("clientId"),
                    snapshot.getString("userId"),
                    snapshot.getString("redirectUri"),
                    snapshot.getString("scope"),
                    snapshot.getString("resource"),
                    snapshot.getString("codeChallenge"),
                    snapshot.getString("codeChallengeMethod"),
                    expiresAt);
            if (snapshot.getTimestamp("usedAt") != null) {
                record.markUsed(Instant.ofEpochSecond(
                        snapshot.getTimestamp("usedAt").getSeconds(),
                        snapshot.getTimestamp("usedAt").getNanos()));
            }
            return Optional.of(record);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load auth code", e);
        }
    }

    public void markUsed(String code) {
        try {
            Timestamp now = Timestamp.now();
            firestore.collection(collectionName)
                    .document(code)
                    .update(Map.of("usedAt", now))
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to mark auth code used", e);
        }
    }
}
