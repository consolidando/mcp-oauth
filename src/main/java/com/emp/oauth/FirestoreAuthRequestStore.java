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
public class FirestoreAuthRequestStore {

    @ConfigProperty(name = "emp.oauth.firestore.auth-requests-collection", defaultValue = "authRequests")
    String collectionName;

    @Inject
    Firestore firestore;

    public void save(AuthRequestRecord record) {
        Map<String, Object> data = new java.util.HashMap<>();
        data.put("id", record.getId());
        data.put("clientId", record.getClientId());
        data.put("redirectUri", record.getRedirectUri());
        if (record.getScope() != null) {
            data.put("scope", record.getScope());
        }
        if (record.getResource() != null) {
            data.put("resource", record.getResource());
        }
        data.put("codeChallenge", record.getCodeChallenge());
        data.put("codeChallengeMethod", record.getCodeChallengeMethod());
        if (record.getOriginalState() != null) {
            data.put("originalState", record.getOriginalState());
        }
        if (record.getUserId() != null) {
            data.put("userId", record.getUserId());
        }
        data.put("expiresAt", Timestamp.ofTimeSecondsAndNanos(
                record.getExpiresAt().getEpochSecond(), record.getExpiresAt().getNano()));
        try {
            firestore.collection(collectionName)
                    .document(record.getId())
                    .set(data, SetOptions.merge())
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save auth request", e);
        }
    }

    public Optional<AuthRequestRecord> find(String id) {
        try {
            DocumentSnapshot snapshot = firestore.collection(collectionName).document(id).get().get();
            if (!snapshot.exists()) {
                return Optional.empty();
            }
            Instant expiresAt = Optional.ofNullable(snapshot.getTimestamp("expiresAt"))
                    .map(ts -> Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos()))
                    .orElse(Instant.now());
            AuthRequestRecord record = new AuthRequestRecord(
                    id,
                    snapshot.getString("clientId"),
                    snapshot.getString("redirectUri"),
                    snapshot.getString("scope"),
                    snapshot.getString("resource"),
                    snapshot.getString("codeChallenge"),
                    snapshot.getString("codeChallengeMethod"),
                    snapshot.getString("originalState"),
                    snapshot.getString("userId"),
                    expiresAt);
            return Optional.of(record);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load auth request", e);
        }
    }

    public void remove(String id) {
        try {
            firestore.collection(collectionName).document(id).delete().get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to delete auth request", e);
        }
    }

    public void updateUserId(String id, String userId) {
        try {
            firestore.collection(collectionName)
                    .document(id)
                    .update(Map.of("userId", userId))
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to update auth request userId", e);
        }
    }
}
