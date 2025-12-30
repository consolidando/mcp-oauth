package com.emp.oauth;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.SetOptions;

@ApplicationScoped
public class FirestoreRefreshTokenStore {

    @ConfigProperty(name = "emp.oauth.firestore.refresh-tokens-collection", defaultValue = "refreshTokens")
    String collectionName;

    @Inject
    Firestore firestore;

    public void save(RefreshTokenRecord record) {
        Map<String, Object> data = new HashMap<>();
        data.put("token", record.getToken());
        data.put("clientId", record.getClientId());
        data.put("userId", record.getUserId());
        if (record.getScope() != null) {
            data.put("scope", record.getScope());
        }
        if (record.getResource() != null) {
            data.put("resource", record.getResource());
        }
        data.put("expiresAt", Timestamp.ofTimeSecondsAndNanos(
                record.getExpiresAt().getEpochSecond(), record.getExpiresAt().getNano()));
        if (record.getUsedAt() != null) {
            data.put("usedAt", Timestamp.ofTimeSecondsAndNanos(
                    record.getUsedAt().getEpochSecond(), record.getUsedAt().getNano()));
        }
        if (record.getRotatedTo() != null) {
            data.put("rotatedTo", record.getRotatedTo());
        }
        try {
            firestore.collection(collectionName)
                    .document(record.getToken())
                    .set(data, SetOptions.merge())
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save refresh token", e);
        }
    }

    public Optional<RefreshTokenRecord> find(String token) {
        try {
            DocumentSnapshot snapshot = firestore.collection(collectionName).document(token).get().get();
            if (!snapshot.exists()) {
                return Optional.empty();
            }
            Instant expiresAt = Optional.ofNullable(snapshot.getTimestamp("expiresAt"))
                    .map(ts -> Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos()))
                    .orElse(Instant.now());
            RefreshTokenRecord record = new RefreshTokenRecord(
                    token,
                    snapshot.getString("clientId"),
                    snapshot.getString("userId"),
                    snapshot.getString("scope"),
                    snapshot.getString("resource"),
                    expiresAt);
            if (snapshot.getTimestamp("usedAt") != null) {
                record.markUsed(Instant.ofEpochSecond(
                        snapshot.getTimestamp("usedAt").getSeconds(),
                        snapshot.getTimestamp("usedAt").getNanos()),
                        snapshot.getString("rotatedTo"));
            }
            return Optional.of(record);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load refresh token", e);
        }
    }

    public void markUsed(String token, String rotatedTo) {
        try {
            Timestamp now = Timestamp.now();
            Map<String, Object> updates = new HashMap<>();
            updates.put("usedAt", now);
            if (rotatedTo != null) {
                updates.put("rotatedTo", rotatedTo);
            }
            firestore.collection(collectionName)
                    .document(token)
                    .update(updates)
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to mark refresh token used", e);
        }
    }

    public int cleanup(Instant now) {
        try {
            Timestamp cutoff = Timestamp.ofTimeSecondsAndNanos(now.getEpochSecond(), now.getNano());
            java.util.Set<String> ids = new java.util.HashSet<>();
            var expiresSnapshot = firestore.collection(collectionName)
                    .whereLessThan("expiresAt", cutoff)
                    .get()
                    .get();
            for (QueryDocumentSnapshot doc : expiresSnapshot.getDocuments()) {
                ids.add(doc.getId());
            }
            var usedSnapshot = firestore.collection(collectionName)
                    .whereLessThan("usedAt", cutoff)
                    .get()
                    .get();
            for (QueryDocumentSnapshot doc : usedSnapshot.getDocuments()) {
                ids.add(doc.getId());
            }
            int removed = 0;
            for (String id : ids) {
                firestore.collection(collectionName).document(id).delete().get();
                removed++;
            }
            return removed;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to cleanup refresh tokens", e);
        }
    }
}
