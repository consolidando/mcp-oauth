package com.emp.oauth;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.Firestore;

@ApplicationScoped
public class FirestoreUserStore {

    @ConfigProperty(name = "emp.oauth.firestore.users-collection", defaultValue = "users")
    String usersCollection;

    @Inject
    Firestore firestore;

    public void upsertGoogleUser(GoogleIdToken idToken) {
        String userId = idToken.getSubject();
        Instant now = Instant.now();
        Map<String, Object> data = new HashMap<>();
        data.put("googleSub", userId);
        data.put("userId", userId);
        if (idToken.getEmail() != null) {
            data.put("email", idToken.getEmail());
        }
        if (idToken.getEmailVerified() != null) {
            data.put("emailVerified", idToken.getEmailVerified());
        }
        Timestamp timestamp = Timestamp.ofTimeSecondsAndNanos(now.getEpochSecond(), now.getNano());
        data.put("lastLoginAt", timestamp);
        data.putIfAbsent("createdAt", timestamp);
        try {
            firestore.collection(usersCollection)
                    .document(userId)
                    .set(data, com.google.cloud.firestore.SetOptions.merge())
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to upsert user in Firestore", e);
        }
    }
}
