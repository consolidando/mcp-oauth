package com.emp.oauth;

import java.time.Instant;
import java.util.List;
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
public class FirestoreClientStore {

    @ConfigProperty(name = "emp.oauth.firestore.clients-collection", defaultValue = "clients")
    String clientsCollection;

    @Inject
    Firestore firestore;

    public void save(ClientRecord client) {
        Instant createdAt = client.getCreatedAt() == null ? Instant.now() : client.getCreatedAt();
        Map<String, Object> data = new java.util.HashMap<>();
        data.put("clientId", client.getClientId());
        if (client.getClientName() != null) {
            data.put("clientName", client.getClientName());
        }
        data.put("redirectUris", client.getRedirectUris());
        if (client.getTokenEndpointAuthMethod() != null) {
            data.put("tokenEndpointAuthMethod", client.getTokenEndpointAuthMethod());
        }
        data.put("createdAt", Timestamp.ofTimeSecondsAndNanos(createdAt.getEpochSecond(), createdAt.getNano()));
        data.put("status", "active");
        try {
            firestore.collection(clientsCollection)
                    .document(client.getClientId())
                    .set(data, SetOptions.merge())
                    .get();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save client to Firestore", e);
        }
    }

    public Optional<ClientRecord> findById(String clientId) {
        try {
            DocumentSnapshot snapshot = firestore.collection(clientsCollection)
                    .document(clientId)
                    .get()
                    .get();
            if (!snapshot.exists()) {
                return Optional.empty();
            }
            String name = snapshot.getString("clientName");
            List<String> redirectUris = (List<String>) snapshot.get("redirectUris");
            String tokenEndpointAuthMethod = snapshot.getString("tokenEndpointAuthMethod");
            Instant createdAt = Optional.ofNullable(snapshot.getTimestamp("createdAt"))
                    .map(ts -> Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos()))
                    .orElse(Instant.now());
            return Optional.of(new ClientRecord(clientId, name, redirectUris, tokenEndpointAuthMethod, createdAt));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load client from Firestore", e);
        }
    }

    public boolean isRedirectUriAllowed(String clientId, String redirectUri) {
        return findById(clientId)
                .map(client -> client.getRedirectUris().contains(redirectUri))
                .orElse(false);
    }
}
