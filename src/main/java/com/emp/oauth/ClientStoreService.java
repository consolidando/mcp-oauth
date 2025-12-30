package com.emp.oauth;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class ClientStoreService {

    @ConfigProperty(name = "emp.oauth.firestore.enabled", defaultValue = "false")
    boolean firestoreEnabled;

    @Inject
    InMemoryClientStore inMemoryClientStore;

    @Inject
    FirestoreClientStore firestoreClientStore;

    public void save(ClientRecord client) {
        if (firestoreEnabled) {
            firestoreClientStore.save(client);
            return;
        }
        inMemoryClientStore.save(client);
    }

    public Optional<ClientRecord> findById(String clientId) {
        if (firestoreEnabled) {
            return firestoreClientStore.findById(clientId);
        }
        return inMemoryClientStore.findById(clientId);
    }

    public boolean isRedirectUriAllowed(String clientId, String redirectUri) {
        if (firestoreEnabled) {
            return firestoreClientStore.isRedirectUriAllowed(clientId, redirectUri);
        }
        return inMemoryClientStore.isRedirectUriAllowed(clientId, redirectUri);
    }

    public void updateLastUsedAt(String clientId, java.time.Instant lastUsedAt) {
        if (firestoreEnabled) {
            firestoreClientStore.updateLastUsedAt(clientId, lastUsedAt);
            return;
        }
        inMemoryClientStore.updateLastUsedAt(clientId, lastUsedAt);
    }
}
