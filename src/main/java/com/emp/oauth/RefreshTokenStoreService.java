package com.emp.oauth;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class RefreshTokenStoreService {

    @ConfigProperty(name = "emp.oauth.firestore.enabled", defaultValue = "false")
    boolean firestoreEnabled;

    @Inject
    InMemoryRefreshTokenStore inMemoryRefreshTokenStore;

    @Inject
    FirestoreRefreshTokenStore firestoreRefreshTokenStore;

    public void save(RefreshTokenRecord record) {
        if (firestoreEnabled) {
            firestoreRefreshTokenStore.save(record);
            return;
        }
        inMemoryRefreshTokenStore.save(record);
    }

    public Optional<RefreshTokenRecord> find(String token) {
        if (firestoreEnabled) {
            return firestoreRefreshTokenStore.find(token);
        }
        return inMemoryRefreshTokenStore.find(token);
    }

    public void markUsed(String token, String rotatedTo) {
        if (firestoreEnabled) {
            firestoreRefreshTokenStore.markUsed(token, rotatedTo);
            return;
        }
        inMemoryRefreshTokenStore.markUsed(token, rotatedTo);
    }
}
