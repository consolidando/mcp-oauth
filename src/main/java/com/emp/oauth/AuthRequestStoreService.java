package com.emp.oauth;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class AuthRequestStoreService {

    @ConfigProperty(name = "emp.oauth.firestore.enabled", defaultValue = "false")
    boolean firestoreEnabled;

    @Inject
    InMemoryAuthRequestStore inMemoryAuthRequestStore;

    @Inject
    FirestoreAuthRequestStore firestoreAuthRequestStore;

    public void save(AuthRequestRecord record) {
        if (firestoreEnabled) {
            firestoreAuthRequestStore.save(record);
            return;
        }
        inMemoryAuthRequestStore.save(record);
    }

    public Optional<AuthRequestRecord> find(String id) {
        if (firestoreEnabled) {
            return firestoreAuthRequestStore.find(id);
        }
        return inMemoryAuthRequestStore.find(id);
    }

    public void remove(String id) {
        if (firestoreEnabled) {
            firestoreAuthRequestStore.remove(id);
            return;
        }
        inMemoryAuthRequestStore.remove(id);
    }

    public void updateUserId(String id, String userId) {
        if (firestoreEnabled) {
            firestoreAuthRequestStore.updateUserId(id, userId);
            return;
        }
        inMemoryAuthRequestStore.updateUserId(id, userId);
    }
}
