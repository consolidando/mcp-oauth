package com.emp.oauth;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class AuthorizationCodeStoreService {

    @ConfigProperty(name = "emp.oauth.firestore.enabled", defaultValue = "false")
    boolean firestoreEnabled;

    @Inject
    InMemoryAuthorizationCodeStore inMemoryAuthorizationCodeStore;

    @Inject
    FirestoreAuthorizationCodeStore firestoreAuthorizationCodeStore;

    public void save(AuthorizationCodeRecord record) {
        if (firestoreEnabled) {
            firestoreAuthorizationCodeStore.save(record);
            return;
        }
        inMemoryAuthorizationCodeStore.save(record);
    }

    public Optional<AuthorizationCodeRecord> find(String code) {
        if (firestoreEnabled) {
            return firestoreAuthorizationCodeStore.find(code);
        }
        return inMemoryAuthorizationCodeStore.find(code);
    }

    public void markUsed(String code) {
        if (firestoreEnabled) {
            firestoreAuthorizationCodeStore.markUsed(code);
        }
    }
}
