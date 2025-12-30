package com.emp.oauth;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/oauth/cleanup")
@Produces(MediaType.APPLICATION_JSON)
public class CleanupResource {

    @ConfigProperty(name = "emp.oauth.cleanup.clients-inactive-days", defaultValue = "7")
    long clientsInactiveDays;

    @Inject
    AuthRequestStoreService authRequestStoreService;

    @Inject
    AuthorizationCodeStoreService authorizationCodeStoreService;

    @Inject
    RefreshTokenStoreService refreshTokenStoreService;

    @Inject
    ClientStoreService clientStoreService;

    @POST
    public Response cleanup() {
        Instant now = Instant.now();
        Instant clientCutoff = now.minus(clientsInactiveDays, ChronoUnit.DAYS);
        int authRequestsDeleted = authRequestStoreService.cleanupExpired(now);
        int authCodesDeleted = authorizationCodeStoreService.cleanup(now);
        int refreshTokensDeleted = refreshTokenStoreService.cleanup(now);
        int clientsDeleted = clientStoreService.cleanupInactive(clientCutoff);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authRequestsDeleted", authRequestsDeleted);
        body.put("authCodesDeleted", authCodesDeleted);
        body.put("refreshTokensDeleted", refreshTokensDeleted);
        body.put("clientsDeleted", clientsDeleted);
        return Response.ok(body).build();
    }
}
