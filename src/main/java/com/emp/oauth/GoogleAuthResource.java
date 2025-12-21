package com.emp.oauth;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

@Path("/oauth/google")
@Produces(MediaType.APPLICATION_JSON)
public class GoogleAuthResource {

    @Inject
    GoogleOidcClient googleOidcClient;

    @Inject
    InMemoryAuthRequestStore authRequestStore;

    @Inject
    AuthorizationCodeService authorizationCodeService;

    @Inject
    FirestoreUserStore userStore;

    @GET
    @Path("/login")
    public Response login(@QueryParam("state") String state) {
        if (state == null || state.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "state is required");
        }
        AuthRequestRecord record = authRequestStore.find(state).orElse(null);
        if (record == null || Instant.now().isAfter(record.getExpiresAt())) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "authorization request expired");
        }
        URI redirect = googleOidcClient.buildAuthorizationUrl(state);
        return Response.seeOther(redirect).build();
    }

    @GET
    @Path("/callback")
    public Response callback(
            @QueryParam("state") String state,
            @QueryParam("code") String code,
            @QueryParam("error") String error) {
        if (state == null || state.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "state is required");
        }
        AuthRequestRecord record = authRequestStore.find(state).orElse(null);
        if (record == null || Instant.now().isAfter(record.getExpiresAt())) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "authorization request expired");
        }
        if (error != null && !error.isBlank()) {
            authRequestStore.remove(state);
            return redirectError(record.getRedirectUri(), error, "google authorization failed", record.getOriginalState());
        }
        if (code == null || code.isBlank()) {
            return redirectError(record.getRedirectUri(), "invalid_request", "code is required", record.getOriginalState());
        }
        GoogleIdToken idToken = googleOidcClient.exchangeCode(code);
        userStore.upsertGoogleUser(idToken);
        String authCode = authorizationCodeService.issueCode(
                record.getClientId(),
                record.getRedirectUri(),
                record.getScope(),
                record.getResource(),
                record.getCodeChallenge(),
                record.getCodeChallengeMethod(),
                idToken.getSubject());
        authRequestStore.remove(state);
        UriBuilder redirect = UriBuilder.fromUri(record.getRedirectUri())
                .queryParam("code", authCode);
        if (record.getOriginalState() != null && !record.getOriginalState().isBlank()) {
            redirect.queryParam("state", record.getOriginalState());
        }
        return Response.seeOther(redirect.build()).build();
    }

    private Response error(Response.Status status, String code, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("error_description", description);
        return Response.status(status).entity(body).build();
    }

    private Response redirectError(String redirectUri, String code, String description, String state) {
        UriBuilder redirect = UriBuilder.fromUri(redirectUri)
                .queryParam("error", code)
                .queryParam("error_description", description);
        if (state != null && !state.isBlank()) {
            redirect.queryParam("state", state);
        }
        return Response.seeOther(redirect.build()).build();
    }
}
