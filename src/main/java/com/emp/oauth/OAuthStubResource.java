package com.emp.oauth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@Path("/")
public class OAuthStubResource {

    private static final Logger LOG = Logger.getLogger(OAuthStubResource.class);

    @Inject
    JwksService jwksService;

    @Inject
    ClientStoreService clientStore;

    @Inject
    AuthorizationCodeStoreService codeStoreService;

    @Inject
    JwtService jwtService;

    @Inject
    AuthRequestStoreService authRequestStore;

    @Inject
    AuthorizationCodeService authorizationCodeService;

    @Inject
    FirestoreUserStore userStore;

    @Inject
    RefreshTokenService refreshTokenService;

    @Inject
    RefreshTokenStoreService refreshTokenStoreService;

    @ConfigProperty(name = "emp.oauth.test-user-id")
    java.util.Optional<String> testUserId;

    @ConfigProperty(name = "emp.oauth.default-resource")
    java.util.Optional<String> defaultResource;

    @ConfigProperty(name = "emp.oauth.auth-request-ttl-seconds", defaultValue = "600")
    long authRequestTtlSeconds;

    @ConfigProperty(name = "emp.oauth.auto-consent", defaultValue = "true")
    boolean autoConsent;
    @GET
    @Path("/jwks.json")
    @Produces(MediaType.APPLICATION_JSON)
    public Response jwks() {
        try {
            return Response.ok(jwksService.jwks()).build();
        } catch (IllegalStateException ex) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "jwks_unavailable");
            body.put("error_description", ex.getMessage());
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(body).build();
        }
    }

    @GET
    @Path("/oauth/authorize")
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(
            @QueryParam("response_type") String responseType,
            @QueryParam("client_id") String clientId,
            @QueryParam("redirect_uri") String redirectUri,
            @QueryParam("scope") String scope,
            @QueryParam("state") String state,
            @QueryParam("code_challenge") String codeChallenge,
            @QueryParam("code_challenge_method") String codeChallengeMethod,
            @QueryParam("resource") String resource) {
        if (!"code".equals(responseType)) {
            return error(Response.Status.BAD_REQUEST, "unsupported_response_type", "response_type must be code");
        }
        if (clientId == null || clientId.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "client_id is required");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "redirect_uri is required");
        }
        if (!clientStore.isRedirectUriAllowed(clientId, redirectUri)) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "redirect_uri is not registered");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            return redirectError(redirectUri, "invalid_request", "code_challenge is required", state);
        }
        if (!"S256".equals(codeChallengeMethod)) {
            return redirectError(redirectUri, "invalid_request", "code_challenge_method must be S256", state);
        }
        clientStore.updateLastUsedAt(clientId, Instant.now());
        String userId = testUserId.orElse(null);
        if (userId == null || userId.isBlank()) {
            AuthRequestRecord request = new AuthRequestRecord(
                UUID.randomUUID().toString(),
                clientId,
                redirectUri,
                scope,
                resource,
                codeChallenge,
                codeChallengeMethod,
                state,
                null,
                Instant.now().plusSeconds(authRequestTtlSeconds));
            authRequestStore.save(request);
            UriBuilder redirect = UriBuilder.fromPath("/oauth/google/login")
                    .queryParam("state", request.getId());
            return Response.seeOther(redirect.build()).build();
        }
        if (!autoConsent) {
            AuthRequestRecord request = new AuthRequestRecord(
                    UUID.randomUUID().toString(),
                    clientId,
                    redirectUri,
                    scope,
                    resource,
                    codeChallenge,
                    codeChallengeMethod,
                    state,
                    userId,
                    Instant.now().plusSeconds(authRequestTtlSeconds));
            authRequestStore.save(request);
            UriBuilder redirect = UriBuilder.fromPath("/oauth/consent")
                    .queryParam("state", request.getId());
            return Response.seeOther(redirect.build()).build();
        }
        String code = authorizationCodeService.issueCode(
                clientId,
                redirectUri,
                scope,
                resource,
                codeChallenge,
                codeChallengeMethod,
                userId);

        UriBuilder redirect = UriBuilder.fromUri(redirectUri)
                .queryParam("code", code);
        if (state != null) {
            redirect.queryParam("state", state);
        }
        return Response.seeOther(redirect.build()).build();
    }

    @POST
    @Path("/oauth/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(
            @FormParam("grant_type") String grantType,
            @FormParam("code") String code,
            @FormParam("redirect_uri") String redirectUri,
            @FormParam("client_id") String clientId,
            @FormParam("code_verifier") String codeVerifier,
            @FormParam("refresh_token") String refreshToken) {
        if (grantType == null || grantType.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "grant_type is required");
        }
        if ("authorization_code".equals(grantType)) {
            if (code == null || code.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "code is required");
            }
            if (clientId == null || clientId.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "client_id is required");
            }
            AuthorizationCodeRecord record = codeStoreService.find(code).orElse(null);
            if (record == null) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "code is invalid");
            }
            if (!clientId.equals(record.getClientId())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "client_id does not match");
            }
            clientStore.updateLastUsedAt(clientId, Instant.now());
            if (redirectUri == null || !redirectUri.equals(record.getRedirectUri())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "redirect_uri does not match");
            }
            if (record.getUsedAt() != null) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "code was already used");
            }
            if (Instant.now().isAfter(record.getExpiresAt())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "code has expired");
            }
            if (codeVerifier == null || codeVerifier.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "code_verifier is required");
            }
            if (!"S256".equals(record.getCodeChallengeMethod())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "unsupported code_challenge_method");
            }
            if (!verifyPkce(codeVerifier, record.getCodeChallenge())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "code_verifier is invalid");
            }
            record.markUsed(Instant.now());
            codeStoreService.markUsed(record.getCode());
            String audience = record.getResource();
            if (audience == null || audience.isBlank()) {
                audience = defaultResource.orElse(null);
            }
            if (audience == null || audience.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "resource is required");
            }
            String email = null;
            try {
                email = userStore.findEmail(record.getUserId()).orElse(null);
            } catch (IllegalStateException ex) {
                LOG.warnf("Unable to load user email for %s: %s", record.getUserId(), ex.getMessage());
            }
            if ((email == null || email.isBlank()) && record.getUserId() != null
                    && record.getUserId().contains("@")) {
                email = record.getUserId();
            }
            String accessToken = jwtService.issueAccessToken(
                    record.getUserId(),
                    audience,
                    record.getScope(),
                    record.getClientId(),
                    email);
            String newRefreshToken = refreshTokenService.issueToken(
                    record.getClientId(),
                    record.getUserId(),
                    record.getScope(),
                    audience);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", accessToken);
            body.put("token_type", "Bearer");
            body.put("expires_in", jwtService.getAccessTokenTtlSeconds());
            body.put("refresh_token", newRefreshToken);
            if (record.getScope() != null && !record.getScope().isBlank()) {
                body.put("scope", record.getScope());
            }
            return Response.ok(body).build();
        }
        if ("refresh_token".equals(grantType)) {
            if (refreshToken == null || refreshToken.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "refresh_token is required");
            }
            if (clientId == null || clientId.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "client_id is required");
            }
            RefreshTokenRecord record = refreshTokenStoreService.find(refreshToken).orElse(null);
            if (record == null) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "refresh token is invalid");
            }
            if (!clientId.equals(record.getClientId())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "client_id does not match");
            }
            clientStore.updateLastUsedAt(clientId, Instant.now());
            if (record.getUsedAt() != null) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "refresh token was already used");
            }
            if (Instant.now().isAfter(record.getExpiresAt())) {
                return error(Response.Status.BAD_REQUEST, "invalid_grant", "refresh token has expired");
            }
            String audience = record.getResource();
            if (audience == null || audience.isBlank()) {
                audience = defaultResource.orElse(null);
            }
            if (audience == null || audience.isBlank()) {
                return error(Response.Status.BAD_REQUEST, "invalid_request", "resource is required");
            }
            String email = null;
            try {
                email = userStore.findEmail(record.getUserId()).orElse(null);
            } catch (IllegalStateException ex) {
                LOG.warnf("Unable to load user email for %s: %s", record.getUserId(), ex.getMessage());
            }
            if ((email == null || email.isBlank()) && record.getUserId() != null
                    && record.getUserId().contains("@")) {
                email = record.getUserId();
            }
            String accessToken = jwtService.issueAccessToken(
                    record.getUserId(),
                    audience,
                    record.getScope(),
                    record.getClientId(),
                    email);
            String newRefreshToken = refreshTokenService.issueToken(
                    record.getClientId(),
                    record.getUserId(),
                    record.getScope(),
                    audience);
            refreshTokenStoreService.markUsed(refreshToken, newRefreshToken);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", accessToken);
            body.put("token_type", "Bearer");
            body.put("expires_in", jwtService.getAccessTokenTtlSeconds());
            body.put("refresh_token", newRefreshToken);
            if (record.getScope() != null && !record.getScope().isBlank()) {
                body.put("scope", record.getScope());
            }
            return Response.ok(body).build();
        }
        return error(Response.Status.BAD_REQUEST, "unsupported_grant_type", "unsupported grant_type");
    }

    @POST
    @Path("/oauth/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(ClientRegistrationRequest request) {
        if (request != null) {
            LOG.infof("DCR request client_name=%s token_endpoint_auth_method=%s redirect_uris=%s scope=%s",
                    request.getClientName(),
                    request.getTokenEndpointAuthMethod(),
                    request.getRedirectUris(),
                    request.getScope());
        } else {
            LOG.info("DCR request with empty body");
        }
        if (request == null || request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "redirect_uris is required");
        }
        String authMethod = request.getTokenEndpointAuthMethod();
        if (authMethod == null || authMethod.isBlank()) {
            authMethod = "none";
        } else {
            authMethod = authMethod.trim().toLowerCase(java.util.Locale.ROOT);
        }
        if ("client_secret_basic".equals(authMethod) || "client_secret_post".equals(authMethod)) {
            authMethod = "none";
        }
        if (!"none".equals(authMethod)) {
            return error(Response.Status.BAD_REQUEST, "invalid_client_metadata",
                    "token_endpoint_auth_method must be none for public clients");
        }
        String clientId = UUID.randomUUID().toString();
        ClientRecord record = new ClientRecord(
                clientId,
                request.getClientName(),
                request.getRedirectUris(),
                authMethod,
                java.time.Instant.now(),
                null);
        clientStore.save(record);

        ClientRegistrationResponse response = new ClientRegistrationResponse();
        response.setClientId(clientId);
        response.setClientIdIssuedAt(record.getCreatedAt().getEpochSecond());
        response.setClientName(record.getClientName());
        response.setRedirectUris(record.getRedirectUris());
        response.setTokenEndpointAuthMethod(record.getTokenEndpointAuthMethod());
        if (request.getScope() != null && !request.getScope().isBlank()) {
            response.setScope(request.getScope());
        }
        return Response.status(Response.Status.CREATED).entity(response).build();
    }

    private Response notImplemented(String endpoint) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "not_implemented");
        body.put("error_description", "Endpoint not implemented yet: " + endpoint);
        return Response.status(Response.Status.NOT_IMPLEMENTED).entity(body).build();
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
        if (state != null) {
            redirect.queryParam("state", state);
        }
        return Response.seeOther(redirect.build()).build();
    }

    private boolean verifyPkce(String codeVerifier, String expectedChallenge) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(codeVerifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            String actual = Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
            return actual.equals(expectedChallenge);
        } catch (Exception e) {
            return false;
        }
    }
}
