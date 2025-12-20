package com.emp.oauth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.security.MessageDigest;
import java.security.SecureRandom;
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

@Path("/")
public class OAuthStubResource {

    @Inject
    JwksService jwksService;

    @Inject
    InMemoryClientStore clientStore;

    @Inject
    InMemoryAuthorizationCodeStore codeStore;

    @Inject
    JwtService jwtService;

    @ConfigProperty(name = "emp.oauth.test-user-id")
    java.util.Optional<String> testUserId;

    @ConfigProperty(name = "emp.oauth.auth-code-ttl-seconds", defaultValue = "300")
    long authCodeTtlSeconds;

    @ConfigProperty(name = "emp.oauth.default-resource")
    java.util.Optional<String> defaultResource;

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
        String userId = testUserId.orElse(null);
        if (userId == null || userId.isBlank()) {
            return redirectError(redirectUri, "access_denied", "user is not authenticated", state);
        }
        String code = generateCode();
        Instant now = Instant.now();
        AuthorizationCodeRecord record = new AuthorizationCodeRecord(
                code,
                clientId,
                userId,
                redirectUri,
                scope,
                resource,
                codeChallenge,
                codeChallengeMethod,
                now.plusSeconds(authCodeTtlSeconds));
        codeStore.save(record);

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
            @FormParam("code_verifier") String codeVerifier) {
        if (!"authorization_code".equals(grantType)) {
            return error(Response.Status.BAD_REQUEST, "unsupported_grant_type", "grant_type must be authorization_code");
        }
        if (code == null || code.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "code is required");
        }
        if (clientId == null || clientId.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "client_id is required");
        }
        AuthorizationCodeRecord record = codeStore.find(code).orElse(null);
        if (record == null) {
            return error(Response.Status.BAD_REQUEST, "invalid_grant", "code is invalid");
        }
        if (!clientId.equals(record.getClientId())) {
            return error(Response.Status.BAD_REQUEST, "invalid_grant", "client_id does not match");
        }
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
        String audience = record.getResource();
        if (audience == null || audience.isBlank()) {
            audience = defaultResource.orElse(null);
        }
        if (audience == null || audience.isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "resource is required");
        }
        String accessToken = jwtService.issueAccessToken(
                record.getUserId(),
                audience,
                record.getScope(),
                record.getClientId());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", jwtService.getAccessTokenTtlSeconds());
        if (record.getScope() != null && !record.getScope().isBlank()) {
            body.put("scope", record.getScope());
        }
        return Response.ok(body).build();
    }

    @POST
    @Path("/oauth/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(ClientRegistrationRequest request) {
        if (request == null || request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "redirect_uris is required");
        }
        String authMethod = request.getTokenEndpointAuthMethod();
        if (authMethod == null || authMethod.isBlank()) {
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
                java.time.Instant.now());
        clientStore.save(record);

        ClientRegistrationResponse response = new ClientRegistrationResponse();
        response.setClientId(clientId);
        response.setClientIdIssuedAt(record.getCreatedAt().getEpochSecond());
        response.setClientName(record.getClientName());
        response.setRedirectUris(record.getRedirectUris());
        response.setTokenEndpointAuthMethod(record.getTokenEndpointAuthMethod());
        response.setScope(request.getScope());
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

    private String generateCode() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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
