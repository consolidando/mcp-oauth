package com.emp.oauth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/.well-known")
@Produces(MediaType.APPLICATION_JSON)
public class OAuthWellKnownResource {

    @ConfigProperty(name = "emp.oauth.issuer")
    String issuer;

    @ConfigProperty(name = "emp.oauth.authorization-endpoint")
    Optional<String> authorizationEndpoint;

    @ConfigProperty(name = "emp.oauth.token-endpoint")
    Optional<String> tokenEndpoint;

    @ConfigProperty(name = "emp.oauth.registration-endpoint")
    Optional<String> registrationEndpoint;

    @ConfigProperty(name = "emp.oauth.jwks-uri")
    Optional<String> jwksUri;

    @ConfigProperty(name = "emp.oauth.scopes-supported")
    Optional<String> scopesSupported;

    @GET
    @Path("/oauth-authorization-server")
    public Response oauthAuthorizationServerMetadata() {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("authorization_endpoint", authorizationEndpoint.orElse(base + "/oauth/authorize"));
        body.put("token_endpoint", tokenEndpoint.orElse(base + "/oauth/token"));
        body.put("registration_endpoint", registrationEndpoint.orElse(base + "/oauth/register"));
        body.put("jwks_uri", jwksUri.orElse(base + "/jwks.json"));
        body.put("code_challenge_methods_supported", new String[] { "S256" });
        scopesSupported.map(this::splitScopes).ifPresent(scopes -> body.put("scopes_supported", scopes));
        return Response.ok(body).build();
    }

    @GET
    @Path("/openid-configuration")
    public Response openIdConfiguration() {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("authorization_endpoint", authorizationEndpoint.orElse(base + "/oauth/authorize"));
        body.put("token_endpoint", tokenEndpoint.orElse(base + "/oauth/token"));
        body.put("registration_endpoint", registrationEndpoint.orElse(base + "/oauth/register"));
        body.put("jwks_uri", jwksUri.orElse(base + "/jwks.json"));
        body.put("response_modes_supported", new String[] { "query" });
        body.put("response_types_supported", new String[] { "code" });
        body.put("subject_types_supported", new String[] { "public" });
        body.put("grant_types_supported", new String[] { "authorization_code" });
        body.put("token_endpoint_auth_methods_supported", new String[] { "none" });
        body.put("id_token_signing_alg_values_supported", new String[] { "ES256" });
        body.put("claims_supported", new String[] { "sub", "email", "email_verified" });
        body.put("code_challenge_methods_supported", new String[] { "S256" });
        scopesSupported.map(this::splitScopes).ifPresent(scopes -> body.put("scopes_supported", scopes));
        return Response.ok(body).build();
    }

    private List<String> splitScopes(String scopes) {
        return java.util.Arrays.stream(scopes.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toList();
    }
}
