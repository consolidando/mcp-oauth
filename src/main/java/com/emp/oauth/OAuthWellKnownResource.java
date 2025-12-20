package com.emp.oauth;

import java.util.LinkedHashMap;
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
        return Response.ok(body).build();
    }


}
