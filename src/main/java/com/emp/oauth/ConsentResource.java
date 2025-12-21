package com.emp.oauth;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

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
import jakarta.ws.rs.WebApplicationException;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;

@Path("/oauth/consent")
public class ConsentResource {

    @Inject
    AuthRequestStoreService authRequestStore;

    @Inject
    AuthorizationCodeService authorizationCodeService;

    @ConfigProperty(name = "emp.oauth.consent.brand-name", defaultValue = "EMP Auth")
    String brandName;

    @Inject
    Template consent;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public TemplateInstance consentPage(@QueryParam("state") String state) {
        AuthRequestRecord record = loadRecord(state);
        return consent.data(
                "brandName", brandName,
                "state", state,
                "clientId", record.getClientId(),
                "scope", record.getScope(),
                "resource", record.getResource());
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response handleConsent(
            @FormParam("state") String state,
            @FormParam("decision") String decision) {
        AuthRequestRecord record = loadRecord(state);
        if (!"approve".equals(decision)) {
            authRequestStore.remove(state);
            return redirectError(record.getRedirectUri(), "access_denied", "consent denied", record.getOriginalState());
        }
        String userId = record.getUserId();
        if (userId == null || userId.isBlank()) {
            authRequestStore.remove(state);
            return redirectError(record.getRedirectUri(), "access_denied", "user not authenticated", record.getOriginalState());
        }
        String code = authorizationCodeService.issueCode(
                record.getClientId(),
                record.getRedirectUri(),
                record.getScope(),
                record.getResource(),
                record.getCodeChallenge(),
                record.getCodeChallengeMethod(),
                userId);
        authRequestStore.remove(state);
        UriBuilder redirect = UriBuilder.fromUri(record.getRedirectUri())
                .queryParam("code", code);
        if (record.getOriginalState() != null && !record.getOriginalState().isBlank()) {
            redirect.queryParam("state", record.getOriginalState());
        }
        return Response.seeOther(redirect.build()).build();
    }

    private AuthRequestRecord loadRecord(String state) {
        if (state == null || state.isBlank()) {
            throw badRequest("state is required");
        }
        AuthRequestRecord record = authRequestStore.find(state).orElse(null);
        if (record == null || Instant.now().isAfter(record.getExpiresAt())) {
            throw badRequest("authorization request expired");
        }
        return record;
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

    private WebApplicationException badRequest(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "invalid_request");
        body.put("error_description", message);
        return new WebApplicationException(
                Response.status(Response.Status.BAD_REQUEST).entity(body).type(MediaType.APPLICATION_JSON).build());
    }
}
