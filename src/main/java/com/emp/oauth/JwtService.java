package com.emp.oauth;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.math.BigInteger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.fasterxml.jackson.databind.ObjectMapper;

@ApplicationScoped
public class JwtService {

    private static final int ES256_PART_BYTES = 32;

    @ConfigProperty(name = "emp.oauth.issuer")
    String issuer;

    @ConfigProperty(name = "emp.oauth.key-id")
    Optional<String> keyId;

    @ConfigProperty(name = "emp.oauth.access-token-ttl-seconds", defaultValue = "3600")
    long accessTokenTtlSeconds;

    @Inject
    KeyMaterialService keyMaterialService;

    @Inject
    ObjectMapper objectMapper;

    public String issueAccessToken(String subject, String audience, String scope, String clientId) {
        Instant now = Instant.now();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "ES256");
        header.put("typ", "JWT");
        keyId.ifPresent(kid -> header.put("kid", kid));

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", issuer);
        payload.put("sub", subject);
        payload.put("aud", audience);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plusSeconds(accessTokenTtlSeconds).getEpochSecond());
        if (scope != null && !scope.isBlank()) {
            payload.put("scope", scope);
        }
        payload.put("client_id", clientId);

        try {
            String headerPart = base64Url(objectMapper.writeValueAsBytes(header));
            String payloadPart = base64Url(objectMapper.writeValueAsBytes(payload));
            String signingInput = headerPart + "." + payloadPart;
            byte[] signatureDer = sign(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] signatureJose = derToJose(signatureDer);
            return signingInput + "." + base64Url(signatureJose);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to issue JWT", e);
        }
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    private byte[] sign(byte[] input) throws Exception {
        ECPrivateKey privateKey = keyMaterialService.privateKey();
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(input);
        return signer.sign();
    }

    private byte[] derToJose(byte[] derSignature) throws Exception {
        ASN1Sequence sequence = (ASN1Sequence) ASN1Primitive.fromByteArray(derSignature);
        BigInteger r = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) sequence.getObjectAt(1)).getValue();
        byte[] rBytes = toFixedLength(r, ES256_PART_BYTES);
        byte[] sBytes = toFixedLength(s, ES256_PART_BYTES);
        byte[] out = new byte[ES256_PART_BYTES * 2];
        System.arraycopy(rBytes, 0, out, 0, ES256_PART_BYTES);
        System.arraycopy(sBytes, 0, out, ES256_PART_BYTES, ES256_PART_BYTES);
        return out;
    }

    private byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int srcPos = Math.max(0, raw.length - length);
        int copyLen = Math.min(raw.length, length);
        System.arraycopy(raw, srcPos, out, length - copyLen, copyLen);
        return out;
    }

    private String base64Url(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
}
