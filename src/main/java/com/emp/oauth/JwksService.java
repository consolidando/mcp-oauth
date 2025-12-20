package com.emp.oauth;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class JwksService {

    private static final int P256_COORDINATE_BYTES = 32;

    @ConfigProperty(name = "emp.oauth.key-id")
    Optional<String> keyId;

    @Inject
    KeyMaterialService keyMaterialService;

    public Map<String, Object> jwks() {
        ECPublicKey publicKey = keyMaterialService.publicKey();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("alg", "ES256");
        jwk.put("use", "sig");
        jwk.put("kid", keyId.orElse("es256-1"));
        jwk.put("x", toBase64Url(publicKey.getW().getAffineX()));
        jwk.put("y", toBase64Url(publicKey.getW().getAffineY()));
        return Map.of("keys", List.of(jwk));
    }

    private String toBase64Url(BigInteger coordinate) {
        byte[] raw = coordinate.toByteArray();
        if (raw.length == P256_COORDINATE_BYTES) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        }
        byte[] fixed = new byte[P256_COORDINATE_BYTES];
        int srcPos = Math.max(0, raw.length - P256_COORDINATE_BYTES);
        int length = Math.min(raw.length, P256_COORDINATE_BYTES);
        System.arraycopy(raw, srcPos, fixed, P256_COORDINATE_BYTES - length, length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed);
    }
}
