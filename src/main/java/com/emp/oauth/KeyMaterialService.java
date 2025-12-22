package com.emp.oauth;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;

@ApplicationScoped
public class KeyMaterialService {

    @ConfigProperty(name = "emp.oauth.public-key-path")
    Optional<String> publicKeyPath;

    @ConfigProperty(name = "emp.oauth.public-key-secret")
    Optional<String> publicKeySecret;

    @ConfigProperty(name = "emp.oauth.private-key-secret")
    Optional<String> privateKeySecret;

    @ConfigProperty(name = "emp.oauth.private-key-path")
    Optional<String> privateKeyPath;

    public ECPublicKey publicKey() {
        String pem = loadPublicKeyPem();
        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(base64);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey key = keyFactory.generatePublic(new X509EncodedKeySpec(der));
            return (ECPublicKey) key;
        } catch (InvalidKeySpecException | java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid EC public key", e);
        }
    }

    private String loadPublicKeyPem() {
        if (publicKeySecret.isPresent()) {
            return loadFromSecretManager(publicKeySecret.get());
        }
        if (publicKeyPath.isPresent()) {
            String pemPath = publicKeyPath.get();
            if (pemPath.startsWith("classpath:")) {
                return loadFromClasspath(pemPath.substring("classpath:".length()));
            }
            try {
                return Files.readString(Path.of(pemPath), StandardCharsets.US_ASCII);
            } catch (IOException e) {
                throw new IllegalStateException("Unable to read public key from " + pemPath, e);
            }
        }
        throw new IllegalStateException("emp.oauth.public-key-secret or emp.oauth.public-key-path must be configured");
    }

    private String loadFromClasspath(String resourcePath) {
        String normalized = resourcePath.startsWith("/") ? resourcePath.substring(1) : resourcePath;
        try (var stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(normalized)) {
            if (stream == null) {
                throw new IllegalStateException("Classpath resource not found: " + resourcePath);
            }
            return new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read classpath resource " + resourcePath, e);
        }
    }

    public ECPrivateKey privateKey() {
        String pem = loadPrivateKeyPem();
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object parsed = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey key;
            if (parsed instanceof PEMKeyPair pemKeyPair) {
                key = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
            } else if (parsed instanceof PrivateKeyInfo keyInfo) {
                key = converter.getPrivateKey(keyInfo);
            } else {
                throw new IllegalStateException("Unsupported private key format");
            }
            return (ECPrivateKey) key;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse EC private key", e);
        }
    }

    private String loadPrivateKeyPem() {
        if (privateKeySecret.isPresent()) {
            return loadFromSecretManager(privateKeySecret.get());
        }
        if (privateKeyPath.isPresent()) {
            String pemPath = privateKeyPath.get();
            try {
                return Files.readString(Path.of(pemPath), StandardCharsets.US_ASCII);
            } catch (IOException e) {
                throw new IllegalStateException("Unable to read private key from " + pemPath, e);
            }
        }
        throw new IllegalStateException("emp.oauth.private-key-secret or emp.oauth.private-key-path must be configured");
    }

    private String loadFromSecretManager(String secretResource) {
        AccessSecretVersionRequest request = AccessSecretVersionRequest.newBuilder()
                .setName(secretResource)
                .build();
        try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
            return client.accessSecretVersion(request).getPayload().getData().toStringUtf8();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to access Secret Manager key", e);
        }
    }
}
