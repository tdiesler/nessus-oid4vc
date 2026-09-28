package io.nessus.oid4vc.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class VcJwtVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(VcJwtVerifier.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private final Map<String, JsonNode> jwksCache = new ConcurrentHashMap<>();

    public void verify(SignedJWT signedJwt) throws VcVerificationException {
        try {
            var claims = signedJwt.getJWTClaimsSet();
            var iss = claims.getIssuer();
            if (iss == null) {
                throw new VcVerificationException("VC JWT has no 'iss' claim");
            }

            var kid = signedJwt.getHeader().getKeyID();
            if (kid == null) {
                throw new VcVerificationException("VC JWT has no 'kid' header");
            }

            var jwks = fetchJwks(iss);
            var key = findKey(jwks, kid);
            if (key == null) {
                throw new VcVerificationException("No key with kid '" + kid + "' in issuer JWKS at " + iss);
            }

            var jwk = JWK.parse(JSON.writeValueAsString(key));
            JWSVerifier verifier;
            if (jwk instanceof ECKey ecKey) {
                verifier = new ECDSAVerifier(ecKey);
            } else if (jwk instanceof RSAKey rsaKey) {
                verifier = new RSASSAVerifier(rsaKey);
            } else {
                throw new VcVerificationException("Unsupported key type: " + jwk.getKeyType());
            }

            if (!signedJwt.verify(verifier)) {
                throw new VcVerificationException("VC JWT signature verification failed (issuer: " + iss + ", kid: " + kid + ")");
            }

            LOG.debug("VC JWT signature verified (issuer: {}, kid: {})", iss, kid);
        } catch (VcVerificationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new VcVerificationException("VC JWT verification error: " + ex.getMessage(), ex);
        }
    }

    public void preloadJwks(String issuer, JsonNode jwks) {
        jwksCache.put(issuer, jwks);
    }

    public void clearCache() {
        jwksCache.clear();
    }

    private JsonNode fetchJwks(String issuer) throws VcVerificationException {
        return jwksCache.computeIfAbsent(issuer, iss -> {
            try {
                var certsUrl = iss + "/protocol/openid-connect/certs";
                LOG.debug("Fetching JWKS from {}", certsUrl);
                var request = HttpRequest.newBuilder()
                        .uri(URI.create(certsUrl))
                        .GET()
                        .build();
                var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new VcVerificationException("Failed to fetch JWKS from " + certsUrl + ": HTTP " + response.statusCode());
                }
                return JSON.readTree(response.body());
            } catch (VcVerificationException ex) {
                throw new RuntimeException(ex);
            } catch (Exception ex) {
                throw new RuntimeException(new VcVerificationException("Failed to fetch JWKS from " + iss + ": " + ex.getMessage(), ex));
            }
        });
    }

    private JsonNode findKey(JsonNode jwks, String kid) {
        var keys = jwks.get("keys");
        if (keys == null || !keys.isArray()) return null;
        for (var key : keys) {
            if (kid.equals(key.path("kid").asText(null))) {
                return key;
            }
        }
        return null;
    }
}
