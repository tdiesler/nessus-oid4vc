package io.nessus.oid4vc.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Parses SD-JWT (Selective Disclosure JWT) credential strings.
 *
 * SD-JWT format: {@code <issuer-jwt>~<disclosure1>~<disclosure2>~...~[kb-jwt]}
 *
 * Each disclosure is a base64url-encoded JSON array: {@code ["salt", "claim_name", claim_value]}
 */
public final class SdJwtParser {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SD_CLAIM = "_sd";
    private static final String SD_ALG_CLAIM = "_sd_alg";
    private static final String DEFAULT_HASH_ALG = "sha-256";

    public record Disclosure(
        String encoded,
        String salt,
        String claimName,
        JsonNode claimValue
    ) {}

    public record SdJwtParts(
        String issuerJwt,
        List<Disclosure> disclosures,
        String keyBindingJwt
    ) {
        public SdJwtParts {
            disclosures = List.copyOf(disclosures);
        }
    }

    private SdJwtParser() {}

    public static boolean isSdJwt(String credential) {
        return credential != null && credential.contains("~");
    }

    public static SdJwtParts parse(String sdJwtString) {
        if (sdJwtString == null || !sdJwtString.contains("~")) {
            throw new IllegalArgumentException("Not an SD-JWT string");
        }

        String[] parts = sdJwtString.split("~", -1);
        String issuerJwt = parts[0];

        List<Disclosure> disclosures = new ArrayList<>();
        String keyBindingJwt = null;

        for (int i = 1; i < parts.length; i++) {
            if (parts[i].isEmpty()) continue;
            if (i == parts.length - 1 && parts[i].contains(".")) {
                keyBindingJwt = parts[i];
            } else {
                disclosures.add(decodeDisclosure(parts[i]));
            }
        }

        return new SdJwtParts(issuerJwt, disclosures, keyBindingJwt);
    }

    public static JsonNode discloseClaims(String sdJwtString) {
        SdJwtParts sdJwt = parse(sdJwtString);
        JsonNode issuerPayload = decodeJwtPayload(sdJwt.issuerJwt());
        return mergeClaims(issuerPayload, sdJwt.disclosures());
    }

    static Disclosure decodeDisclosure(String encoded) {
        byte[] decoded = Base64.getUrlDecoder().decode(encoded);
        try {
            JsonNode arr = JSON.readTree(new String(decoded, StandardCharsets.UTF_8));
            if (!arr.isArray() || arr.size() < 3) {
                throw new IllegalArgumentException("Disclosure must be a JSON array with at least 3 elements");
            }
            return new Disclosure(
                encoded,
                arr.get(0).asText(),
                arr.get(1).asText(),
                arr.get(2)
            );
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to decode disclosure: " + ex.getMessage(), ex);
        }
    }

    static JsonNode decodeJwtPayload(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        if (jwtParts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT: expected at least 2 parts");
        }
        byte[] payloadBytes = Base64.getUrlDecoder().decode(jwtParts[1]);
        try {
            return JSON.readTree(new String(payloadBytes, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to decode JWT payload: " + ex.getMessage(), ex);
        }
    }

    static JsonNode mergeClaims(JsonNode issuerPayload, List<Disclosure> disclosures) {
        ObjectNode result = issuerPayload.deepCopy();

        Set<String> sdHashes = extractSdHashes(result);
        String hashAlg = result.path(SD_ALG_CLAIM).asText(DEFAULT_HASH_ALG);

        for (Disclosure disclosure : disclosures) {
            String hash = hashDisclosure(disclosure.encoded(), hashAlg);
            if (sdHashes.contains(hash)) {
                result.set(disclosure.claimName(), disclosure.claimValue());
            }
        }

        result.remove(SD_CLAIM);
        result.remove(SD_ALG_CLAIM);
        removeNestedSdArrays(result);

        return result;
    }

    private static Set<String> extractSdHashes(JsonNode node) {
        Set<String> hashes = new HashSet<>();
        collectSdHashes(node, hashes);
        return Collections.unmodifiableSet(hashes);
    }

    private static void collectSdHashes(JsonNode node, Set<String> hashes) {
        if (node.isObject()) {
            JsonNode sdArray = node.get(SD_CLAIM);
            if (sdArray != null && sdArray.isArray()) {
                for (JsonNode hash : sdArray) {
                    hashes.add(hash.asText());
                }
            }
            Iterator<String> fieldNames = node.fieldNames();
            while (fieldNames.hasNext()) {
                collectSdHashes(node.get(fieldNames.next()), hashes);
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                collectSdHashes(element, hashes);
            }
        }
    }

    private static void removeNestedSdArrays(ObjectNode node) {
        Iterator<String> fieldNames = node.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            JsonNode child = node.get(fieldName);
            if (child.isObject()) {
                ObjectNode childObj = (ObjectNode) child;
                childObj.remove(SD_CLAIM);
                removeNestedSdArrays(childObj);
            }
        }
    }

    private static String hashDisclosure(String encoded, String hashAlg) {
        String javaAlg = hashAlg.replace("sha-", "SHA-").replace("sha3-", "SHA3-");
        try {
            MessageDigest digest = MessageDigest.getInstance(javaAlg);
            byte[] hash = digest.digest(encoded.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlg, ex);
        }
    }
}
