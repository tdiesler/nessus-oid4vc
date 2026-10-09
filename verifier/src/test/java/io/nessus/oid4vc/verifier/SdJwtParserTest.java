package io.nessus.oid4vc.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SdJwtParserTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void isSdJwt() {
        assertTrue(SdJwtParser.isSdJwt("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.sig~disc1~"));
        assertFalse(SdJwtParser.isSdJwt("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.sig"));
        assertFalse(SdJwtParser.isSdJwt(null));
    }

    @Test
    void decodeDisclosure() {
        // ["salt123", "given_name", "John"]
        String disclosureJson = "[\"salt123\", \"given_name\", \"John\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            disclosureJson.getBytes(StandardCharsets.UTF_8));

        SdJwtParser.Disclosure disclosure = SdJwtParser.decodeDisclosure(encoded);
        assertEquals("salt123", disclosure.salt());
        assertEquals("given_name", disclosure.claimName());
        assertEquals("John", disclosure.claimValue().asText());
        assertEquals(encoded, disclosure.encoded());
    }

    @Test
    void decodeDisclosureWithObjectValue() throws Exception {
        String disclosureJson = "[\"salt456\", \"address\", {\"street\": \"123 Main St\", \"city\": \"Anytown\"}]";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            disclosureJson.getBytes(StandardCharsets.UTF_8));

        SdJwtParser.Disclosure disclosure = SdJwtParser.decodeDisclosure(encoded);
        assertEquals("address", disclosure.claimName());
        assertTrue(disclosure.claimValue().isObject());
        assertEquals("Anytown", disclosure.claimValue().get("city").asText());
    }

    @Test
    void decodeDisclosureWithBooleanValue() {
        String disclosureJson = "[\"salt789\", \"age_over_18\", true]";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            disclosureJson.getBytes(StandardCharsets.UTF_8));

        SdJwtParser.Disclosure disclosure = SdJwtParser.decodeDisclosure(encoded);
        assertEquals("age_over_18", disclosure.claimName());
        assertTrue(disclosure.claimValue().asBoolean());
    }

    @Test
    void parseSdJwtString() {
        String issuerJwt = buildJwt("""
            {"iss": "https://issuer.example.com", "vct": "NaturalPerson", "_sd_alg": "sha-256", "_sd": []}
            """);
        String disc1 = encodeDisclosure("[\"salt1\", \"given_name\", \"John\"]");
        String disc2 = encodeDisclosure("[\"salt2\", \"family_name\", \"Doe\"]");

        String sdJwtString = issuerJwt + "~" + disc1 + "~" + disc2 + "~";

        SdJwtParser.SdJwtParts parts = SdJwtParser.parse(sdJwtString);
        assertEquals(issuerJwt, parts.issuerJwt());
        assertEquals(2, parts.disclosures().size());
        assertEquals("given_name", parts.disclosures().get(0).claimName());
        assertEquals("family_name", parts.disclosures().get(1).claimName());
        assertNull(parts.keyBindingJwt());
    }

    @Test
    void parseSdJwtWithKeyBindingJwt() {
        String issuerJwt = buildJwt("{\"iss\": \"https://issuer.example.com\", \"_sd\": []}");
        String disc1 = encodeDisclosure("[\"salt1\", \"given_name\", \"Alice\"]");
        String kbJwt = buildJwt("{\"nonce\": \"abc123\", \"aud\": \"https://verifier.example.com\"}");

        String sdJwtString = issuerJwt + "~" + disc1 + "~" + kbJwt;

        SdJwtParser.SdJwtParts parts = SdJwtParser.parse(sdJwtString);
        assertEquals(1, parts.disclosures().size());
        assertNotNull(parts.keyBindingJwt());
    }

    @Test
    void discloseClaimsWithMatchingHashes() throws Exception {
        String disc1Encoded = encodeDisclosure("[\"salt1\", \"given_name\", \"John\"]");
        String disc2Encoded = encodeDisclosure("[\"salt2\", \"family_name\", \"Doe\"]");
        String hash1 = sha256Hash(disc1Encoded);
        String hash2 = sha256Hash(disc2Encoded);

        String payloadJson = String.format("""
            {"iss": "https://issuer.example.com", "vct": "NaturalPerson", "_sd_alg": "sha-256", "_sd": ["%s", "%s"]}
            """, hash1, hash2);

        String issuerJwt = buildJwt(payloadJson);
        String sdJwtString = issuerJwt + "~" + disc1Encoded + "~" + disc2Encoded + "~";

        JsonNode disclosed = SdJwtParser.discloseClaims(sdJwtString);

        assertEquals("John", disclosed.get("given_name").asText());
        assertEquals("Doe", disclosed.get("family_name").asText());
        assertEquals("https://issuer.example.com", disclosed.get("iss").asText());
        assertEquals("NaturalPerson", disclosed.get("vct").asText());
        assertNull(disclosed.get("_sd"));
        assertNull(disclosed.get("_sd_alg"));
    }

    @Test
    void discloseClaimsIgnoresNonMatchingDisclosures() throws Exception {
        String disc1Encoded = encodeDisclosure("[\"salt1\", \"given_name\", \"John\"]");
        String hash1 = sha256Hash(disc1Encoded);

        // Only hash1 is in _sd — a second disclosure with non-matching hash should be ignored
        String discExtra = encodeDisclosure("[\"saltX\", \"secret\", \"hidden\"]");

        String payloadJson = String.format("""
            {"iss": "https://issuer.example.com", "_sd_alg": "sha-256", "_sd": ["%s"]}
            """, hash1);

        String issuerJwt = buildJwt(payloadJson);
        String sdJwtString = issuerJwt + "~" + disc1Encoded + "~" + discExtra + "~";

        JsonNode disclosed = SdJwtParser.discloseClaims(sdJwtString);
        assertEquals("John", disclosed.get("given_name").asText());
        assertNull(disclosed.get("secret"));
    }

    @Test
    void discloseClaimsPreservesVisibleClaims() throws Exception {
        String discEncoded = encodeDisclosure("[\"salt1\", \"email\", \"john@example.com\"]");
        String hash = sha256Hash(discEncoded);

        String payloadJson = String.format("""
            {"iss": "https://issuer.example.com", "vct": "Identity", "iat": 1700000000, "_sd_alg": "sha-256", "_sd": ["%s"]}
            """, hash);

        String issuerJwt = buildJwt(payloadJson);
        String sdJwtString = issuerJwt + "~" + discEncoded + "~";

        JsonNode disclosed = SdJwtParser.discloseClaims(sdJwtString);
        assertEquals("https://issuer.example.com", disclosed.get("iss").asText());
        assertEquals("Identity", disclosed.get("vct").asText());
        assertEquals(1700000000, disclosed.get("iat").asLong());
        assertEquals("john@example.com", disclosed.get("email").asText());
    }

    @Test
    void parseRejectsNonSdJwt() {
        assertThrows(IllegalArgumentException.class,
            () -> SdJwtParser.parse("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlciJ9.sig"));
    }

    @Test
    void decodeJwtPayload() throws Exception {
        String jwt = buildJwt("{\"iss\": \"test\", \"sub\": \"user1\"}");
        JsonNode payload = SdJwtParser.decodeJwtPayload(jwt);
        assertEquals("test", payload.get("iss").asText());
        assertEquals("user1", payload.get("sub").asText());
    }

    // -- helpers --

    private static String buildJwt(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
            "{\"alg\":\"ES256\",\"typ\":\"vc+sd-jwt\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            payloadJson.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString("fakesig".getBytes());
        return header + "." + payload + "." + signature;
    }

    private static String encodeDisclosure(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            json.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
