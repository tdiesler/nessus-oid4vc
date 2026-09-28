package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ShowCmdTest extends AbstractCmdTest {

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void setupTestWallet() throws Exception {
        var mapper = new ObjectMapper();
        var ecKey = new ECKeyGenerator(Curve.P_256).keyID("test-key-01").generate();

        var vcJwt = buildVcJwt(ecKey, Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_natural_person"),
                "credentialSubject", Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland")));

        var keyMap = new LinkedHashMap<String, Object>();
        keyMap.put("kid", ecKey.getKeyID());
        keyMap.put("kty", "EC");
        keyMap.put("crv", "P-256");

        var conn = new LinkedHashMap<String, Object>();
        conn.put("credentials", Map.of("oid4vc_natural_person_jwt_0000", vcJwt));
        conn.put("keys", List.of(keyMap));
        conn.put("defaultKey", ecKey.getKeyID());

        var realmState = new LinkedHashMap<String, Object>();
        realmState.put("defaultClient", "oid4vci-client");
        realmState.put("defaultUser", "alice");
        realmState.put("users", Map.of("alice", conn));

        Map<String, Object> wallet;
        if (walletExists) {
            wallet = mapper.readValue(walletFile.toFile(), LinkedHashMap.class);
            var realms = (Map<String, Object>) wallet.computeIfAbsent("realms", k -> new LinkedHashMap<>());
            realms.put(DEFAULT_REALM, realmState);
        } else {
            wallet = new LinkedHashMap<>();
            wallet.put("serverUrl", SERVER_URL);
            wallet.put("defaultRealm", DEFAULT_REALM);
            wallet.put("realms", Map.of(DEFAULT_REALM, realmState));
        }

        tryAdminLogin(wallet);

        Files.createDirectories(walletFile.getParent());
        mapper.writerWithDefaultPrettyPrinter().writeValue(walletFile.toFile(), wallet);
        walletExists = true;
    }

    @SuppressWarnings("unchecked")
    private static void tryAdminLogin(Map<String, Object> wallet) {
        if (!keycloakAvailable) return;
        try {
            var pb = new ProcessBuilder("kubectl", "--context=rancher-desktop",
                    "get", "secret", "keycloak-secret", "-o", "jsonpath={.data.ADMIN_PASSWORD}");
            var proc = pb.start();
            var b64 = new String(proc.getInputStream().readAllBytes()).trim();
            if (proc.waitFor() != 0 || b64.isEmpty()) return;
            var password = new String(java.util.Base64.getDecoder().decode(b64));

            var body = "grant_type=password&client_id=admin-cli"
                    + "&username=admin&password=" + java.net.URLEncoder.encode(password, "UTF-8");
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(SERVER_URL + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                    .build();
            var resp = java.net.http.HttpClient.newHttpClient()
                    .send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return;

            var mapper = new ObjectMapper();
            var tokens = mapper.readTree(resp.body());
            var adminConn = new LinkedHashMap<String, Object>();
            adminConn.put("clientId", "admin-cli");
            adminConn.put("accessToken", tokens.get("access_token").asText());
            adminConn.put("refreshToken", tokens.get("refresh_token").asText());
            adminConn.put("expiresAt", java.time.Instant.now()
                    .plusSeconds(tokens.get("expires_in").asLong()).toString());

            var realms = (Map<String, Object>) wallet.computeIfAbsent("realms", k -> new LinkedHashMap<>());
            var masterRealm = (Map<String, Object>) realms.computeIfAbsent("master", k -> new LinkedHashMap<>());
            var masterUsers = (Map<String, Object>) masterRealm.computeIfAbsent("users", k -> new LinkedHashMap<>());
            masterUsers.put("admin", adminConn);
        } catch (Exception ignored) {
        }
    }

    @Test
    void showHelp() throws Exception {
        var result = cli("show", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("vc"), result.stdout());
        assertTrue(result.stdout().contains("key"), result.stdout());
        assertTrue(result.stdout().contains("realm"), result.stdout());
        assertTrue(result.stdout().contains("client"), result.stdout());
        assertTrue(result.stdout().contains("scope"), result.stdout());
        assertTrue(result.stdout().contains("user"), result.stdout());
    }

    @Test
    void showVcsList() throws Exception {
        var result = cli("show", "vc");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vc_natural_person_jwt"), result.stdout());
    }

    @Test
    void showVcsByIndex() throws Exception {
        var result = cli("show", "vc", "--credential-id", "1");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("credentialSubject"), result.stdout());
    }

    @Test
    void showVcsByName() throws Exception {
        var result = cli("show", "vc", "--credential-id", "oid4vc_natural_person_jwt_0000");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("credentialSubject"), result.stdout());
    }

    @Test
    void showVcsInvalidIndex() throws Exception {
        var result = cli("show", "vc", "--credential-id", "99");
        assertNotEquals(0, result.exitCode());
        assertTrue(result.stderr().contains("out of range"), result.stderr());
    }

    @Test
    void showKeys() throws Exception {
        var result = cli("show", "key");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("EC"), result.stdout());
        assertTrue(result.stdout().contains("P-256"), result.stdout());
    }

    @Test
    void showRealm() throws Exception {
        assumeTrue(realmAvailable, "Keycloak realm not available");
        assertTrue(adminLoggedIn(), "Admin login failed");

        var result = cli("show", "realm");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vci"), result.stdout());
    }

    @Test
    void showClient() throws Exception {
        assumeTrue(realmAvailable, "Keycloak realm not available");
        assertTrue(adminLoggedIn(), "Admin login failed");

        var result = cli("show", "client");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vci-client"), result.stdout());
    }

    @Test
    void showScope() throws Exception {
        assumeTrue(realmAvailable, "Keycloak realm not available");
        assertTrue(adminLoggedIn(), "Admin login failed");

        var result = cli("show", "scope", "--name", "oid4vc_natural_person_jwt");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vc_natural_person_jwt"), result.stdout());
    }

    @Test
    void showUser() throws Exception {
        assumeTrue(realmAvailable, "Keycloak realm not available");
        assertTrue(adminLoggedIn(), "Admin login failed");

        var result = cli("show", "user");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("alice"), result.stdout());
    }

    @Test
    void showUserByName() throws Exception {
        assumeTrue(realmAvailable, "Keycloak realm not available");
        assertTrue(adminLoggedIn(), "Admin login failed");

        var result = cli("show", "user", "--user", "max");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Mustermann"), result.stdout());
    }

    private boolean adminLoggedIn() {
        try {
            var wallet = new ObjectMapper().readTree(walletFile.toFile());
            var adminToken = wallet.at("/realms/master/users/admin/accessToken");
            return !adminToken.isMissingNode() && !adminToken.asText().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    private static String buildVcJwt(com.nimbusds.jose.jwk.ECKey ecKey, Map<String, Object> vcClaims) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("vc+jwt"))
                .keyID(ecKey.getKeyID())
                .build();
        var claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer("http://localhost:30800/realms/test")
                .subject("alice")
                .issueTime(new Date())
                .claim("vc", vcClaims)
                .build();
        var jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }
}
