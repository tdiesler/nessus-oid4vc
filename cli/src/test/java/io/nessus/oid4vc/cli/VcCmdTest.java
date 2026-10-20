package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import io.nessus.oid4vc.dcql.SdJwtParser;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("unchecked")
class VcCmdTest extends AbstractCmdTest {

    static final ObjectMapper MAPPER = new ObjectMapper();

    // filterDisclosures — regression coverage for a bug where a nested DCQL claim path (e.g.
    // ["airline-ticket", "flightNumber"], addressing a field inside an object the GraphQL mapper discloses
    // as a single atomic claim) was matched against the disclosure's name using the LAST path segment
    // ("flightNumber") instead of the FIRST ("airline-ticket"), silently dropping the whole disclosure from
    // the presentation sent to the verifier.

    @Test
    void filterDisclosuresKeepsDisclosureAddressedByNestedPath() throws Exception {
        var sdJwtStr = fakeSdJwt(
                disclosure("salt1", "airline-ticket", Map.of("flightNumber", "BA123")),
                disclosure("salt2", "unrelatedClaim", "should be dropped"));

        var dcqlQuery = MAPPER.readTree("""
                {"credentials":[{"id":"airline_ticket_sd","claims":[
                    {"path":["airline-ticket","flightNumber"]},
                    {"path":["airline-ticket","passengerName"]}
                ]}]}""");

        var present = new VcCmd.Present();
        var filtered = present.filterDisclosures(sdJwtStr, dcqlQuery, "airline_ticket_sd");

        var parts = SdJwtParser.parse(filtered);
        var names = parts.disclosures().stream().map(SdJwtParser.Disclosure::claimName).toList();
        assertEquals(List.of("airline-ticket"), names, "must keep the 'airline-ticket' disclosure by its "
                + "first path segment and drop the unrequested one");
    }

    @Test
    void filterDisclosuresKeepsFlatClaimUnaffected() throws Exception {
        // Single-segment paths are unaffected by the first-vs-last-segment distinction (first == last);
        // this guards against a fix that accidentally breaks the pre-existing flat-claim case.
        var sdJwtStr = fakeSdJwt(
                disclosure("salt1", "firstName", "Alice"),
                disclosure("salt2", "familyName", "Wonderland"));

        var dcqlQuery = MAPPER.readTree("""
                {"credentials":[{"id":"natural_person_sd","claims":[
                    {"path":["firstName"]}
                ]}]}""");

        var present = new VcCmd.Present();
        var filtered = present.filterDisclosures(sdJwtStr, dcqlQuery, "natural_person_sd");

        var parts = SdJwtParser.parse(filtered);
        var names = parts.disclosures().stream().map(SdJwtParser.Disclosure::claimName).toList();
        assertEquals(List.of("firstName"), names);
    }

    private static String fakeSdJwt(String... disclosures) {
        var sb = new StringBuilder("fake.issuer.jwt");
        for (var d : disclosures) {
            sb.append("~").append(d);
        }
        sb.append("~");
        return sb.toString();
    }

    private static String disclosure(String salt, String claimName, Object value) throws Exception {
        var array = MAPPER.createArrayNode();
        array.add(salt);
        array.add(claimName);
        array.addPOJO(value);
        var json = MAPPER.writeValueAsString(array);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void vcHelp() throws Exception {
        var result = cli("vc", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("get"), result.stdout());
    }

    @Test
    void vcGetMissingArgs() throws Exception {
        var result = cli("vc", "get");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void vcGetViaPreAuthOffer() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var scope = "oid4vc_natural_person_jwt";

        // Login as iss (offer creator)
        var issLogin = cli("login", "--realm", DEFAULT_REALM, "--client", "oid4vci-client",
                "--user", "iss", "--password", "password");
        assertEquals(0, issLogin.exitCode(), issLogin.stderr());

        // Create pre-auth offer for alice
        var offerCreate = cli("offer", "create",
                "--credential-configuration", scope,
                "--target-user", "alice",
                "--pre-auth=true",
                "--user", "iss");
        assertEquals(0, offerCreate.exitCode(), offerCreate.stderr());

        // Alice fetches the offer
        var offerGet = cli("offer", "get", scope, "--user", "alice");
        assertEquals(0, offerGet.exitCode(), offerGet.stderr());

        // Alice redeems the offer
        var redeem = cli("offer", "redeem", scope, "--user", "alice");
        assertEquals(0, redeem.exitCode(), redeem.stderr());

        var vcJwt = redeem.stdout().trim();
        validateCredentialJwt(DEFAULT_REALM, vcJwt);
    }

    private ECKey findHolderKey(String realm, String user, String kid) throws Exception {
        var wallet = MAPPER.readTree(walletFile.toFile());
        var keys = wallet.at("/realms/" + realm + "/users/" + user + "/keys");
        assertFalse(keys.isMissingNode() || keys.isEmpty(), "No holder keys in wallet for " + user);
        for (var keyNode : keys) {
            if (kid.equals(keyNode.get("kid").asText())) {
                Map<String, Object> keyMap = MAPPER.convertValue(keyNode, Map.class);
                return ECKey.parse(keyMap).toPublicJWK();
            }
        }
        fail("Holder key '" + kid + "' not found in wallet for " + user);
        return null;
    }

    private void validateCredentialJwt(String realm, String vcJwt) throws Exception {

        var parts = vcJwt.split("\\.");
        assertEquals(3, parts.length, "JWT must have 3 parts (header.payload.signature)");

        var signedJwt = SignedJWT.parse(vcJwt);

        var header = signedJwt.getHeader();
        assertNotNull(header.getAlgorithm(), "JWT header must contain alg");
        assertEquals("vc+jwt", header.getType().getType());
        assertNotNull(header.getKeyID(), "JWT header must contain kid");

        var claims = signedJwt.getJWTClaimsSet();
        assertNotNull(claims.getIssuer(), "iss claim required");
        assertNotNull(claims.getNotBeforeTime(), "nbf claim required");
        assertNotNull(claims.getExpirationTime(), "exp claim required");
        assertEquals("alice", claims.getSubject(), "sub must be alice");

        var cnf = claims.getJSONObjectClaim("cnf");
        assertNotNull(cnf, "cnf claim required — credential must be key-bound");
        var cnfJwk = (Map<String, Object>) cnf.get("jwk");
        assertNotNull(cnfJwk, "cnf.jwk required — holder key must be present");

        var cnfKey = ECKey.parse(cnfJwk).toPublicJWK();
        var kid = (String) cnfJwk.get("kid");
        assertNotNull(kid, "cnf.jwk must contain kid");
        var walletKey = findHolderKey(realm, "alice", kid);
        assertEquals(cnfKey.getX(), walletKey.getX(), "cnf.jwk x must match wallet key");
        assertEquals(cnfKey.getY(), walletKey.getY(), "cnf.jwk y must match wallet key");
        assertEquals(cnfKey.getCurve(), walletKey.getCurve(), "cnf.jwk curve must match wallet key");

        var vc = claims.getJSONObjectClaim("vc");
        assertNotNull(vc, "vc claim required");
        assertNotNull(vc.get("type"), "vc.type required");
        assertNotNull(vc.get("credentialSubject"), "vc.credentialSubject required");

        var jwksUrl = getJwksUrl(realm);
        var jwkSet = JWKSet.load(URI.create(jwksUrl).toURL());
        var signingKey = jwkSet.getKeyByKeyId(header.getKeyID());
        assertNotNull(signingKey, "Signing key must be in realm JWKS");

        var verified = signedJwt.verify(new ECDSAVerifier((ECKey) signingKey));
        assertTrue(verified, "JWT signature must be valid");
    }
}
