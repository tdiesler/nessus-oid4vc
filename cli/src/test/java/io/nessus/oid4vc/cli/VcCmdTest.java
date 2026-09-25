package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("unchecked")
class VcCmdTest extends AbstractCmdTest {

    static final ObjectMapper MAPPER = new ObjectMapper();

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
    void vcGetByCredentialId() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var scope = "oid4vc_natural_person_jwt";
        var login = cli("login", "--realm", DEFAULT_REALM, "--client-id", "oid4vci-client",
                "--user", "alice", "--password", "password", "--scope", scope);
        assertEquals(0, login.exitCode(), login.stderr());

        var result = cli("vc", "get", "--credential-id", scope + "_0000");
        assertEquals(0, result.exitCode(), result.stderr());

        var vcJwt = result.stdout().trim();
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

        var verified = signedJwt.verify(new RSASSAVerifier((RSAKey) signingKey));
        assertTrue(verified, "JWT signature must be valid");
    }
}
