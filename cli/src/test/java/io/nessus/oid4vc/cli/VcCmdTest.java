package io.nessus.oid4vc.cli;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class VcCmdTest extends AbstractCmdTest {

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
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        var realm = "cli-test-vc";
        cli("realm", "create", realm);
        try {
            cli("key", "create", "--realm", realm, "--algo", "ES256", "--priority", "120");
            cli("key", "create", "--realm", realm, "--algo", "ECDH-ES", "--priority", "130");
            cli("client", "create", "oid4vci-client", "--realm", realm,
                "--vc-scope", "oid4vc_natural_person_sd",
                "--vc-scope", "oid4vc_natural_person_jwt");
            cli("user", "create", "alice",
                "--realm", realm,
                "--first-name", "Alice", "--last-name", "Wonderland",
                "--email", "alice@test.com", "--password", "password",
                "--vc-scope", "oid4vc_natural_person_sd",
                "--vc-scope", "oid4vc_natural_person_jwt");
            cli("login", "--realm", realm, "--client-id", "oid4vci-client",
                "--user", "alice", "--password", "password",
                "--scope", "oid4vc_natural_person_jwt");
            cli("key", "create", "--user", "alice", "--algo", "ES256");

            var result = cli("vc", "get", "--credential-id", "oid4vc_natural_person_jwt_0000");
            assertEquals(0, result.exitCode(), result.stderr());

            var vcJwt = result.stdout().trim();
            assertTrue(validateCredentialJwt(realm, vcJwt));
        } finally {
            cli("logout", "--realm", realm, "--user", "alice");
            cli("realm", "delete", realm);
        }
    }

    private boolean validateCredentialJwt(String realm, String vcJwt) throws Exception {

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

        return true;
    }
}
