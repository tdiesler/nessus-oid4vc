package io.nessus.oid4vp.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
            cli("client", "create", "oid4vci-client", "--realm", realm);
            cli("user", "create", "alice",
                "--realm", realm,
                "--first-name", "Alice", "--last-name", "Wonderland",
                "--email", "alice@test.com", "--password", "password");
            cli("login", "--realm", realm, "--client-id", "oid4vci-client",
                "--user", "alice", "--password", "password",
                "--scope", "oid4vc_natural_person_jwt");
            cli("key", "create", "--user", "alice", "--algo", "ES256");

            var result = cli("vc", "get", "--credential-id", "oid4vc_natural_person_jwt_0000");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Credential:"), result.stdout());
        } finally {
            cli("logout", "--realm", realm, "--user", "alice");
            cli("realm", "delete", realm);
        }
    }
}
