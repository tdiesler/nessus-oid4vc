package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class KeyCmdTest extends AbstractCmdTest {

    @Test
    void keyHelp() throws Exception {
        var result = cli("key", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
        assertTrue(result.stdout().contains("delete"), result.stdout());
    }

    @Test
    void keyCreateMissingTarget() throws Exception {
        var result = cli("key", "create", "--algo", "ES256");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void realmKeyCreateES256() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-key");
        try {
            var result = cli("key", "create", "--realm", "cli-test-key", "--algo", "ES256");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created ES256 key"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-key");
        }
    }

    @Test
    void realmKeyCreateECDH() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-key2");
        try {
            var result = cli("key", "create", "--realm", "cli-test-key2", "--algo", "ECDH-ES");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created ECDH-ES key"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-key2");
        }
    }

    @Test
    void realmKeyDeleteRS256() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        var realm = "cli-test-key-del";
        cli("realm", "create", realm);
        try {
            var result = cli("key", "delete", "--realm", realm, "--algo", "RS256");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Deleted RS256"), result.stdout());

            var again = cli("key", "delete", "--realm", realm, "--algo", "RS256");
            assertNotEquals(0, again.exitCode(), "Second delete should fail — key already gone");
        } finally {
            cli("realm", "delete", realm);
        }
    }
}
