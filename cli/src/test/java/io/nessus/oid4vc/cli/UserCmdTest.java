package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class UserCmdTest extends AbstractCmdTest {

    @Test
    void userHelp() throws Exception {
        var result = cli("user", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
    }

    @Test
    void userCreateMissingArgs() throws Exception {
        var result = cli("user", "create");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void userCreateIssuer() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-user");
        try {
            var result = cli("user", "create", "max",
                "--realm", "cli-test-user",
                "--first-name", "Max", "--last-name", "Mustermann",
                "--email", "max@test.com", "--password", "password",
                "--role", "issuer",
                "--vc-scope", "oid4vc_natural_person_sd",
                "--vc-scope", "oid4vc_natural_person_jwt");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created user: max"), result.stdout());
            assertTrue(result.stdout().contains("Assigned role"), result.stdout());
            assertTrue(result.stdout().contains("Assigned VC scope"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-user");
        }
    }

    @Test
    void userCreateHolder() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-user2");
        try {
            var result = cli("user", "create", "alice",
                "--realm", "cli-test-user2",
                "--first-name", "Alice", "--last-name", "Wonderland",
                "--email", "alice@test.com", "--password", "password",
                "--vc-scope", "oid4vc_natural_person_sd",
                "--vc-scope", "oid4vc_natural_person_jwt");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created user: alice"), result.stdout());
            assertTrue(result.stdout().contains("Assigned VC scope"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-user2");
        }
    }
}
