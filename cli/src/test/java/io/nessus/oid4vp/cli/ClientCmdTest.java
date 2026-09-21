package io.nessus.oid4vp.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ClientCmdTest extends AbstractCmdTest {

    @Test
    void clientHelp() throws Exception {
        var result = cli("client", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
    }

    @Test
    void clientCreateMissingId() throws Exception {
        var result = cli("client", "create");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void clientCreateInTestRealm() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-client");
        try {
            var result = cli("client", "create", "test-client", "--realm", "cli-test-client");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created client"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-client");
        }
    }
}
