package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ClientScopeCmdTest extends AbstractCmdTest {

    @Test
    void scopeHelp() throws Exception {
        var result = cli("scope", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
    }

    @Test
    void scopeCreateInTestRealm() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-scope");
        try {
            var result = cli("scope", "create", "oid4vc_test_scope",
                    "--realm", "cli-test-scope");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created client scope"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-scope");
        }
    }
}
