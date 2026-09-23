package io.nessus.oid4vp.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ClientScopeCmdTest extends AbstractCmdTest {

    @Test
    void clientScopeHelp() throws Exception {
        var result = cli("client-scope", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
    }

    @Test
    void clientScopeCreateInTestRealm() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        cli("realm", "create", "cli-test-scope");
        try {
            var result = cli("client-scope", "create", "oid4vc_test_scope",
                "--realm", "cli-test-scope",
                "--attr", "oid4vc.credential.format=jwt_vc");
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Created client scope"), result.stdout());
        } finally {
            cli("realm", "delete", "cli-test-scope");
        }
    }
}
