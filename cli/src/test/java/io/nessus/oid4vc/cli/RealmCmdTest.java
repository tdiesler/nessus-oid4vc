package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RealmCmdTest extends AbstractCmdTest {

    @Test
    void realmHelp() throws Exception {
        var result = cli("realm", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
        assertTrue(result.stdout().contains("delete"), result.stdout());
    }

    @Test
    void realmCreateMissingName() throws Exception {
        var result = cli("realm", "create");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void realmCreateDeleteRoundTrip() throws Exception {
        assumeTrue(walletExists, "No wallet session — run 'oid4vc login' first");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        var create = cli("realm", "create", "oid4vci-test", "--display-name", "CLI Test");
        assertEquals(0, create.exitCode(), create.stderr());
        assertTrue(create.stdout().contains("Created realm"), create.stdout());

        var delete = cli("realm", "delete", "oid4vci-test");
        assertEquals(0, delete.exitCode(), delete.stderr());
        assertTrue(delete.stdout().contains("Deleted realm"), delete.stdout());
    }
}
