package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyCmdTest extends AbstractCmdTest {

    @Test
    void keyHelp() throws Exception {
        var result = cli("key", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
    }

    @Test
    void createHolderKey() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        var result = cli("key", "create", "--algo", "ES256", "--user", "alice");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Created ES256 holder key"), result.stdout());
    }

    @Test
    void createNamedHolderKey() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        var result = cli("key", "create", "--algo", "ES256", "--name", "test-key", "--user", "alice");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Created ES256 holder key 'test-key'"), result.stdout());
    }

    @Test
    void createKeyMissingAlgo() throws Exception {
        var result = cli("key", "create", "--user", "alice");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void createKeyMissingUser() throws Exception {
        var result = cli("key", "create", "--algo", "ES256");
        assertNotEquals(0, result.exitCode());
    }
}
