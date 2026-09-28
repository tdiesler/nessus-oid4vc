package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ShowCmdTest extends AbstractCmdTest {

    @Test
    void showHelp() throws Exception {
        var result = cli("show", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("vcs"), result.stdout());
        assertTrue(result.stdout().contains("keys"), result.stdout());
        assertTrue(result.stdout().contains("realm"), result.stdout());
        assertTrue(result.stdout().contains("client"), result.stdout());
        assertTrue(result.stdout().contains("scope"), result.stdout());
        assertTrue(result.stdout().contains("user"), result.stdout());
    }

    @Test
    void showVcsList() throws Exception {
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var result = cli("show", "vcs");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vc_natural_person_jwt"), result.stdout());
    }

    @Test
    void showVcsByIndex() throws Exception {
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var result = cli("show", "vcs", "--credential-id", "1");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("credentialSubject"), result.stdout());
    }

    @Test
    void showVcsByName() throws Exception {
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var result = cli("show", "vcs", "--credential-id", "oid4vc_natural_person_jwt_0000");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("credentialSubject"), result.stdout());
    }

    @Test
    void showVcsInvalidIndex() throws Exception {
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var result = cli("show", "vcs", "--credential-id", "99");
        assertNotEquals(0, result.exitCode());
        assertTrue(result.stderr().contains("out of range"), result.stderr());
    }

    @Test
    void showKeys() throws Exception {
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var result = cli("show", "keys");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("EC"), result.stdout());
        assertTrue(result.stdout().contains("P-256"), result.stdout());
    }

    @Test
    void showRealm() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        assumeTrue(adminLoggedIn(), "Admin login required");

        var result = cli("show", "realm");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vci"), result.stdout());
    }

    @Test
    void showClient() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        assumeTrue(adminLoggedIn(), "Admin login required");

        var result = cli("show", "client");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vci-client"), result.stdout());
    }

    @Test
    void showScope() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        assumeTrue(adminLoggedIn(), "Admin login required");

        var result = cli("show", "scope", "--name", "oid4vc_natural_person_jwt");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("oid4vc_natural_person_jwt"), result.stdout());
    }

    @Test
    void showUser() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        assumeTrue(adminLoggedIn(), "Admin login required");

        var result = cli("show", "user");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("alice"), result.stdout());
    }

    @Test
    void showUserByName() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");
        assumeTrue(adminLoggedIn(), "Admin login required");

        var result = cli("show", "user", "--user", "max");
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Mustermann"), result.stdout());
    }

    private boolean adminLoggedIn() {
        try {
            var wallet = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(walletFile.toFile());
            var adminToken = wallet.at("/realms/master/users/admin/accessToken");
            return !adminToken.isMissingNode() && !adminToken.asText().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}
