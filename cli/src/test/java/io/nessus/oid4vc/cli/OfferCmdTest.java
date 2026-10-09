package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OfferCmdTest extends AbstractCmdTest {

    static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void offerHelp() throws Exception {
        var result = cli("offer", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
        assertTrue(result.stdout().contains("get"), result.stdout());
        assertTrue(result.stdout().contains("redeem"), result.stdout());
    }

    @Test
    void offerCreateMissingArgs() throws Exception {
        var result = cli("offer", "create");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void offerGetMissingArgs() throws Exception {
        var result = cli("offer", "get");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void offerRedeemMissingArgs() throws Exception {
        var result = cli("offer", "redeem");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void offerCreateGetAndRedeem() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var credConfigId = "oid4vc_natural_person_jwt";

        // Log in as max (has credential_offer_create role)
        var maxLogin = cli("login", "--realm", DEFAULT_REALM, "--client", "oid4vci-client",
                "--user", "max", "--password", "password");
        assertEquals(0, maxLogin.exitCode(), maxLogin.stderr());

        // Max creates a pre-authorized offer — stored in alice's wallet
        var createResult = cli("offer", "create",
                "--credential-configuration", credConfigId,
                "--target-user", "alice",
                "--pre-auth=true",
                "--user", "max");
        assertEquals(0, createResult.exitCode(), createResult.stderr());

        // Verify offer URI stored in alice's wallet
        var wallet = MAPPER.readTree(walletFile.toFile());
        var offers = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/offers");
        assertFalse(offers.isMissingNode(), "Offers must be in wallet");
        assertTrue(offers.has(credConfigId), "Offer for " + credConfigId + " must be in wallet");
        assertTrue(offers.get(credConfigId).has("offerUri"), "Stored offer must have offerUri");

        // Show offers list — should show [pending]
        var showList = cli("show", "offer", "--user", "alice");
        assertEquals(0, showList.exitCode(), showList.stderr());
        assertTrue(showList.stdout().contains(credConfigId), showList.stdout());
        assertTrue(showList.stdout().contains("pending"), showList.stdout());

        // Show offer detail by name
        var showDetail = cli("show", "offer", credConfigId, "--user", "alice");
        assertEquals(0, showDetail.exitCode(), showDetail.stderr());
        assertTrue(showDetail.stdout().contains("offerUri"), showDetail.stdout());

        // Alice fetches the offer by name
        var getResult = cli("offer", "get", credConfigId,
                "--user", "alice");
        assertEquals(0, getResult.exitCode(), getResult.stderr());

        // Verify offer is now fetched (has credential_configuration_ids, no offerUri)
        wallet = MAPPER.readTree(walletFile.toFile());
        offers = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/offers");
        var fetchedOffer = offers.get(credConfigId);
        assertFalse(fetchedOffer.has("offerUri"), "Fetched offer must not have offerUri");
        assertTrue(fetchedOffer.has("credential_configuration_ids"), "Fetched offer must have credential_configuration_ids");

        // Show offers list — should show [fetched]
        showList = cli("show", "offer", "--user", "alice");
        assertEquals(0, showList.exitCode(), showList.stderr());
        assertTrue(showList.stdout().contains("fetched"), showList.stdout());

        // Show offer detail by name — should show full offer
        showDetail = cli("show", "offer", credConfigId, "--user", "alice");
        assertEquals(0, showDetail.exitCode(), showDetail.stderr());
        assertTrue(showDetail.stdout().contains("credential_configuration_ids"), showDetail.stdout());

        // Alice redeems the offer
        var redeemResult = cli("offer", "redeem", credConfigId,
                "--user", "alice");
        assertEquals(0, redeemResult.exitCode(), redeemResult.stderr());

        var vcJwt = redeemResult.stdout().trim();
        assertFalse(vcJwt.isEmpty(), "Credential must not be empty");
        assertTrue(vcJwt.contains("."), "Credential must be a JWT");

        // Verify offer removed and credential stored
        wallet = MAPPER.readTree(walletFile.toFile());
        offers = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/offers");
        assertFalse(offers.has(credConfigId), "Offer must be removed after redemption");
        var credentials = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/credentials");
        assertFalse(credentials.isMissingNode(), "Credentials must be in wallet");
    }

    @Test
    void offerCreateGetAndRedeemByIndex() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var credConfigId = "oid4vc_natural_person_jwt";

        // Log in as max (has credential_offer_create role)
        var maxLogin = cli("login", "--realm", DEFAULT_REALM, "--client", "oid4vci-client",
                "--user", "max", "--password", "password");
        assertEquals(0, maxLogin.exitCode(), maxLogin.stderr());

        // Max creates a pre-authorized offer — stored in alice's wallet
        var createResult = cli("offer", "create",
                "--credential-configuration", credConfigId,
                "--target-user", "alice",
                "--pre-auth=true",
                "--user", "max");
        assertEquals(0, createResult.exitCode(), createResult.stderr());

        // Show offer by index
        var showResult = cli("show", "offer", "1");
        assertEquals(0, showResult.exitCode(), showResult.stderr());
        assertTrue(showResult.stdout().contains("offerUri"), showResult.stdout());

        // Get by index
        var getResult = cli("offer", "get", "1", "--user", "alice");
        assertEquals(0, getResult.exitCode(), getResult.stderr());

        // Show fetched offer by index
        showResult = cli("show", "offer", "1");
        assertEquals(0, showResult.exitCode(), showResult.stderr());
        assertTrue(showResult.stdout().contains("credential_configuration_ids"), showResult.stdout());

        // Redeem by index
        var redeemResult = cli("offer", "redeem", "1", "--user", "alice");
        assertEquals(0, redeemResult.exitCode(), redeemResult.stderr());

        var vcJwt = redeemResult.stdout().trim();
        assertFalse(vcJwt.isEmpty(), "Credential must not be empty");
        assertTrue(vcJwt.contains("."), "Credential must be a JWT");
    }

    @Test
    void offerAuthCodeGrant() throws Exception {
        assumeTrue(realmAvailable, "Run oid4vc-setup first");
        assumeTrue(walletExists, "Run oid4vc-setup first");

        var credConfigId = "oid4vc_natural_person_jwt";

        // Log in as max (has credential_offer_create role)
        var maxLogin = cli("login", "--realm", DEFAULT_REALM, "--client", "oid4vci-client",
                "--user", "max", "--password", "password");
        assertEquals(0, maxLogin.exitCode(), maxLogin.stderr());

        // Max creates an authorization code grant offer
        var createResult = cli("offer", "create",
                "--credential-configuration", credConfigId,
                "--target-user", "alice",
                "--pre-auth=false",
                "--user", "max");
        assertEquals(0, createResult.exitCode(), createResult.stderr());

        // Alice fetches the offer
        var getResult = cli("offer", "get", credConfigId, "--user", "alice");
        assertEquals(0, getResult.exitCode(), getResult.stderr());

        // Verify it's an auth code grant (no pre-authorized_code)
        var wallet = MAPPER.readTree(walletFile.toFile());
        var fetchedOffer = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/offers/" + credConfigId);
        assertFalse(fetchedOffer.has("pre-authorized_code"), "Auth code offer must not have pre-authorized_code");

        // Alice logs in with the right scope before redeeming
        var aliceLogin = cli("login", "--realm", DEFAULT_REALM, "--client", "oid4vci-client",
                "--user", "alice", "--password", "password", "--scope", credConfigId);
        assertEquals(0, aliceLogin.exitCode(), aliceLogin.stderr());

        // Alice redeems the auth code offer
        var redeemResult = cli("offer", "redeem", credConfigId, "--user", "alice");
        assertEquals(0, redeemResult.exitCode(), redeemResult.stderr());

        var vcJwt = redeemResult.stdout().trim();
        assertFalse(vcJwt.isEmpty(), "Credential must not be empty");
        assertTrue(vcJwt.contains("."), "Credential must be a JWT");

        // Verify offer removed and credential stored
        wallet = MAPPER.readTree(walletFile.toFile());
        var offers = wallet.at("/realms/" + DEFAULT_REALM + "/users/alice/offers");
        assertFalse(offers.has(credConfigId), "Offer must be removed after redemption");
    }
}
