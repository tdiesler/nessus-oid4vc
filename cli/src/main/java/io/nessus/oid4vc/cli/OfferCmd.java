package io.nessus.oid4vc.cli;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "offer", mixinStandardHelpOptions = true, description = "Manage credential offers",
    subcommands = { OfferCmd.Create.class, OfferCmd.Get.class, OfferCmd.Redeem.class })
class OfferCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "create", description = "Create a credential offer")
    static class Create implements Callable<Integer> {

        @Option(names = "--credential-configuration", required = true, description = "Credential configuration (e.g. oid4vc_airline_ticket_jwt)")
        String credConfigId;

        @Option(names = "--pre-auth", defaultValue = "true", description = "Pre-authorized code grant offer (default: true)")
        boolean preAuthorized;

        @Option(names = "--target-user", required = true, description = "Username the credential offer is for")
        String targetUser;

        @Option(names = "--store-for", description = "Wallet user to store the offer for (defaults to target-user)")
        String storeFor;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--user", description = "Issuing user (defaults to current logged-in user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                if (Instant.parse(conn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
                    refreshAccessToken(wallet.serverUrl, realmName, conn);
                    saveWallet(wallet);
                }

                var url = wallet.serverUrl + "/realms/" + realmName + "/protocol/oid4vc/create-credential-offer"
                    + "?credential_configuration_id=" + URLEncoder.encode(credConfigId, StandardCharsets.UTF_8)
                    + "&pre_authorized=" + preAuthorized
                    + "&target_user=" + URLEncoder.encode(targetUser, StandardCharsets.UTF_8)
                    + "&type=uri_qr&width=500&height=500";

                var response = httpGet(url, conn.accessToken);
                if (response.statusCode() != 200) {
                    System.err.println("Offer creation failed: " + response.body());
                    return 1;
                }

                var json = MAPPER.readTree(response.body());
                var offerUri = json.get("issuer").asText() + "/" + json.get("nonce").asText();

                // Store offer URI and QR code in wallet and switch default user
                var storeUser = storeFor != null ? storeFor : targetUser;
                var storeConn = resolveWalletEntry(wallet, realmName, storeUser);
                if (storeConn.offers == null) storeConn.offers = new LinkedHashMap<>();
                var offerData = new LinkedHashMap<String, Object>();
                offerData.put("offerUri", offerUri);
                var qrNode = json.get("qr_code");
                if (qrNode != null) offerData.put("qrCode", qrNode.asText());
                storeConn.offers.put(credConfigId, offerData);
                wallet.realms.get(realmName).defaultUser = storeUser;
                saveWallet(wallet);

                System.out.println("Offer URI stored for " + storeUser + ": " + credConfigId);
                var displayJson = MAPPER.createObjectNode();
                displayJson.put("issuer", json.get("issuer").asText());
                displayJson.put("nonce", json.get("nonce").asText());
                if (qrNode != null) {
                    var qrValue = qrNode.asText();
                    var prefix = qrValue.substring(0, Math.min(34, qrValue.length()));
                    var suffix = qrValue.substring(Math.max(0, qrValue.length() - 12));
                    displayJson.put("qrCode", prefix + "..." + suffix);
                    openQrCode(qrValue);
                }
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(displayJson));
                return 0;
            } catch (Exception ex) {
                System.err.println("Offer creation failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    static String resolveOfferKey(String input, Map<String, Map<String, Object>> offers) {
        if (offers == null || offers.isEmpty()) return input;
        try {
            int idx = Integer.parseInt(input);
            var keys = offers.keySet().toArray(new String[0]);
            if (idx >= 1 && idx <= keys.length) return keys[idx - 1];
        } catch (NumberFormatException ignored) {}
        return input;
    }

    @Command(name = "get", description = "Fetch a credential offer from its stored URI")
    static class Get implements Callable<Integer> {

        @CommandLine.Parameters(index = "0", description = "Credential configuration ID or index number")
        String credConfigId;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--user", description = "Wallet user (defaults to current user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                var resolvedId = resolveOfferKey(credConfigId, conn.offers);
                if (conn.offers == null || !conn.offers.containsKey(resolvedId)) {
                    System.err.println("No pending offer for '" + credConfigId + "'. Run 'oid4vc show offer' to list.");
                    return 1;
                }

                var stored = conn.offers.get(resolvedId);
                var offerUri = (String) stored.get("offerUri");
                if (offerUri == null) {
                    System.err.println("Offer already fetched. Run 'oid4vc show offer' or 'oid4vc offer redeem'.");
                    return 1;
                }

                var response = httpGet(offerUri, null);
                if (response.statusCode() != 200) {
                    System.err.println("Failed to fetch offer: " + response.body());
                    return 1;
                }

                var offer = MAPPER.readTree(response.body());
                @SuppressWarnings("unchecked")
                var offerMap = (Map<String, Object>) MAPPER.convertValue(offer, Map.class);
                conn.offers.put(resolvedId, offerMap);
                saveWallet(wallet);

                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(offer));
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed to fetch offer: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "redeem", description = "Redeem a fetched credential offer")
    static class Redeem implements Callable<Integer> {

        @CommandLine.Parameters(index = "0", description = "Credential configuration ID or index number")
        String credConfigId;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--user", description = "Wallet user (defaults to current user)")
        String user;

        @Option(names = "--client", description = "OAuth client ID (defaults to stored default)")
        String clientId;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                var resolvedId = resolveOfferKey(credConfigId, conn.offers);
                if (conn.offers == null || !conn.offers.containsKey(resolvedId)) {
                    System.err.println("No offer for '" + credConfigId + "'. Run 'oid4vc offer get' first.");
                    return 1;
                }

                var offerMap = conn.offers.get(resolvedId);
                if (offerMap.containsKey("offerUri")) {
                    System.err.println("Offer not yet fetched. Run 'oid4vc offer get " + resolvedId + "' first.");
                    return 1;
                }

                var offer = MAPPER.valueToTree(offerMap);

                var oauthClientId = clientId;
                if (oauthClientId == null) oauthClientId = conn.clientId;

                String accessToken;
                String credId;

                var preAuthGrant = offer.path("grants").path("urn:ietf:params:oauth:grant-type:pre-authorized_code");
                var preAuthCode = preAuthGrant.path("pre-authorized_code").asText(null);

                if (preAuthCode != null) {
                    // Pre-authorized code grant: exchange code for token
                    var tokenBody = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                        + "&pre-authorized_code=" + URLEncoder.encode(preAuthCode, StandardCharsets.UTF_8)
                        + "&client_id=" + URLEncoder.encode(oauthClientId, StandardCharsets.UTF_8);

                    var tokenResponse = httpPost(
                        wallet.serverUrl + "/realms/" + realmName + "/protocol/openid-connect/token",
                        tokenBody, "application/x-www-form-urlencoded", null);
                    if (tokenResponse.statusCode() != 200) {
                        System.err.println("Token exchange failed: " + tokenResponse.body());
                        return 1;
                    }

                    var tokenJson = MAPPER.readTree(tokenResponse.body());
                    accessToken = tokenJson.get("access_token").asText();
                    if (verbose) System.err.println("Access token obtained via pre-auth code");

                    // Extract credential identifier from authorization_details
                    credId = null;
                    var authDetails = tokenJson.get("authorization_details");
                    if (authDetails != null && authDetails.isArray() && !authDetails.isEmpty()) {
                        var credIds = authDetails.get(0).get("credential_identifiers");
                        if (credIds != null && credIds.isArray() && !credIds.isEmpty()) {
                            credId = credIds.get(0).asText();
                        }
                    }
                    if (credId == null) {
                        credId = resolvedId + "_0000";
                    }
                } else {
                    // Authorization code grant: user must already be logged in
                    if (conn.accessToken == null) {
                        System.err.println("Authorization code offer requires login. Run 'oid4vc login --scope " + resolvedId + "' first.");
                        return 1;
                    }
                    if (Instant.parse(conn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
                        refreshAccessToken(wallet.serverUrl, realmName, conn);
                        saveWallet(wallet);
                    }
                    accessToken = conn.accessToken;
                    credId = null;
                    if (conn.authorizationDetails != null) {
                        for (var entry : conn.authorizationDetails) {
                            if (resolvedId.equals(entry.get("credential_configuration_id"))) {
                                @SuppressWarnings("unchecked")
                                var credIds = (List<String>) entry.get("credential_identifiers");
                                if (credIds != null && !credIds.isEmpty()) {
                                    credId = credIds.get(0);
                                }
                                break;
                            }
                        }
                    }
                    if (credId == null) {
                        credId = resolvedId + "_0000";
                    }
                    if (verbose) System.err.println("Using existing access token for auth code grant");
                }
                if (verbose) System.err.println("Credential identifier: " + credId);

                // Get nonce
                var nonceResponse = httpPost(
                    wallet.serverUrl + "/realms/" + realmName + "/protocol/oid4vc/nonce",
                    null, "application/x-www-form-urlencoded", accessToken);
                if (nonceResponse.statusCode() != 200) {
                    System.err.println("Nonce request failed: " + nonceResponse.body());
                    return 1;
                }
                var cNonce = MAPPER.readTree(nonceResponse.body()).get("c_nonce").asText();
                if (verbose) System.err.println("Nonce: " + cNonce);

                // Build proof JWT using holder key
                if (conn.keys == null || conn.keys.isEmpty()) {
                    System.err.println("No holder key. Run 'oid4vc key create --algo ES256 --user <name>' first.");
                    return 1;
                }
                var resolvedKid = conn.defaultKey;
                Map<String, Object> jwkMap;
                if (resolvedKid != null) {
                    var kid = resolvedKid;
                    jwkMap = conn.keys.stream()
                        .filter(k -> kid.equals(k.get("kid")))
                        .findFirst().orElse(null);
                    if (jwkMap == null) {
                        System.err.println("No key with kid '" + kid + "'");
                        return 1;
                    }
                } else {
                    jwkMap = conn.keys.get(0);
                }

                var ecKey = com.nimbusds.jose.jwk.ECKey.parse(jwkMap);
                var proofHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(ecKey.toPublicJWK())
                    .build();
                var proofPayload = new JWTClaimsSet.Builder()
                    .issuer(oauthClientId)
                    .audience(wallet.serverUrl + "/realms/" + realmName)
                    .issueTime(Date.from(Instant.now()))
                    .claim("nonce", cNonce)
                    .build();
                var signedJwt = new SignedJWT(proofHeader, proofPayload);
                signedJwt.sign(new ECDSASigner(ecKey));

                // Request credential
                var credRequest = Map.of(
                    "credential_identifier", credId,
                    "proofs", Map.of("jwt", List.of(signedJwt.serialize())));
                var credBody = MAPPER.writeValueAsString(credRequest);

                var credResponse = httpPost(
                    wallet.serverUrl + "/realms/" + realmName + "/protocol/oid4vc/credential",
                    credBody, "application/json", accessToken);
                if (credResponse.statusCode() != 200) {
                    System.err.println("Credential request failed: " + credResponse.body());
                    return 1;
                }

                var credJson = MAPPER.readTree(credResponse.body());
                var credentials = credJson.get("credentials");
                if (credentials != null && credentials.isArray() && !credentials.isEmpty()) {
                    String vcJwt = credentials.get(0).get("credential").asText();
                    if (conn.credentials == null) conn.credentials = new LinkedHashMap<>();
                    conn.credentials.put(credId, vcJwt);
                    conn.offers.remove(resolvedId);
                    saveWallet(wallet);
                    System.out.println(vcJwt);
                } else {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(credJson));
                }
                return 0;
            } catch (Exception ex) {
                System.err.println("Offer redemption failed: " + ex.getMessage());
                return 1;
            }
        }
    }
}
