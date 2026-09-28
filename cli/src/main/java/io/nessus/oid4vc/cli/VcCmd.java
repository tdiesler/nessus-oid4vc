package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "vc", mixinStandardHelpOptions = true, description = "Manage verifiable credentials",
    subcommands = { VcCmd.Get.class, VcCmd.Present.class })
class VcCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "get", description = "Fetch a verifiable credential")
    static class Get implements Callable<Integer> {

        @Option(names = "--credential-id", description = "Credential identifier from authorization_details")
        String credId;

        @Option(names = "--credential-configuration-id", description = "Credential configuration (e.g. oid4vc_natural_person_jwt)")
        String credConfigId;

        @Option(names = "--key", description = "Holder key name (defaults to default key for algo)")
        String key;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--user", description = "Username (defaults to realm's default user)")
        String user;

        @Override
        public Integer call() {
            if (credId == null && credConfigId == null) {
                System.err.println("Either --credential-id or --credential-configuration-id is required");
                return 1;
            }
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                if (Instant.parse(conn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
                    refreshAccessToken(wallet.serverUrl, realmName, conn);
                    saveWallet(wallet);
                }
                var accessToken = conn.accessToken;

                var nonceResponse = httpPost(
                    wallet.serverUrl + "/realms/" + realmName + "/protocol/oid4vc/nonce",
                    null, "application/x-www-form-urlencoded", accessToken);
                if (nonceResponse.statusCode() != 200) {
                    System.err.println("Nonce request failed: " + nonceResponse.body());
                    return 1;
                }
                var cNonce = MAPPER.readTree(nonceResponse.body()).get("c_nonce").asText();
                if (verbose) System.out.println("Nonce: " + cNonce);

                if (conn.keys == null || conn.keys.isEmpty()) {
                    System.err.println("No holder key. Run 'oid4vc key create --algo ES256 --user <name>' first.");
                    return 1;
                }
                var resolvedKid = key != null ? key : conn.defaultKey;
                Map<String, Object> jwkMap;
                if (resolvedKid != null) {
                    var kid = resolvedKid;
                    jwkMap = conn.keys.stream()
                        .filter(k -> kid.equals(k.get("kid")))
                        .findFirst().orElse(null);
                    if (jwkMap == null) {
                        var kids = conn.keys.stream().map(k -> k.get("kid")).toList();
                        System.err.println("No key with kid '" + kid + "'. Available: " + kids);
                        return 1;
                    }
                } else {
                    jwkMap = conn.keys.get(0);
                }
                var usedKid = (String) jwkMap.get("kid");
                if (verbose) System.out.println("Using key '" + usedKid + "'");
                var ecKey = com.nimbusds.jose.jwk.ECKey.parse(jwkMap);
                var proofHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(ecKey.toPublicJWK())
                    .build();
                var proofPayload = new JWTClaimsSet.Builder()
                    .issuer(conn.clientId)
                    .audience(wallet.serverUrl + "/realms/" + realmName)
                    .issueTime(Date.from(Instant.now()))
                    .claim("nonce", cNonce)
                    .build();
                var signedJwt = new SignedJWT(proofHeader, proofPayload);
                signedJwt.sign(new ECDSASigner(ecKey));

                Map<String, Object> credRequest;
                if (credId != null) {
                    credRequest = Map.of(
                        "credential_identifier", credId,
                        "proofs", Map.of("jwt", List.of(signedJwt.serialize())));
                } else {
                    credRequest = Map.of(
                        "credential_configuration_id", credConfigId,
                        "proofs", Map.of("jwt", List.of(signedJwt.serialize())));
                }
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
                    var credKey = credId != null ? credId : credConfigId;
                    if (conn.credentials == null) conn.credentials = new LinkedHashMap<>();
                    conn.credentials.put(credKey, vcJwt);
                    saveWallet(wallet);
                    System.out.println(vcJwt);
                } else {
                    System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(credJson));
                }
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed to get credential: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "present", description = "Present verifiable credentials to a verifier")
    static class Present implements Callable<Integer> {

        @Option(names = "--verifier", required = true, description = "Verifier endpoint URL")
        String verifierUrl;

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = {"-u", "--user"}, description = "Username (defaults to realm's default user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                if (verbose) System.out.println("Contacting verifier: " + verifierUrl);

                var authRequest = HttpRequest.newBuilder()
                        .uri(URI.create(verifierUrl))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build();
                var authResponse = HTTP.send(authRequest, HttpResponse.BodyHandlers.ofString());
                if (authResponse.statusCode() != 200) {
                    System.err.println("Verifier request failed: " + authResponse.body());
                    return 1;
                }

                var authJson = MAPPER.readTree(authResponse.body());
                var dcqlQuery = authJson.get("dcql_query");
                var nonce = authJson.path("nonce").asText(null);
                var responseUri = authJson.get("response_uri").asText();

                if (verbose) {
                    System.out.println("DCQL query: " + MAPPER.writeValueAsString(dcqlQuery));
                    System.out.println("Nonce: " + nonce);
                    System.out.println("Response URI: " + responseUri);
                }

                if (conn.credentials == null || conn.credentials.isEmpty()) {
                    System.err.println("No credentials in wallet. Run 'oid4vc vc get' first.");
                    return 1;
                }

                var vpToken = matchCredentials(dcqlQuery, conn.credentials);
                if (vpToken.isEmpty()) {
                    System.err.println("No matching credentials found for the verifier's query");
                    return 1;
                }

                if (verbose) System.out.println("Matched credentials: " + vpToken.keySet());

                var resolvedUser = user != null ? user : resolveDefaultUser(wallet, realmName);
                var responseBody = new LinkedHashMap<String, Object>();
                responseBody.put("vp_token", vpToken);
                responseBody.put("passenger_id", resolvedUser);
                var body = MAPPER.writeValueAsString(responseBody);

                var vpResponse = httpPost(responseUri, body, "application/json", null);
                if (vpResponse.statusCode() != 200) {
                    System.err.println("Presentation failed: " + vpResponse.body());
                    return 1;
                }

                var result = MAPPER.readTree(vpResponse.body());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result));
                return 0;
            } catch (Exception ex) {
                System.err.println("Presentation failed: " + ex.getMessage());
                return 1;
            }
        }

        private Map<String, String> matchCredentials(JsonNode dcqlQuery, Map<String, String> walletCredentials) {
            var matched = new LinkedHashMap<String, String>();
            var credentials = dcqlQuery.get("credentials");
            if (credentials == null || !credentials.isArray()) return matched;

            for (var credQuery : credentials) {
                var credId = credQuery.get("id").asText();
                for (var entry : walletCredentials.entrySet()) {
                    var walletKey = entry.getKey();
                    if (walletKey.startsWith("oid4vc_" + credId) || walletKey.contains(credId)) {
                        matched.put(credId, entry.getValue());
                        break;
                    }
                }
            }
            return matched;
        }

        private String resolveDefaultUser(WalletState wallet, String realm) {
            if (wallet.realms != null && wallet.realms.containsKey(realm)) {
                var realmState = wallet.realms.get(realm);
                if (realmState.defaultUser != null) return realmState.defaultUser;
                if (realmState.users != null && !realmState.users.isEmpty()) {
                    return realmState.users.keySet().iterator().next();
                }
            }
            return "unknown";
        }
    }
}
