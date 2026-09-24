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

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "vc", mixinStandardHelpOptions = true, description = "Manage verifiable credentials",
    subcommands = { VcCmd.Get.class })
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
}
