package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "vp", mixinStandardHelpOptions = true, description = "Manage verifiable presentations",
    subcommands = { VpCmd.Present.class })
class VpCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "present", description = "Present verifiable credentials to a verifier")
    static class Present implements Callable<Integer> {

        @Option(names = "--verifier", required = true, description = "Verifier endpoint URL")
        String verifierUrl;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--user", description = "Username (defaults to realm's default user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            try {
                // Step 1: Contact verifier, get DCQL query
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

                // Step 2: Match wallet credentials against DCQL query
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

                // Step 3: Send VP token to response_uri
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
                // Match by credential ID prefix in wallet keys
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
