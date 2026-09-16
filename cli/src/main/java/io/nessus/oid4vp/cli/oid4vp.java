///usr/bin/env jbang "$0" "$@" ; exit $?

//DEPS info.picocli:picocli:4.7.6
// Keep keycloak version aligned with pom.xml (from github.com/keycloak/keycloak-client)
//DEPS org.keycloak:keycloak-admin-client:26.0.12
//DEPS com.fasterxml.jackson.core:jackson-databind:2.17.0

package io.nessus.oid4vp.cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RealmRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.Callable;

@Command(name = "oid4vp", mixinStandardHelpOptions = true,
    subcommands = {
        oid4vp.Login.class,
        oid4vp.Realm.class
    })
public class oid4vp implements Runnable {

    static final Path WALLET_DIR = Path.of(System.getProperty("user.home"), ".config", "nessus-oid4vp");
    static final Path WALLET_FILE = WALLET_DIR.resolve("wallet.json");
    static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .enable(SerializationFeature.INDENT_OUTPUT);
    static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] args) {
        System.exit(new CommandLine(new oid4vp()).execute(args));
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    static WalletState loadWallet() {
        if (!Files.exists(WALLET_FILE)) {
            throw new IllegalStateException("Not logged in. Run 'oid4vp login' first.");
        }
        try {
            return MAPPER.readValue(WALLET_FILE.toFile(), WalletState.class);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to read wallet: " + ex.getMessage(), ex);
        }
    }

    static void saveWallet(WalletState state) {
        try {
            Files.createDirectories(WALLET_DIR);
            MAPPER.writeValue(WALLET_FILE.toFile(), state);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to save wallet: " + ex.getMessage(), ex);
        }
    }

    static String refreshAccessToken(WalletState.Connection conn) throws Exception {
        var body = "grant_type=refresh_token"
            + "&client_id=admin-cli"
            + "&refresh_token=" + URLEncoder.encode(conn.refreshToken, StandardCharsets.UTF_8);

        var request = HttpRequest.newBuilder()
            .uri(URI.create(conn.serverUrl + "/realms/master/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Token refresh failed. Run 'oid4vp login' again.");
        }

        var json = MAPPER.readTree(response.body());
        conn.accessToken = json.get("access_token").asText();
        conn.refreshToken = json.get("refresh_token").asText();
        conn.expiresAt = Instant.now().plusSeconds(json.get("expires_in").asLong()).toString();
        return conn.accessToken;
    }

    static Keycloak adminClient() {
        var wallet = loadWallet();
        var conn = wallet.connection;

        if (Instant.parse(conn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
            try {
                refreshAccessToken(conn);
                saveWallet(wallet);
            } catch (Exception ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }

        return KeycloakBuilder.builder()
            .serverUrl(conn.serverUrl)
            .realm("master")
            .clientId("admin-cli")
            .authorization("Bearer " + conn.accessToken)
            .build();
    }

    @Command(name = "login", description = "Authenticate with Keycloak")
    static class Login implements Callable<Integer> {

        @Option(names = "--server", required = true, description = "Keycloak server URL")
        String serverUrl;

        @Option(names = "--user", defaultValue = "admin", description = "Admin username")
        String user;

        @Option(names = "--password", interactive = true, arity = "0..1", description = "Admin password (prompted if not given)")
        String password;

        @Override
        public Integer call() {
            if (password == null) {
                var console = System.console();
                if (console == null) {
                    System.err.println("No console available for password input. Use --password.");
                    return 1;
                }
                password = new String(console.readPassword("Password: "));
            }
            try {
                var body = "grant_type=password"
                    + "&client_id=admin-cli"
                    + "&username=" + URLEncoder.encode(user, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);

                var request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

                var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    System.err.println("Login failed: " + response.body());
                    return 1;
                }

                var json = MAPPER.readTree(response.body());

                var state = new WalletState();
                state.connection = new WalletState.Connection();
                state.connection.serverUrl = serverUrl;
                state.connection.accessToken = json.get("access_token").asText();
                state.connection.refreshToken = json.get("refresh_token").asText();
                state.connection.expiresAt = Instant.now().plusSeconds(json.get("expires_in").asLong()).toString();
                saveWallet(state);

                System.out.println("Logged in to " + serverUrl);
                System.out.println("Session stored in " + WALLET_FILE);
                return 0;
            } catch (Exception ex) {
                System.err.println("Login failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "realm", mixinStandardHelpOptions = true, description = "Manage realms",
        subcommands = { oid4vp.Realm.Create.class, oid4vp.Realm.Delete.class })
    static class Realm implements Runnable {

        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }

        @Command(name = "create", description = "Create an OID4VCI enabled realm")
        static class Create implements Callable<Integer> {

            @CommandLine.Parameters(index = "0", description = "Realm name")
            String realm;

            @Option(names = "--display-name", description = "Display name for the realm")
            String displayName;

            @Override
            public Integer call() {
                try (var kc = adminClient()) {
                    var rep = new RealmRepresentation();
                    rep.setRealm(realm);
                    rep.setDisplayName(displayName != null ? displayName : realm);
                    rep.setEnabled(true);
                    rep.setVerifiableCredentialsEnabled(true);
                    kc.realms().create(rep);

                    System.out.println("Created realm: " + realm);
                    return 0;
                } catch (Exception ex) {
                    System.err.println("Failed: " + ex.getMessage());
                    return 1;
                }
            }
        }

        @Command(name = "delete", description = "Delete a realm")
        static class Delete implements Callable<Integer> {

            @CommandLine.Parameters(index = "0", description = "Realm name")
            String realm;

            @Override
            public Integer call() {
                try (var kc = adminClient()) {
                    kc.realm(realm).remove();

                    System.out.println("Deleted realm: " + realm);
                    return 0;
                } catch (Exception ex) {
                    System.err.println("Failed: " + ex.getMessage());
                    return 1;
                }
            }
        }
    }
}

class WalletState {
    public WalletState.Connection connection;

    static class Connection {
        public String serverUrl;
        public String accessToken;
        public String refreshToken;
        public String expiresAt;
    }
}
