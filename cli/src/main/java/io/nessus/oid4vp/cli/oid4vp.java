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
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import jakarta.ws.rs.WebApplicationException;
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
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "oid4vp", mixinStandardHelpOptions = true,
    subcommands = {
        oid4vp.Login.class,
        oid4vp.Key.class,
        oid4vp.Realm.class,
        oid4vp.User.class
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

    static String resolveRealm(String realmOption) {
        if (realmOption != null) return realmOption;
        var wallet = loadWallet();
        if (wallet.defaultRealm == null) {
            throw new IllegalStateException("No realm specified and no default realm set. Use --realm or 'oid4vp realm use <name>'.");
        }
        return wallet.defaultRealm;
    }

    static void saveWallet(WalletState state) {
        try {
            Files.createDirectories(WALLET_DIR);
            MAPPER.writeValue(WALLET_FILE.toFile(), state);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to save wallet: " + ex.getMessage(), ex);
        }
    }

    static String formatError(String context, Exception ex) {
        if (ex instanceof WebApplicationException wae) {
            var response = wae.getResponse();
            var status = response.getStatus();
            var body = "";
            try { body = response.readEntity(String.class); } catch (Exception ignored) {}
            return context + ": HTTP " + status + (body.isEmpty() ? "" : " - " + body);
        }
        return context + ": " + ex.getMessage();
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

    @Command(name = "key", mixinStandardHelpOptions = true, description = "Manage keys",
        subcommands = { oid4vp.Key.Create.class })
    static class Key implements Runnable {

        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }

        @Command(name = "create", description = "Create a key for a realm")
        static class Create implements Callable<Integer> {

            @Option(names = "--algo", required = true, description = "Key algorithm (ES256, ECDH-ES)")
            String algo;

            @Option(names = "--name", description = "Key name (derived from algorithm if not given)")
            String name;

            @Option(names = "--priority", defaultValue = "100", description = "Key priority (default: 100)")
            String priority;

            @Option(names = "--realm", description = "Realm name (defaults to current realm)")
            String realm;

            @Override
            public Integer call() {
                var realmName = resolveRealm(realm);
                try (var kc = adminClient()) {
                    var realmId = kc.realm(realmName).toRepresentation().getId();

                    var comp = new ComponentRepresentation();
                    comp.setProviderType("org.keycloak.keys.KeyProvider");
                    comp.setParentId(realmId);
                    var config = new MultivaluedHashMap<String, String>();
                    config.putSingle("priority", priority);
                    config.putSingle("active", "true");
                    config.putSingle("enabled", "true");

                    switch (algo) {
                        case "ES256" -> {
                            comp.setName(name != null ? name : "es256-vc-signing");
                            comp.setProviderId("ecdsa-generated");
                            config.putSingle("ecdsaEllipticCurveKey", "P-256");
                        }
                        case "ECDH-ES" -> {
                            comp.setName(name != null ? name : "ecdh-vc-encryption");
                            comp.setProviderId("ecdh-generated");
                            config.putSingle("ecdhAlgorithm", "ECDH-ES");
                        }
                        default -> {
                            System.err.println("Unsupported algorithm: " + algo);
                            return 1;
                        }
                    }

                    comp.setConfig(config);

                    try (var response = kc.realm(realmName).components().add(comp)) {
                        var location = response.getLocation();
                        var id = location != null ? location.getPath().replaceAll(".*/", "") : "unknown";
                        System.out.println("Created " + algo + " key: " + id);
                    }
                    return 0;
                } catch (Exception ex) {
                    System.err.println(formatError("Failed to create " + algo + " key in realm '" + realmName + "'", ex));
                    return 1;
                }
            }
        }
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
        subcommands = { oid4vp.Realm.Create.class, oid4vp.Realm.Delete.class, oid4vp.Realm.Use.class })
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

                    var wallet = loadWallet();
                    wallet.defaultRealm = realm;
                    saveWallet(wallet);

                    System.out.println("Created realm: " + realm);
                    System.out.println("Default realm set to: " + realm);
                    return 0;
                } catch (Exception ex) {
                    System.err.println(formatError("Failed to create realm '" + realm + "'", ex));
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

                    var wallet = loadWallet();
                    if (realm.equals(wallet.defaultRealm)) {
                        wallet.defaultRealm = null;
                        saveWallet(wallet);
                    }

                    System.out.println("Deleted realm: " + realm);
                    return 0;
                } catch (Exception ex) {
                    System.err.println(formatError("Failed to delete realm '" + realm + "'", ex));
                    return 1;
                }
            }
        }

        @Command(name = "use", description = "Set the default realm")
        static class Use implements Callable<Integer> {

            @CommandLine.Parameters(index = "0", description = "Realm name")
            String realm;

            @Override
            public Integer call() {
                var wallet = loadWallet();
                wallet.defaultRealm = realm;
                saveWallet(wallet);
                System.out.println("Default realm set to: " + realm);
                return 0;
            }
        }
    }

    @Command(name = "user", mixinStandardHelpOptions = true, description = "Manage users",
        subcommands = { oid4vp.User.Create.class })
    static class User implements Runnable {

        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }

        @Command(name = "create", description = "Create a user in a realm")
        static class Create implements Callable<Integer> {

            @CommandLine.Parameters(index = "0", description = "Username")
            String username;

            @Option(names = "--email", required = true, description = "User email")
            String email;

            @Option(names = "--first-name", required = true, description = "First name")
            String firstName;

            @Option(names = "--last-name", required = true, description = "Last name")
            String lastName;

            @Option(names = "--password", required = true, description = "User password")
            String password;

            @Option(names = "--realm", description = "Realm name (defaults to current realm)")
            String realm;

            @Option(names = "--role", description = "User role (e.g., issuer)")
            String role;

            @Override
            public Integer call() {
                var realmName = resolveRealm(realm);
                try (var kc = adminClient()) {
                    var userRep = new UserRepresentation();
                    userRep.setUsername(username);
                    userRep.setEmail(email);
                    userRep.setFirstName(firstName);
                    userRep.setLastName(lastName);
                    userRep.setEmailVerified(true);
                    userRep.setEnabled(true);

                    var cred = new CredentialRepresentation();
                    cred.setType(CredentialRepresentation.PASSWORD);
                    cred.setValue(password);
                    cred.setTemporary(false);
                    userRep.setCredentials(List.of(cred));

                    try (var response = kc.realm(realmName).users().create(userRep)) {
                        if (response.getStatus() != 201) {
                            System.err.println("Failed to create user: " + response.readEntity(String.class));
                            return 1;
                        }
                        var location = response.getLocation();
                        var userId = location != null ? location.getPath().replaceAll(".*/", "") : null;
                        System.out.println("Created user: " + username + " (" + userId + ")");

                        if ("issuer".equals(role) && userId != null) {
                            var roleName = "credential-offer-create";
                            try {
                                var roleRep = kc.realm(realmName).roles().get(roleName).toRepresentation();
                                kc.realm(realmName).users().get(userId).roles().realmLevel().add(List.of(roleRep));
                                System.out.println("Assigned role: " + roleName);
                            } catch (Exception rex) {
                                System.err.println(formatError("Failed to assign role '" + roleName + "' to user '" + username + "'", rex));
                                return 1;
                            }
                        }
                    }
                    return 0;
                } catch (Exception ex) {
                    System.err.println(formatError("Failed to create user '" + username + "' in realm '" + realmName + "'", ex));
                    return 1;
                }
            }
        }
    }
}

class WalletState {
    public WalletState.Connection connection;
    public String defaultRealm;

    static class Connection {
        public String serverUrl;
        public String accessToken;
        public String refreshToken;
        public String expiresAt;
    }
}
