///usr/bin/env jbang "$0" "$@" ; exit $?

//DEPS info.picocli:picocli:4.7.6
//DEPS com.fasterxml.jackson.core:jackson-databind:2.17.0
//DEPS com.nimbusds:nimbus-jose-jwt:9.37.3
//DEPS com.microsoft.playwright:playwright:1.44.0

//SOURCES ConfigCmd.java
//SOURCES DemoCmd.java
//SOURCES KeyCmd.java
//SOURCES LoginCmd.java
//SOURCES LogoutCmd.java
//SOURCES VcCmd.java
//SOURCES WalletState.java

package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

@Command(name = "oid4vc", mixinStandardHelpOptions = true,
    subcommands = {
        ConfigCmd.class,
        DemoCmd.class,
        KeyCmd.class,
        LoginCmd.class,
        LogoutCmd.class,
        VcCmd.class
    })
public class RootCmd implements Runnable {

    @Option(names = "--verbose", scope = CommandLine.ScopeType.INHERIT, description = "Show request/response details")
    static boolean verbose;

    static final Path WALLET_DIR = Path.of(".config");
    static final Path WALLET_FILE = WALLET_DIR.resolve("wallet.json");
    static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .enable(SerializationFeature.INDENT_OUTPUT);
    static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] args) {
        int exitCode = new CommandLine(new RootCmd()).execute(args);
        if (verbose) System.out.println();
        System.exit(exitCode);
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    static WalletState.Connection resolveWalletEntry(WalletState wallet, String realm, String user) {
        if (wallet.realms == null || !wallet.realms.containsKey(realm)) {
            throw new IllegalStateException("No wallet entry for realm '" + realm + "'. Run 'oid4vc user create' first.");
        }
        var realmState = wallet.realms.get(realm);
        if (realmState.users == null || !realmState.users.containsKey(user)) {
            throw new IllegalStateException("No wallet entry for user '" + user + "' in realm '" + realm + "'. Run 'oid4vc user create' first.");
        }
        return realmState.users.get(user);
    }

    static WalletState.Connection resolveConnection(WalletState wallet, String realm, String user) {
        if (wallet.realms == null || !wallet.realms.containsKey(realm)) {
            throw new IllegalStateException("No sessions for realm '" + realm + "'. Run 'oid4vc login' first.");
        }
        var realmState = wallet.realms.get(realm);
        if (realmState.users == null || realmState.users.isEmpty()) {
            throw new IllegalStateException("No sessions for realm '" + realm + "'.");
        }
        if (user != null) {
            var conn = realmState.users.get(user);
            if (conn == null) {
                throw new IllegalStateException("No session for user '" + user + "' in realm '" + realm + "'.");
            }
            return conn;
        }
        var resolvedUser = realmState.defaultUser != null ? realmState.defaultUser : null;
        if (resolvedUser != null && realmState.users.containsKey(resolvedUser)) {
            return realmState.users.get(resolvedUser);
        }
        return realmState.users.values().iterator().next();
    }

    static HttpResponse<String> httpPost(String url, String body, String contentType, String bearerToken) throws Exception {
        var builder = HttpRequest.newBuilder().uri(URI.create(url))
            .header("Content-Type", contentType);
        if (bearerToken != null) builder.header("Authorization", "Bearer " + bearerToken);
        if (body != null) builder.POST(HttpRequest.BodyPublishers.ofString(body));
        else builder.POST(HttpRequest.BodyPublishers.noBody());
        if (verbose) {
            System.out.println("POST " + url);
            if (body != null) System.out.println(body);
        }
        var response = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (verbose) System.out.println("Response: " + response.statusCode());
        return response;
    }

    static WalletState loadWallet() {
        if (!Files.exists(WALLET_FILE)) {
            throw new IllegalStateException("Not logged in. Run 'oid4vc login' first.");
        }
        try {
            return MAPPER.readValue(WALLET_FILE.toFile(), WalletState.class);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to read wallet: " + ex.getMessage(), ex);
        }
    }

    static String refreshAccessToken(String serverUrl, String realm, WalletState.Connection conn) throws Exception {
        var oauthClientId = conn.clientId != null ? conn.clientId : "admin-cli";
        var body = "grant_type=refresh_token"
            + "&client_id=" + URLEncoder.encode(oauthClientId, StandardCharsets.UTF_8)
            + "&refresh_token=" + URLEncoder.encode(conn.refreshToken, StandardCharsets.UTF_8);

        var response = httpPost(serverUrl + "/realms/" + realm + "/protocol/openid-connect/token",
            body, "application/x-www-form-urlencoded", null);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Token refresh failed. Run 'oid4vc login' again.");
        }

        var json = MAPPER.readTree(response.body());
        conn.accessToken = json.get("access_token").asText();
        conn.refreshToken = json.get("refresh_token").asText();
        conn.expiresAt = Instant.now().plusSeconds(json.get("expires_in").asLong()).toString();
        return conn.accessToken;
    }

    static String resolveRealm(String realmOption) {
        if (realmOption != null) return realmOption;
        var wallet = loadWallet();
        if (wallet.defaultRealm == null) {
            throw new IllegalStateException("No realm specified and no default realm set. Use --realm or 'oid4vc realm use <name>'.");
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
}
