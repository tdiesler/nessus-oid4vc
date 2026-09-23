package io.nessus.oid4vp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Playwright;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.Callable;

import static io.nessus.oid4vp.cli.RootCmd.*;

@Command(name = "login", mixinStandardHelpOptions = true, description = "Authenticate with Keycloak")
class LoginCmd implements Callable<Integer> {

    @Option(names = "--client-id", description = "OAuth client ID (default: admin-cli)")
    String clientId;

    @Option(names = "--password", interactive = true, arity = "0..1", description = "Password (prompted if not given)")
    String password;

    @Option(names = "--realm", description = "Realm for user login (omit for admin login)")
    String realm;

    @Option(names = "--scope", description = "OAuth scope (e.g. 'openid oid4vc_natural_person_jwt')")
    String scope;

    @Option(names = "--server", description = "Keycloak server URL (defaults to stored URL)")
    String serverUrl;

    @Option(names = "--user", defaultValue = "admin", description = "Username")
    String user;

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

        if (serverUrl == null) {
            try {
                serverUrl = loadWallet().serverUrl;
            } catch (Exception e) {
                System.err.println("No server URL. Use --server or login as admin first.");
                return 1;
            }
            if (serverUrl == null) {
                System.err.println("No server URL. Use --server or login as admin first.");
                return 1;
            }
        }

        var tokenRealm = realm != null ? realm : "master";
        var oauthClientId = clientId != null ? clientId : "admin-cli";

        try {
            JsonNode json;
            if (realm != null) {
                json = userLogin(serverUrl, tokenRealm, oauthClientId);
            } else {
                json = adminLogin(serverUrl, oauthClientId);
            }
            if (json == null) return 1;

            WalletState state;
            try {
                state = loadWallet();
            } catch (Exception e) {
                state = new WalletState();
            }

            state.serverUrl = serverUrl;
            if (state.realms == null) state.realms = new HashMap<>();
            var realmState = state.realms.computeIfAbsent(tokenRealm, k -> {
                var rs = new WalletState.RealmState();
                rs.users = new HashMap<>();
                return rs;
            });
            if (realmState.users == null) realmState.users = new HashMap<>();
            var conn = realmState.users.computeIfAbsent(user, k -> new WalletState.Connection());
            conn.clientId = oauthClientId;
            conn.accessToken = json.get("access_token").asText();
            conn.refreshToken = json.get("refresh_token").asText();
            conn.expiresAt = Instant.now().plusSeconds(json.get("expires_in").asLong()).toString();
            realmState.defaultUser = user;

            if (realm == null) {
                System.out.println("Logged in to " + serverUrl);
            } else {
                System.out.println("Logged in as " + user + " in realm " + realm);
            }
            saveWallet(state);
            return 0;
        } catch (Exception ex) {
            var msg = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
            System.err.println("Login failed: " + msg);
            return 1;
        }
    }

    private JsonNode adminLogin(String serverUrl, String clientId) throws Exception {
        var body = "grant_type=password"
            + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
            + "&username=" + URLEncoder.encode(user, StandardCharsets.UTF_8)
            + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);

        var response = httpPost(serverUrl + "/realms/master/protocol/openid-connect/token",
            body, "application/x-www-form-urlencoded", null);
        if (response.statusCode() != 200) {
            System.err.println("Login failed: " + response.body());
            return null;
        }
        return MAPPER.readTree(response.body());
    }

    private JsonNode userLogin(String serverUrl, String tokenRealm, String clientId) throws Exception {
        var redirectUri = "urn:ietf:wg:oauth:2.0:oob";
        var authScope = scope != null ? scope : "openid";

        var authUrl = serverUrl + "/realms/" + tokenRealm + "/protocol/openid-connect/auth"
            + "?response_type=code"
            + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&scope=" + URLEncoder.encode(authScope, StandardCharsets.UTF_8);

        if (verbose) System.out.println("GET " + authUrl);

        try (var pw = Playwright.create()) {
            var browser = pw.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
            var page = browser.newPage();

            page.navigate(authUrl);
            page.waitForLoadState();
            var loginForm = page.querySelector("#username");
            if (loginForm == null) {
                System.err.println("Login form not found. Page title: " + page.title());
                System.err.println("URL: " + page.url());
                System.err.println(page.content().substring(0, Math.min(2000, page.content().length())));
                return null;
            }
            page.fill("#username", user);
            page.fill("#password", password);
            page.click("#kc-login");

            page.waitForURL("**/oauth/oob**");
            var oobUrl = page.url();
            if (verbose) System.out.println("OOB redirect: " + oobUrl);

            String code = null;
            var query = oobUrl.substring(oobUrl.indexOf('?') + 1);
            for (var param : query.split("&")) {
                if (param.startsWith("code=")) {
                    code = URLDecoder.decode(param.substring(5), StandardCharsets.UTF_8);
                }
            }
            if (code == null) {
                System.err.println("No auth code in OOB redirect: " + oobUrl);
                return null;
            }
            browser.close();
            if (verbose) System.out.println("Auth code: " + code);

            var tokenBody = "grant_type=authorization_code"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

            var tokenResponse = httpPost(serverUrl + "/realms/" + tokenRealm + "/protocol/openid-connect/token",
                tokenBody, "application/x-www-form-urlencoded", null);
            if (tokenResponse.statusCode() != 200) {
                System.err.println("Token exchange failed (" + tokenResponse.statusCode() + "): " + tokenResponse.body());
                return null;
            }
            return MAPPER.readTree(tokenResponse.body());
        }
    }
}
