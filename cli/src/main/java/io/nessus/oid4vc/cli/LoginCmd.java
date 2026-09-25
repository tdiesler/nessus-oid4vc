package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Playwright;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.awt.Desktop;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "login", mixinStandardHelpOptions = true, description = "Authenticate with Keycloak")
class LoginCmd implements Callable<Integer> {

    @Option(names = {"-b", "--browser"}, description = "Open system browser for login instead of headless Playwright")
    boolean browser;

    @Option(names = {"-c", "--client"}, description = "OAuth client ID (defaults to stored or admin-cli)")
    String clientId;

    @Option(names = {"-p", "--password"}, interactive = true, arity = "0..1", description = "Password (prompted if not given)")
    String password;

    @Option(names = {"-r", "--realm"}, description = "Realm for user login (omit for admin login)")
    String realm;

    @Option(names = {"-s", "--scope"}, description = "OAuth scope (e.g. 'openid oid4vc_natural_person_jwt')")
    String scope;

    @Option(names = "--server", description = "Keycloak server URL (defaults to stored URL)")
    String serverUrl;

    @Option(names = {"-u", "--user"}, description = "Username (default: admin, derived from token for --browser)")
    String user;

    @Override
    public Integer call() {
        if (browser && realm == null) {
            try {
                realm = resolveRealm(null);
            } catch (Exception e) {
                System.err.println("--browser requires --realm or a default realm (oid4vc config --realm <name>).");
                return 1;
            }
        }
        if (!browser && password == null) {
            var console = System.console();
            if (console == null) {
                System.err.println("No console available for password input. Use --password or --browser.");
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
        String oauthClientId = clientId;
        if (oauthClientId == null) {
            try {
                var wallet = loadWallet();
                if (wallet.realms != null) {
                    var rs = wallet.realms.get(tokenRealm);
                    if (rs != null) oauthClientId = rs.defaultClient;
                }
            } catch (Exception ignored) {}
        }
        if (oauthClientId == null && realm != null) {
            System.err.println("No client specified. Use --client or set a default (oid4vc config --client <name>).");
            return 1;
        }
        if (oauthClientId == null) oauthClientId = "admin-cli";

        if (user == null && !browser) user = "admin";

        try {
            JsonNode json;
            if (realm != null) {
                json = userLogin(serverUrl, tokenRealm, oauthClientId);
            } else {
                json = adminLogin(serverUrl, oauthClientId);
            }
            if (json == null) return 1;

            if (verbose) System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(json));

            var resolvedUser = user;
            if (resolvedUser == null) {
                var accessToken = json.get("access_token").asText();
                var claims = SignedJWT.parse(accessToken).getJWTClaimsSet();
                resolvedUser = claims.getStringClaim("preferred_username");
            }
            if (resolvedUser == null) {
                System.err.println("Cannot determine username. Use --user.");
                return 1;
            }

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
            var conn = realmState.users.computeIfAbsent(resolvedUser, k -> new WalletState.Connection());
            conn.clientId = oauthClientId;
            conn.accessToken = json.get("access_token").asText();
            conn.refreshToken = json.get("refresh_token").asText();
            conn.expiresAt = Instant.now().plusSeconds(json.get("expires_in").asLong()).toString();
            realmState.defaultUser = resolvedUser;

            if (realm == null) {
                System.out.println("Logged in to " + serverUrl);
            } else {
                System.out.println("Logged in as " + resolvedUser + " in realm " + realm);
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
        if (password == null) {
            System.err.println("Admin login requires --password.");
            return null;
        }
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
        if (browser) {
            return browserLogin(serverUrl, tokenRealm, clientId);
        }
        return playwrightLogin(serverUrl, tokenRealm, clientId);
    }

    private JsonNode browserLogin(String serverUrl, String tokenRealm, String clientId) throws Exception {
        var codeFuture = new CompletableFuture<String>();
        var callbackPort = 18888;
        var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", callbackPort), 0);
        var redirectUri = "http://localhost:" + callbackPort + "/callback";

        httpServer.createContext("/callback", exchange -> {
            var query = exchange.getRequestURI().getQuery();
            String code = null;
            String error = null;
            String errorDesc = null;
            if (query != null) {
                for (var param : query.split("&")) {
                    if (param.startsWith("code=")) {
                        code = URLDecoder.decode(param.substring(5), StandardCharsets.UTF_8);
                    } else if (param.startsWith("error=")) {
                        error = URLDecoder.decode(param.substring(6), StandardCharsets.UTF_8);
                    } else if (param.startsWith("error_description=")) {
                        errorDesc = URLDecoder.decode(param.substring(18), StandardCharsets.UTF_8);
                    }
                }
            }

            String response;
            if (code != null) {
                response = "<html><body><h2>Login successful</h2><p>You can close this tab.</p></body></html>";
            } else {
                var msg = error != null ? error : "unknown_error";
                if (errorDesc != null) msg += ": " + errorDesc;
                response = "<html><body><h2>Login failed</h2><p>" + msg + "</p></body></html>";
            }
            var bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();

            if (code != null) {
                codeFuture.complete(code);
            } else {
                var msg = error != null ? error : "No authorization code in callback";
                if (errorDesc != null) msg += ": " + errorDesc;
                codeFuture.completeExceptionally(new IllegalStateException(msg));
            }
        });
        httpServer.start();

        try {
            var authScope = scope != null ? scope : "openid profile";
            var authUrl = serverUrl + "/realms/" + tokenRealm + "/protocol/openid-connect/auth"
                    + "?response_type=code"
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&scope=" + URLEncoder.encode(authScope, StandardCharsets.UTF_8);

            if (verbose) System.out.println("GET " + authUrl);

            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                System.out.println("Opening browser for login...");
                Desktop.getDesktop().browse(URI.create(authUrl));
            } else {
                System.out.println("Open this URL in your browser to log in:");
                System.out.println(authUrl);
            }

            var code = codeFuture.get(120, TimeUnit.SECONDS);
            if (verbose) System.out.println("Auth code: " + code);

            return exchangeCodeForTokens(serverUrl, tokenRealm, clientId, code, redirectUri);
        } finally {
            httpServer.stop(0);
        }
    }

    private JsonNode playwrightLogin(String serverUrl, String tokenRealm, String clientId) throws Exception {
        if (password == null) {
            System.err.println("Headless login requires --password. Use --browser for interactive login.");
            return null;
        }
        var redirectUri = "urn:ietf:wg:oauth:2.0:oob";
        var authScope = scope != null ? scope : "openid";

        var authUrl = serverUrl + "/realms/" + tokenRealm + "/protocol/openid-connect/auth"
            + "?response_type=code"
            + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
            + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            + "&scope=" + URLEncoder.encode(authScope, StandardCharsets.UTF_8);

        if (verbose) System.out.println("GET " + authUrl);

        try (var pw = Playwright.create()) {
            var pwBrowser = pw.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
            var page = pwBrowser.newPage();

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
            pwBrowser.close();
            if (verbose) System.out.println("Auth code: " + code);

            return exchangeCodeForTokens(serverUrl, tokenRealm, clientId, code, redirectUri);
        }
    }

    private JsonNode exchangeCodeForTokens(String serverUrl, String tokenRealm, String clientId,
                                            String code, String redirectUri) throws Exception {
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
