package io.nessus.oid4vc.cli;

import com.nimbusds.jwt.SignedJWT;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.time.Instant;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "show", mixinStandardHelpOptions = true, description = "Show wallet and server state",
    subcommands = {
        ShowCmd.ClientShow.class,
        ShowCmd.Keys.class,
        ShowCmd.RealmShow.class,
        ShowCmd.ScopeShow.class,
        ShowCmd.UserShow.class,
        ShowCmd.Vcs.class
    })
class ShowCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    private static String resolveAdminToken() throws Exception {
        var wallet = loadWallet();
        var conn = resolveConnection(wallet, "master", "admin");
        if (Instant.parse(conn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
            refreshAccessToken(wallet.serverUrl, "master", conn);
            saveWallet(wallet);
        }
        return conn.accessToken;
    }

    @Command(name = "client", description = "Show client details")
    static class ClientShow implements Callable<Integer> {

        @Option(names = "--name", description = "Client ID (defaults to realm's default client)")
        String name;

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            try {
                var realmName = resolveRealm(realm);
                var wallet = loadWallet();
                var token = resolveAdminToken();

                if (name == null) {
                    if (wallet.realms != null) {
                        var rs = wallet.realms.get(realmName);
                        if (rs != null) name = rs.defaultClient;
                    }
                }
                if (name == null) {
                    System.err.println("No client specified. Use --name or set a default (oid4vc config --client <name>).");
                    return 1;
                }

                var resp = httpGet(wallet.serverUrl + "/admin/realms/" + realmName
                        + "/clients?clientId=" + name, token);
                if (resp.statusCode() != 200) {
                    System.err.println("Failed: " + resp.body());
                    return 1;
                }
                var clients = MAPPER.readTree(resp.body());
                if (!clients.isArray() || clients.isEmpty()) {
                    System.err.println("Client '" + name + "' not found in realm '" + realmName + "'.");
                    return 1;
                }
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(clients.get(0)));
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "keys", description = "Show holder keys")
    static class Keys implements Callable<Integer> {

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = {"-u", "--user"}, description = "Username (defaults to realm's default user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            if (conn.keys == null || conn.keys.isEmpty()) {
                System.out.println("No keys stored.");
                return 0;
            }

            for (var key : conn.keys) {
                var kid = key.get("kid");
                var kty = key.get("kty");
                var crv = key.get("crv");
                var isDefault = kid != null && kid.equals(conn.defaultKey);
                System.out.printf("%-20s  kty=%-4s  crv=%-6s%s%n",
                        kid, kty, crv,
                        isDefault ? "  [default]" : "");
            }
            return 0;
        }
    }

    @Command(name = "realm", description = "Show realm details")
    static class RealmShow implements Callable<Integer> {

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            try {
                var realmName = resolveRealm(realm);
                var wallet = loadWallet();
                var token = resolveAdminToken();

                var resp = httpGet(wallet.serverUrl + "/admin/realms/" + realmName, token);
                if (resp.statusCode() != 200) {
                    System.err.println("Failed: " + resp.body());
                    return 1;
                }
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(MAPPER.readTree(resp.body())));
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "scope", description = "Show client scope details")
    static class ScopeShow implements Callable<Integer> {

        @Option(names = "--name", required = true, description = "Scope name")
        String name;

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            try {
                var realmName = resolveRealm(realm);
                var wallet = loadWallet();
                var token = resolveAdminToken();

                var resp = httpGet(wallet.serverUrl + "/admin/realms/" + realmName
                        + "/client-scopes", token);
                if (resp.statusCode() != 200) {
                    System.err.println("Failed: " + resp.body());
                    return 1;
                }
                var scopes = MAPPER.readTree(resp.body());
                for (var scope : scopes) {
                    if (name.equals(scope.get("name").asText())) {
                        System.out.println(MAPPER.writerWithDefaultPrettyPrinter()
                                .writeValueAsString(scope));
                        return 0;
                    }
                }
                System.err.println("Scope '" + name + "' not found in realm '" + realmName + "'.");
                return 1;
            } catch (Exception ex) {
                System.err.println("Failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "user", description = "Show user details")
    static class UserShow implements Callable<Integer> {

        @Option(names = {"-u", "--user"}, description = "Username (defaults to realm's default user)")
        String user;

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            try {
                var realmName = resolveRealm(realm);
                var wallet = loadWallet();
                var token = resolveAdminToken();

                var resolvedUser = user;
                if (resolvedUser == null && wallet.realms != null) {
                    var rs = wallet.realms.get(realmName);
                    if (rs != null) resolvedUser = rs.defaultUser;
                }
                if (resolvedUser == null) {
                    System.err.println("No user specified. Use --user.");
                    return 1;
                }

                var resp = httpGet(wallet.serverUrl + "/admin/realms/" + realmName
                        + "/users?username=" + resolvedUser + "&exact=true", token);
                if (resp.statusCode() != 200) {
                    System.err.println("Failed: " + resp.body());
                    return 1;
                }
                var users = MAPPER.readTree(resp.body());
                if (!users.isArray() || users.isEmpty()) {
                    System.err.println("User '" + resolvedUser + "' not found in realm '" + realmName + "'.");
                    return 1;
                }
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(users.get(0)));
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed: " + ex.getMessage());
                return 1;
            }
        }
    }

    @Command(name = "vcs", description = "Show stored verifiable credentials")
    static class Vcs implements Callable<Integer> {

        @Option(names = "--credential-id", description = "Credential key or index number (omit to list all)")
        String credId;

        @Option(names = {"-r", "--realm"}, description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = {"-u", "--user"}, description = "Username (defaults to realm's default user)")
        String user;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            var wallet = loadWallet();
            var conn = resolveConnection(wallet, realmName, user);

            if (conn.credentials == null || conn.credentials.isEmpty()) {
                System.out.println("No credentials stored.");
                return 0;
            }

            if (credId != null) {
                return showCredential(conn);
            }
            return listCredentials(conn);
        }

        private Integer listCredentials(WalletState.Connection conn) {
            var keys = conn.credentials.keySet().toArray(new String[0]);
            for (int i = 0; i < keys.length; i++) {
                try {
                    var jwt = SignedJWT.parse(conn.credentials.get(keys[i]));
                    var claims = jwt.getJWTClaimsSet();
                    var vc = claims.getJSONObjectClaim("vc");

                    var type = vc != null ? vc.get("type") : null;
                    var exp = claims.getExpirationTime();
                    var expired = exp != null && exp.toInstant().isBefore(Instant.now());

                    System.out.printf("  %d  %-40s  type=%s%s%n",
                            i + 1,
                            keys[i],
                            type != null ? type : "unknown",
                            expired ? "  [EXPIRED]" : "");
                } catch (Exception ex) {
                    System.out.printf("  %d  %-40s  (unable to parse)%n", i + 1, keys[i]);
                }
            }
            return 0;
        }

        private Integer showCredential(WalletState.Connection conn) {
            var resolvedKey = credId;
            try {
                int idx = Integer.parseInt(credId);
                var keys = conn.credentials.keySet().toArray(new String[0]);
                if (idx < 1 || idx > keys.length) {
                    System.err.println("Index " + idx + " out of range (1-" + keys.length + ").");
                    return 1;
                }
                resolvedKey = keys[idx - 1];
            } catch (NumberFormatException ignored) {}

            if (!conn.credentials.containsKey(resolvedKey)) {
                System.err.println("No credential '" + resolvedKey + "'. Run 'oid4vc show vcs' to list.");
                return 1;
            }

            try {
                var jwt = SignedJWT.parse(conn.credentials.get(resolvedKey));
                var payload = MAPPER.readTree(jwt.getPayload().toString());
                System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(payload));
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed to decode credential: " + ex.getMessage());
                return 1;
            }
        }
    }
}
