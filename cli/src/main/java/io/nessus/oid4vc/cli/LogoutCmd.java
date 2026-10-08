package io.nessus.oid4vc.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "logout", mixinStandardHelpOptions = true, description = "End Keycloak session and clear stored tokens")
class LogoutCmd implements Callable<Integer> {

    @Option(names = "--realm", description = "Realm of the user session to clear")
    String realm;

    @Option(names = "--user", description = "Username of the session to clear")
    String user;

    @Override
    public Integer call() {
        WalletState state;
        try {
            state = loadWallet();
        } catch (Exception e) {
            System.out.println("No active session.");
            return 0;
        }

        var targetRealm = resolveRealm(realm);
        if (state.realms == null || !state.realms.containsKey(targetRealm)) {
            System.err.println("No sessions for realm '" + targetRealm + "'.");
            return 1;
        }
        var realmState = state.realms.get(targetRealm);
        if (realmState.users == null || realmState.users.isEmpty()) {
            System.err.println("No sessions for realm '" + targetRealm + "'.");
            return 1;
        }

        var usersToLogout = new ArrayList<String>();
        if (user != null) {
            if (!realmState.users.containsKey(user)) {
                System.err.println("No session for user '" + user + "' in realm '" + targetRealm + "'.");
                return 1;
            }
            usersToLogout.add(user);
        } else {
            usersToLogout.addAll(realmState.users.keySet());
        }

        for (var username : usersToLogout) {
            var conn = realmState.users.get(username);
            endKeycloakSession(state.serverUrl, targetRealm, conn);
            conn.accessToken = null;
            conn.refreshToken = null;
            conn.expiresAt = null;
            System.out.println("Logged out " + username + " from realm " + targetRealm);
        }

        saveWallet(state);
        return 0;
    }

    private void endKeycloakSession(String serverUrl, String realm, WalletState.Connection conn) {
        if (conn.refreshToken == null || conn.clientId == null) return;
        try {
            var body = "client_id=" + URLEncoder.encode(conn.clientId, StandardCharsets.UTF_8)
                + "&refresh_token=" + URLEncoder.encode(conn.refreshToken, StandardCharsets.UTF_8);
            httpPost(serverUrl + "/realms/" + realm + "/protocol/openid-connect/logout",
                body, "application/x-www-form-urlencoded", null);
        } catch (Exception ex) {
            if (verbose) System.err.println("KC logout failed: " + ex.getMessage());
        }
    }
}
