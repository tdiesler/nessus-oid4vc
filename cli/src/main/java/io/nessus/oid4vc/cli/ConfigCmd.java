package io.nessus.oid4vc.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.HashMap;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "config", mixinStandardHelpOptions = true, description = "Configure wallet defaults")
class ConfigCmd implements Callable<Integer> {

    @Option(names = "--client", description = "Default OAuth client ID for the realm")
    String clientId;

    @Option(names = "--realm", description = "Default realm")
    String realm;

    @Option(names = "--server", description = "Keycloak server URL")
    String serverUrl;

    @Override
    public Integer call() {
        if (clientId == null && realm == null && serverUrl == null) {
            try {
                var state = loadWallet();
                if (state.serverUrl != null) System.out.println("server: " + state.serverUrl);
                if (state.defaultRealm != null) {
                    System.out.println("realm: " + state.defaultRealm);
                    if (state.realms != null) {
                        var rs = state.realms.get(state.defaultRealm);
                        if (rs != null && rs.defaultClient != null) {
                            System.out.println("client: " + rs.defaultClient);
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("No configuration set.");
            }
            return 0;
        }

        WalletState state;
        try {
            state = loadWallet();
        } catch (Exception e) {
            state = new WalletState();
        }

        if (serverUrl != null) state.serverUrl = serverUrl;
        if (realm != null) state.defaultRealm = realm;

        if (clientId != null) {
            var realmName = state.defaultRealm;
            if (realmName == null) {
                System.err.println("No realm set. Use --realm first.");
                return 1;
            }
            if (state.realms == null) state.realms = new HashMap<>();
            var rs = state.realms.computeIfAbsent(realmName, k -> {
                var r = new WalletState.RealmState();
                r.users = new HashMap<>();
                return r;
            });
            rs.defaultClient = clientId;
        }

        saveWallet(state);
        return 0;
    }
}
