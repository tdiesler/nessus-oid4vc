package io.nessus.oid4vc.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "config", mixinStandardHelpOptions = true, description = "Configure wallet defaults")
class ConfigCmd implements Callable<Integer> {

    @Option(names = "--realm", description = "Default realm")
    String realm;

    @Option(names = "--server", description = "Keycloak server URL")
    String serverUrl;

    @Override
    public Integer call() {
        if (realm == null && serverUrl == null) {
            try {
                var state = loadWallet();
                if (state.serverUrl != null) System.out.println("server: " + state.serverUrl);
                if (state.defaultRealm != null) System.out.println("realm: " + state.defaultRealm);
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
        saveWallet(state);

        return 0;
    }
}
