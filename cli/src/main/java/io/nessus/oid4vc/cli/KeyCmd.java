package io.nessus.oid4vc.cli;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "key", mixinStandardHelpOptions = true, description = "Manage keys",
    subcommands = { KeyCmd.Create.class })
class KeyCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "create", description = "Create a holder key")
    static class Create implements Callable<Integer> {

        @Option(names = "--algo", required = true, description = "Key algorithm (ES256)")
        String algo;

        @Option(names = "--name", description = "Key name (derived from algorithm if not given)")
        String name;

        @Option(names = "--user", required = true, description = "Target user")
        String user;

        @Override
        public Integer call() {
            return createHolderKey();
        }

        private Integer createHolderKey() {
            var realmName = resolveRealm(null);
            try {
                var ecKey = switch (algo) {
                    case "ES256" -> new ECKeyGenerator(Curve.P_256).generate();
                    default -> {
                        System.err.println("Unsupported holder key algorithm: " + algo);
                        yield null;
                    }
                };
                if (ecKey == null) return 1;

                var wallet = loadWallet();
                if (wallet.realms == null) wallet.realms = new HashMap<>();
                var realmState = wallet.realms.computeIfAbsent(realmName, k -> {
                    var rs = new WalletState.RealmState();
                    rs.users = new HashMap<>();
                    return rs;
                });
                if (realmState.users == null) realmState.users = new HashMap<>();
                var conn = realmState.users.computeIfAbsent(user, k -> new WalletState.Connection());
                if (conn.keys == null) conn.keys = new ArrayList<>();

                String kid;
                if (name != null) {
                    kid = name;
                    conn.keys.removeIf(k -> kid.equals(k.get("kid")));
                } else {
                    var prefix = algo.toLowerCase() + "#";
                    int max = conn.keys.stream()
                        .map(k -> (String) k.get("kid"))
                        .filter(k -> k != null && k.startsWith(prefix))
                        .mapToInt(k -> {
                            try { return Integer.parseInt(k.substring(prefix.length())); }
                            catch (NumberFormatException e) { return 0; }
                        })
                        .max().orElse(0);
                    kid = prefix + (max + 1);
                }
                ecKey = new com.nimbusds.jose.jwk.ECKey.Builder(ecKey).keyID(kid).build();
                conn.keys.add(ecKey.toJSONObject());
                conn.defaultKey = kid;
                saveWallet(wallet);

                System.out.println("Created " + algo + " holder key '" + kid + "' for " + user);
                return 0;
            } catch (Exception ex) {
                System.err.println("Failed to create holder key: " + ex.getMessage());
                return 1;
            }
        }

    }
}
