package io.nessus.oid4vc.cli;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;


import java.util.ArrayList;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "key", mixinStandardHelpOptions = true, description = "Manage keys",
    subcommands = { KeyCmd.Create.class, KeyCmd.Delete.class })
class KeyCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "delete", description = "Delete a realm signing key by algorithm")
    static class Delete implements Callable<Integer> {

        @Option(names = "--algo", required = true, description = "Key algorithm (e.g. RS256)")
        String algo;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            try (var kc = adminClient()) {
                var keysMetadata = kc.realm(realmName).keys().getKeyMetadata();
                var componentId = keysMetadata.getKeys().stream()
                    .filter(k -> algo.equals(k.getAlgorithm()))
                    .map(k -> k.getProviderId())
                    .findFirst().orElse(null);
                if (componentId == null) {
                    System.err.println("No " + algo + " signing key found in realm '" + realmName + "'");
                    return 1;
                }
                kc.realm(realmName).components().component(componentId).remove();
                System.out.println("Deleted " + algo + " signing key: " + componentId);
                return 0;
            } catch (Exception ex) {
                System.err.println(formatError("Failed to delete " + algo + " key in realm '" + realmName + "'", ex));
                return 1;
            }
        }
    }

    @Command(name = "create", description = "Create a key")
    static class Create implements Callable<Integer> {

        @Option(names = "--algo", required = true, description = "Key algorithm (ES256, ECDH-ES)")
        String algo;

        @Option(names = "--name", description = "Key name (derived from algorithm if not given)")
        String name;

        @Option(names = "--priority", defaultValue = "100", description = "Key priority (default: 100)")
        String priority;

        @Option(names = "--realm", description = "Realm key: target realm")
        String realm;

        @Option(names = "--user", description = "Holder key: target user")
        String user;

        @Override
        public Integer call() {
            if (realm != null && user != null) {
                System.err.println("Options --realm and --user are mutually exclusive.");
                return 1;
            }
            if (realm == null && user == null) {
                System.err.println("Specify --realm for a realm key or --user for a holder key.");
                return 1;
            }
            return user != null ? createHolderKey() : createRealmKey();
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
                var conn = resolveWalletEntry(wallet, realmName, user);
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

        private Integer createRealmKey() {
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
