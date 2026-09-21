package io.nessus.oid4vp.cli;

import org.keycloak.representations.idm.RealmRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

import static io.nessus.oid4vp.cli.RootCmd.*;

@Command(name = "realm", mixinStandardHelpOptions = true, description = "Manage realms",
    subcommands = { RealmCmd.Create.class, RealmCmd.Delete.class, RealmCmd.Use.class })
class RealmCmd implements Runnable {

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
                var modified = false;
                if (realm.equals(wallet.defaultRealm)) {
                    wallet.defaultRealm = null;
                    modified = true;
                }
                if (wallet.realms != null && wallet.realms.remove(realm) != null) {
                    if (wallet.realms.isEmpty()) wallet.realms = null;
                    modified = true;
                }
                if (modified) saveWallet(wallet);

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
