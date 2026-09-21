package io.nessus.oid4vp.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

import static io.nessus.oid4vp.cli.RootCmd.*;

@Command(name = "logout", mixinStandardHelpOptions = true, description = "Clear stored session")
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

        var targetRealm = realm != null ? realm : "master";
        if (state.realms == null || !state.realms.containsKey(targetRealm)) {
            System.err.println("No sessions for realm '" + targetRealm + "'.");
            return 1;
        }
        var realmState = state.realms.get(targetRealm);
        if (user != null) {
            if (realmState.users == null || !realmState.users.containsKey(user)) {
                System.err.println("No session for user '" + user + "' in realm '" + targetRealm + "'.");
                return 1;
            }
            realmState.users.remove(user);
            if (user.equals(realmState.defaultUser)) realmState.defaultUser = null;
            System.out.println("Logged out " + user + " from realm " + targetRealm);
        } else {
            realmState.users = null;
            realmState.defaultUser = null;
            System.out.println("Logged out all users from realm " + targetRealm);
        }
        if (realmState.users == null || realmState.users.isEmpty()) state.realms.remove(targetRealm);
        if (state.realms.isEmpty()) state.realms = null;
        saveWallet(state);
        return 0;
    }
}
