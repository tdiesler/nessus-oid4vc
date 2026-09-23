package io.nessus.oid4vp.cli;

import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vp.cli.RootCmd.*;

@Command(name = "user", mixinStandardHelpOptions = true, description = "Manage users",
    subcommands = { UserCmd.Create.class })
class UserCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "create", description = "Create a user in a realm")
    static class Create implements Callable<Integer> {

        @CommandLine.Parameters(index = "0", description = "Username")
        String username;

        @Option(names = "--email", required = true, description = "User email")
        String email;

        @Option(names = "--first-name", required = true, description = "First name")
        String firstName;

        @Option(names = "--last-name", required = true, description = "Last name")
        String lastName;

        @Option(names = "--password", required = true, description = "User password")
        String password;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Option(names = "--role", description = "User role (e.g., issuer)")
        String role;

        @Option(names = "--vc-scope", description = "VC scope to assign (repeatable)")
        List<String> vcScopes;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            try (var kc = adminClient()) {
                var userRep = new UserRepresentation();
                userRep.setUsername(username);
                userRep.setEmail(email);
                userRep.setFirstName(firstName);
                userRep.setLastName(lastName);
                userRep.setEmailVerified(true);
                userRep.setEnabled(true);

                var cred = new CredentialRepresentation();
                cred.setType(CredentialRepresentation.PASSWORD);
                cred.setValue(password);
                cred.setTemporary(false);
                userRep.setCredentials(List.of(cred));

                try (var response = kc.realm(realmName).users().create(userRep)) {
                    if (response.getStatus() != 201) {
                        System.err.println("Failed to create user: " + response.readEntity(String.class));
                        return 1;
                    }
                    var location = response.getLocation();
                    var userId = location != null ? location.getPath().replaceAll(".*/", "") : null;
                    System.out.println("Created user: " + username + " (" + userId + ")");

                    if (userId != null) {
                        var wallet = loadWallet();
                        if (wallet.realms == null) wallet.realms = new LinkedHashMap<>();
                        var realmState = wallet.realms.computeIfAbsent(realmName, k -> new WalletState.RealmState());
                        if (realmState.users == null) realmState.users = new LinkedHashMap<>();
                        realmState.users.computeIfAbsent(username, k -> new WalletState.Connection());
                        saveWallet(wallet);
                    }

                    if ("issuer".equals(role) && userId != null) {
                        var roleName = "credential-offer-create";
                        try {
                            var roleRep = kc.realm(realmName).roles().get(roleName).toRepresentation();
                            kc.realm(realmName).users().get(userId).roles().realmLevel().add(List.of(roleRep));
                            System.out.println("- Assigned role: " + roleName);
                        } catch (Exception rex) {
                            System.err.println(formatError("Failed to assign role '" + roleName + "' to user '" + username + "'", rex));
                            return 1;
                        }
                    }

                    if (userId != null && vcScopes != null && !vcScopes.isEmpty()) {
                        var wallet = loadWallet();
                        var adminConn = resolveConnection(wallet, "master", null);
                        if (Instant.parse(adminConn.expiresAt).minusSeconds(30).isBefore(Instant.now())) {
                            refreshAccessToken(wallet.serverUrl, "master", adminConn);
                            saveWallet(wallet);
                        }
                        for (var vcScope : vcScopes) {
                            var body = MAPPER.writeValueAsString(Map.of("credentialScopeName", vcScope));
                            var vcResponse = httpPost(
                                wallet.serverUrl + "/admin/realms/" + realmName + "/users/" + userId + "/vc/credentials",
                                body, "application/json", adminConn.accessToken);
                            if (vcResponse.statusCode() / 100 == 2) {
                                System.out.println("- Assigned VC scope: " + vcScope);
                            } else {
                                System.err.println("Failed to assign VC scope '" + vcScope + "': " + vcResponse.body());
                                return 1;
                            }
                        }
                    }
                }
                return 0;
            } catch (Exception ex) {
                System.err.println(formatError("Failed to create user '" + username + "' in realm '" + realmName + "'", ex));
                return 1;
            }
        }
    }
}
