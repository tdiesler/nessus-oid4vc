package io.nessus.oid4vp.cli;

import org.keycloak.representations.idm.ClientRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vp.cli.RootCmd.*;

@Command(name = "client", mixinStandardHelpOptions = true, description = "Manage clients",
    subcommands = { ClientCmd.Create.class })
class ClientCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "create", description = "Create an OID4VCI Client")
    static class Create implements Callable<Integer> {

        @CommandLine.Parameters(index = "0", description = "Client ID")
        String clientId;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            try (var kc = adminClient()) {
                var clientRep = new ClientRepresentation();
                clientRep.setClientId(clientId);
                clientRep.setName("OID4VCI Client");
                clientRep.setEnabled(true);
                clientRep.setProtocol("openid-connect");
                clientRep.setPublicClient(true);
                clientRep.setDirectAccessGrantsEnabled(true);
                clientRep.setRedirectUris(List.of("urn:ietf:wg:oauth:2.0:oob", "https://oauth.pstmn.io/v1/callback"));
                clientRep.setDefaultClientScopes(List.of("basic", "profile"));
                clientRep.setOptionalClientScopes(List.of(
                    "oid4vc_natural_person_sd",
                    "oid4vc_natural_person_jwt"
                ));
                clientRep.setAttributes(Map.of("oid4vci.enabled", "true"));

                try (var response = kc.realm(realmName).clients().create(clientRep)) {
                    if (response.getStatus() != 201) {
                        System.err.println("Failed to create client: " + response.readEntity(String.class));
                        return 1;
                    }
                    var location = response.getLocation();
                    var id = location != null ? location.getPath().replaceAll(".*/", "") : "unknown";
                    System.out.println("Created client: " + clientId + " (" + id + ")");
                }
                return 0;
            } catch (Exception ex) {
                System.err.println(formatError("Failed to create client '" + clientId + "' in realm '" + realmName + "'", ex));
                return 1;
            }
        }
    }
}
