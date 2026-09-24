package io.nessus.oid4vc.cli;

import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "scope", mixinStandardHelpOptions = true, description = "Manage client scopes",
    subcommands = { ClientScopeCmd.Create.class })
class ClientScopeCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "create", description = "Create an OID4VCI client scope with protocol mappers")
    static class Create implements Callable<Integer> {

        @CommandLine.Parameters(index = "0", description = "Client scope name (e.g. oid4vc_airline_ticket_jwt)")
        String name;

        @Option(names = "--credential-type", description = "Verifiable credential type (e.g. AirlineTicketCredential)")
        String credentialType;

        @Option(names = "--credential-description", description = "Human-readable credential description (e.g. 'Airline Ticket')")
        String credentialDescription;

        @Option(names = "--attr", description = "Scope attribute (key=value, repeatable)")
        List<String> attrs;

        @Option(names = "--mapper", description = "Claim mapper (claimName=userAttribute, repeatable)")
        List<String> mappers;

        @Option(names = "--graphql-endpoint", description = "GraphQL endpoint URL for external claim mapper")
        String graphqlEndpoint;

        @Option(names = "--graphql-query", description = "GraphQL query template")
        String graphqlQuery;

        @Option(names = "--graphql-variable-mapping", description = "GraphQL variable mapping (e.g. 'id=username')")
        String graphqlVariableMapping;

        @Option(names = "--graphql-response-path", description = "Dot-separated path into GraphQL response data")
        String graphqlResponsePath;

        @Option(names = "--graphql-claim-name", description = "Claim name for the GraphQL mapper")
        String graphqlClaimName;

        @Option(names = "--realm", description = "Realm name (defaults to current realm)")
        String realm;

        @Override
        public Integer call() {
            var realmName = resolveRealm(realm);
            try (var kc = adminClient()) {
                var rep = new ClientScopeRepresentation();
                rep.setName(name);
                rep.setProtocol("oid4vc");

                var attrMap = new LinkedHashMap<String, String>();
                attrMap.put("vc.credential_configuration_id", name);
                attrMap.put("vc.credential_signing_alg", "ES256");
                attrMap.put("vc.format", "jwt_vc_json");
                attrMap.put("vc.credential_build_config.token_jws_type", "vc+jwt");
                attrMap.put("vc.credential_build_config.hash_algorithm", "SHA-256");
                attrMap.put("vc.binding_required", "true");
                attrMap.put("vc.binding_required_proof_types", "jwt,attestation");
                attrMap.put("vc.cryptographic_binding_methods_supported", "jwk");
                attrMap.put("vc.expiry_in_seconds", "31536000");
                attrMap.put("vc.include_in_metadata", "true");
                attrMap.put("include.in.token.scope", "true");
                attrMap.put("display.on.consent.screen", "true");

                if (credentialType != null) {
                    attrMap.put("vc.verifiable_credential_type", credentialType);
                    attrMap.put("vc.supported_credential_types", credentialType);
                    attrMap.put("vc.credential_contexts", credentialType);
                }
                if (credentialDescription != null) {
                    attrMap.put("vc.display", "[{\"name\":\"" + credentialDescription + "\",\"locale\":\"en\"}]");
                }

                if (attrs != null) {
                    for (var attr : attrs) {
                        var idx = attr.indexOf('=');
                        if (idx <= 0) {
                            System.err.println("Invalid attribute (expected key=value): " + attr);
                            return 1;
                        }
                        attrMap.put(attr.substring(0, idx), attr.substring(idx + 1));
                    }
                }
                rep.setAttributes(attrMap);

                var protocolMappers = new ArrayList<ProtocolMapperRepresentation>();

                var subjectMapper = new ProtocolMapperRepresentation();
                subjectMapper.setName("subject-id");
                subjectMapper.setProtocol("oid4vc");
                subjectMapper.setProtocolMapper("oid4vc-subject-id-mapper");
                subjectMapper.setConfig(Map.of("claim.name", "id", "userAttribute", "username"));
                protocolMappers.add(subjectMapper);

                if (mappers != null) {
                    for (var mapper : mappers) {
                        var idx = mapper.indexOf('=');
                        if (idx <= 0) {
                            System.err.println("Invalid mapper (expected claimName=userAttribute): " + mapper);
                            return 1;
                        }
                        var claimName = mapper.substring(0, idx);
                        var userAttr = mapper.substring(idx + 1);

                        var pm = new ProtocolMapperRepresentation();
                        pm.setName(claimName);
                        pm.setProtocol("oid4vc");
                        pm.setProtocolMapper("oid4vc-user-attribute-mapper");
                        pm.setConfig(Map.of(
                            "claim.name", claimName,
                            "userAttribute", userAttr,
                            "aggregateAttributes", "false"
                        ));
                        protocolMappers.add(pm);
                    }
                }
                if (graphqlEndpoint != null) {
                    var gqlMapper = new ProtocolMapperRepresentation();
                    gqlMapper.setName(graphqlClaimName != null ? graphqlClaimName : "graphql-claims");
                    gqlMapper.setProtocol("oid4vc");
                    gqlMapper.setProtocolMapper("oid4vc-graphql-claim-mapper");
                    var gqlConfig = new LinkedHashMap<String, String>();
                    gqlConfig.put("claim.name", graphqlClaimName != null ? graphqlClaimName : "graphql-claims");
                    gqlConfig.put("graphqlEndpoint", graphqlEndpoint);
                    if (graphqlQuery != null) gqlConfig.put("graphqlQuery", graphqlQuery);
                    if (graphqlVariableMapping != null) gqlConfig.put("graphqlVariableMapping", graphqlVariableMapping);
                    if (graphqlResponsePath != null) gqlConfig.put("responsePath", graphqlResponsePath);
                    gqlMapper.setConfig(gqlConfig);
                    protocolMappers.add(gqlMapper);
                }

                rep.setProtocolMappers(protocolMappers);

                try (var response = kc.realm(realmName).clientScopes().create(rep)) {
                    if (response.getStatus() != 201) {
                        System.err.println("Failed to create client scope: " + response.readEntity(String.class));
                        return 1;
                    }
                    var location = response.getLocation();
                    var id = location != null ? location.getPath().replaceAll(".*/", "") : "unknown";
                    System.out.println("Created client scope: " + name + " (" + id + ")");
                }
                return 0;
            } catch (Exception ex) {
                System.err.println(formatError("Failed to create client scope '" + name + "' in realm '" + realmName + "'", ex));
                return 1;
            }
        }
    }
}
