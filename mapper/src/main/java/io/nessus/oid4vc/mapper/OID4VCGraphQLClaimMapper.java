package io.nessus.oid4vc.mapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class OID4VCGraphQLClaimMapper extends OID4VCMapper {

    public static final String MAPPER_ID = "oid4vc-graphql-claim-mapper";
    public static final String GRAPHQL_ENDPOINT = "graphqlEndpoint";
    public static final String GRAPHQL_QUERY = "graphqlQuery";
    public static final String GRAPHQL_VARIABLE_MAPPING = "graphqlVariableMapping";
    public static final String RESPONSE_PATH = "responsePath";

    private static final Logger LOG = Logger.getLogger(OID4VCGraphQLClaimMapper.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty claimNameConfig = new ProviderConfigProperty();
        claimNameConfig.setName(CLAIM_NAME);
        claimNameConfig.setLabel("Claim Name");
        claimNameConfig.setHelpText("Name of the claim in the credential subject.");
        claimNameConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(claimNameConfig);

        ProviderConfigProperty endpointConfig = new ProviderConfigProperty();
        endpointConfig.setName(GRAPHQL_ENDPOINT);
        endpointConfig.setLabel("GraphQL Endpoint");
        endpointConfig.setHelpText("URL of the external GraphQL service.");
        endpointConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(endpointConfig);

        ProviderConfigProperty queryConfig = new ProviderConfigProperty();
        queryConfig.setName(GRAPHQL_QUERY);
        queryConfig.setLabel("GraphQL Query");
        queryConfig.setHelpText("GraphQL query template. Variables are resolved from the user session.");
        queryConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(queryConfig);

        ProviderConfigProperty variableMappingConfig = new ProviderConfigProperty();
        variableMappingConfig.setName(GRAPHQL_VARIABLE_MAPPING);
        variableMappingConfig.setLabel("Variable Mapping");
        variableMappingConfig.setHelpText("Maps GraphQL variables to user attributes (e.g. 'id=username,email=email').");
        variableMappingConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(variableMappingConfig);

        ProviderConfigProperty responsePathConfig = new ProviderConfigProperty();
        responsePathConfig.setName(RESPONSE_PATH);
        responsePathConfig.setLabel("Response Path");
        responsePathConfig.setHelpText("Dot-separated path into the GraphQL response data (e.g. 'booking').");
        responsePathConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(responsePathConfig);
    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void setClaim(VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {
    }

    @Override
    public void setClaim(Map<String, Object> claims, UserSessionModel userSessionModel) {
        var config = mapperModel.getConfig();
        var claimName = config.get(CLAIM_NAME);
        var endpoint = config.get(GRAPHQL_ENDPOINT);
        var query = config.get(GRAPHQL_QUERY);
        var variableMapping = config.get(GRAPHQL_VARIABLE_MAPPING);
        var responsePath = config.get(RESPONSE_PATH);

        if (endpoint == null || query == null) {
            LOG.warn("GraphQL mapper misconfigured: endpoint or query missing");
            return;
        }

        try {
            var variables = resolveVariables(userSessionModel, variableMapping);
            var responseData = executeQuery(endpoint, query, variables);

            var node = navigatePath(responseData, responsePath);
            if (node == null) {
                LOG.warnf("No data at response path '%s'", responsePath);
                return;
            }

            if (node.isObject()) {
                var it = node.fields();
                while (it.hasNext()) {
                    var field = it.next();
                    claims.put(field.getKey(), unwrap(field.getValue()));
                }
            } else {
                claims.put(claimName, unwrap(node));
            }
        } catch (Exception ex) {
            LOG.errorf(ex, "GraphQL claim mapper failed for endpoint '%s'", endpoint);
        }
    }

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        return new OID4VCGraphQLClaimMapper();
    }

    @Override
    public String getDisplayType() {
        return "GraphQL Claim Mapper";
    }

    @Override
    public String getHelpText() {
        return "Fetches credential claims from an external GraphQL endpoint.";
    }

    @Override
    public String getId() {
        return MAPPER_ID;
    }

    private JsonNode executeQuery(String endpoint, String query, Map<String, Object> variables) throws Exception {
        var requestBody = new HashMap<String, Object>();
        requestBody.put("query", query);
        if (!variables.isEmpty()) {
            requestBody.put("variables", variables);
        }
        var json = JSON.writeValueAsString(requestBody);

        LOG.debugf("GraphQL request to %s: %s", endpoint, json);

        var request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("GraphQL request failed: HTTP " + response.statusCode() + " " + response.body());
        }

        var responseJson = JSON.readTree(response.body());
        var errors = responseJson.get("errors");
        if (errors != null && errors.isArray() && !errors.isEmpty()) {
            throw new RuntimeException("GraphQL errors: " + errors);
        }

        return responseJson.get("data");
    }

    private JsonNode navigatePath(JsonNode data, String path) {
        if (data == null || path == null || path.isEmpty()) {
            return data;
        }
        var node = data;
        for (var segment : path.split("\\.")) {
            if (node == null) return null;
            node = node.get(segment);
        }
        return node;
    }

    private Map<String, Object> resolveVariables(UserSessionModel userSessionModel, String variableMapping) {
        if (variableMapping == null || variableMapping.isEmpty()) {
            return Collections.emptyMap();
        }
        var user = userSessionModel.getUser();
        var variables = new HashMap<String, Object>();
        for (var mapping : variableMapping.split(",")) {
            var parts = mapping.trim().split("=", 2);
            if (parts.length != 2) continue;
            var varName = parts[0].trim();
            var userAttr = parts[1].trim();
            var values = KeycloakModelUtils.resolveAttribute(user, userAttr, false);
            if (!values.isEmpty()) {
                variables.put(varName, values.iterator().next());
            }
        }
        return variables;
    }

    private Object unwrap(JsonNode node) {
        if (node.isTextual()) return node.asText();
        if (node.isNumber()) return node.numberValue();
        if (node.isBoolean()) return node.asBoolean();
        if (node.isNull()) return null;
        return node.toString();
    }
}
