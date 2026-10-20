package io.nessus.oid4vc.demo.gate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.nessus.oid4vc.dcql.DcqlEvaluator;
import io.nessus.oid4vc.dcql.DcqlQuery;
import io.nessus.oid4vc.dcql.JacksonSupport;
import io.nessus.oid4vc.dcql.SdJwtParser;
import io.nessus.oid4vc.dcql.VcJwtVerifier;
import io.nessus.oid4vc.dcql.VcVerificationException;
import io.nessus.oid4vc.dcql.VpJwtVerifier;
import io.nessus.oid4vc.dcql.VpToken;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;

import java.util.LinkedHashMap;
import java.util.UUID;

public class GateRoutes extends RouteBuilder {

    static final String DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "boarding_pass_jwt",
                  "format": "jwt_vc_json",
                  "claims": [
                    {"path": ["vc", "credentialSubject", "passengerName"]},
                    {"path": ["vc", "credentialSubject", "flightNumber"]},
                    {"path": ["vc", "credentialSubject", "seat"]},
                    {"path": ["vc", "credentialSubject", "boardingGroup"]},
                    {"path": ["vc", "credentialSubject", "departureDateTime"]},
                    {"path": ["vc", "credentialSubject", "gate"]}
                  ]
                },
                {
                  "id": "boarding_pass_sd",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"path": ["passengerName"]},
                    {"path": ["flightNumber"]},
                    {"path": ["seat"]},
                    {"path": ["boardingGroup"]},
                    {"path": ["departureDateTime"]},
                    {"path": ["gate"]}
                  ]
                },
                {
                  "id": "natural_person_jwt",
                  "format": "jwt_vc_json",
                  "claims": [
                    {"path": ["vc", "credentialSubject", "firstName"]},
                    {"path": ["vc", "credentialSubject", "familyName"]}
                  ]
                },
                {
                  "id": "natural_person_sd",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"path": ["firstName"]},
                    {"path": ["familyName"]}
                  ]
                }
              ],
              "credential_sets": [
                {"options": [["boarding_pass_jwt"], ["boarding_pass_sd"]]},
                {"options": [["natural_person_jwt"], ["natural_person_sd"]]}
              ]
            }
            """;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper DCQL_MAPPER = JacksonSupport.getMapper();

    private final DcqlEvaluator evaluator = new DcqlEvaluator();
    final VcJwtVerifier jwtVerifier = new VcJwtVerifier();
    final VpJwtVerifier vpJwtVerifier = new VpJwtVerifier();
    private final int port;

    public GateRoutes(int port) {
        this.port = port;
        var keycloakUrl = System.getenv("KEYCLOAK_URL");
        if (keycloakUrl != null) jwtVerifier.setIssuerBaseUrl(keycloakUrl);
    }

    @Override
    public void configure() {

        from("undertow:http://0.0.0.0:" + port + "/gate?httpMethodRestrict=POST")
                .process(this::handleGateRequest);

        from("undertow:http://0.0.0.0:" + port + "/gate/response?httpMethodRestrict=POST")
                .process(this::handleGateResponse);
    }

    private void handleGateRequest(Exchange exchange) throws Exception {
        var nonce = UUID.randomUUID().toString();
        var requestUrl = exchange.getIn().getHeader("CamelHttpUrl", String.class);
        var responseUri = requestUrl + "/response";

        var response = new LinkedHashMap<String, Object>();
        response.put("dcql_query", JSON.readTree(DCQL_QUERY));
        response.put("nonce", nonce);
        response.put("response_uri", responseUri);

        exchange.getIn().setBody(JSON.writeValueAsString(response));
        exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
    }

    private void handleGateResponse(Exchange exchange) throws Exception {
        var body = exchange.getIn().getBody(String.class);
        var request = JSON.readTree(body);

        var vpTokenNode = request.get("vp_token");
        if (vpTokenNode == null) {
            exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 400);
            exchange.getIn().setBody("{\"status\":\"denied\",\"reason\":\"vp_token required\"}");
            exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
            return;
        }

        var vpTokenBuilder = VpToken.builder();
        var fields = vpTokenNode.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            var credId = entry.getKey();
            var vpJwtStr = entry.getValue().asText();
            try {
                var vpSignedJwt = SignedJWT.parse(vpJwtStr);
                var vcJwtStr = vpJwtVerifier.verifyAndExtract(vpSignedJwt);
                JsonNode claims;
                if (SdJwtParser.isSdJwt(vcJwtStr)) {
                    var sdJwt = SdJwtParser.parse(vcJwtStr);
                    var issuerJwt = SignedJWT.parse(sdJwt.issuerJwt());
                    jwtVerifier.verify(issuerJwt);
                    claims = SdJwtParser.discloseClaims(vcJwtStr);
                } else {
                    var vcSignedJwt = SignedJWT.parse(vcJwtStr);
                    jwtVerifier.verify(vcSignedJwt);
                    claims = JSON.readTree(vcSignedJwt.getPayload().toString());
                }
                vpTokenBuilder.addCredential(credId, claims);
            } catch (VcVerificationException ex) {
                exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 400);
                exchange.getIn().setBody("{\"status\":\"denied\",\"reason\":\"" + ex.getMessage().replace("\"", "'") + "\"}");
                exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                return;
            }
        }
        var vpToken = vpTokenBuilder.build();

        var query = DCQL_MAPPER.readValue(DCQL_QUERY, DcqlQuery.class);
        var result = evaluator.evaluate(vpToken, query);

        if (!result.satisfied()) {
            var response = new LinkedHashMap<String, Object>();
            response.put("status", "denied");
            response.put("reason", "credential verification failed");
            response.put("details", result);
            exchange.getIn().setBody(JSON.writeValueAsString(response));
            exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
            return;
        }

        var bpCreds = vpToken.getCredentials("boarding_pass_jwt");
        boolean bpSd = bpCreds.isEmpty();
        if (bpSd) bpCreds = vpToken.getCredentials("boarding_pass_sd");
        var bpClaims = bpCreds.getFirst();
        // The GraphQL claim mapper spreads the boarding pass object's fields into individual top-level
        // claims (not nested under claim.name; see keycloak/keycloak#53956), directly under credentialSubject.
        var bp = bpSd ? bpClaims : bpClaims.at("/vc/credentialSubject");

        var personCreds = vpToken.getCredentials("natural_person_jwt");
        boolean personSd = personCreds.isEmpty();
        if (personSd) personCreds = vpToken.getCredentials("natural_person_sd");
        var personClaims = personCreds.getFirst();
        var firstName = personSd
                ? personClaims.path("firstName").asText("")
                : personClaims.at("/vc/credentialSubject/firstName").asText("");
        var familyName = personSd
                ? personClaims.path("familyName").asText("")
                : personClaims.at("/vc/credentialSubject/familyName").asText("");
        var passengerName = firstName + " " + familyName;

        var response = new LinkedHashMap<String, Object>();
        response.put("status", "boarded");
        response.put("passenger", passengerName);
        response.put("flight", bp.path("flightNumber").asText());
        response.put("seat", bp.path("seat").asText());
        response.put("gate", bp.path("gate").asText());
        exchange.getIn().setBody(JSON.writeValueAsString(response));
        exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
    }
}
