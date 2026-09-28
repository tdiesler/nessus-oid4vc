package io.nessus.oid4vc.demo.gate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.nessus.oid4vc.verifier.DcqlEvaluator;
import io.nessus.oid4vc.verifier.DcqlQuery;
import io.nessus.oid4vc.verifier.JacksonSupport;
import io.nessus.oid4vc.verifier.VcJwtVerifier;
import io.nessus.oid4vc.verifier.VcVerificationException;
import io.nessus.oid4vc.verifier.VpJwtVerifier;
import io.nessus.oid4vc.model.VpToken;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;

import java.util.LinkedHashMap;
import java.util.UUID;

public class GateRoutes extends RouteBuilder {

    static final String DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "boarding_pass",
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
                  "id": "natural_person",
                  "format": "jwt_vc_json",
                  "claims": [
                    {"path": ["vc", "credentialSubject", "firstName"]},
                    {"path": ["vc", "credentialSubject", "familyName"]}
                  ]
                }
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

        var passengerId = request.has("passenger_id") ? request.get("passenger_id").asText() : null;
        if (passengerId == null || passengerId.isBlank()) {
            exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 400);
            exchange.getIn().setBody("{\"status\":\"denied\",\"reason\":\"passenger_id required\"}");
            exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
            return;
        }

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
                var vcSignedJwt = SignedJWT.parse(vcJwtStr);
                jwtVerifier.verify(vcSignedJwt);
                var claims = JSON.readTree(vcSignedJwt.getPayload().toString());
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

        var boardingPassClaims = vpToken.getCredentials("boarding_pass").getFirst();
        var bp = boardingPassClaims.at("/vc/credentialSubject");

        var personClaims = vpToken.getCredentials("natural_person").getFirst();
        var firstName = personClaims.at("/vc/credentialSubject/firstName").asText("");
        var familyName = personClaims.at("/vc/credentialSubject/familyName").asText("");
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
