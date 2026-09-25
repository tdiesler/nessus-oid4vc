package io.nessus.oid4vc.demo.checkin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.nessus.oid4vc.dcql.DcqlEvaluator;
import io.nessus.oid4vc.dcql.DcqlQuery;
import io.nessus.oid4vc.dcql.JacksonSupport;
import io.nessus.oid4vc.model.VpToken;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class CheckinRoutes extends RouteBuilder {

    static final String DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "airline_ticket",
                  "format": "jwt_vc_json",
                  "claims": [
                    {"path": ["vc", "credentialSubject", "flightNumber"]},
                    {"path": ["vc", "credentialSubject", "passengerName"]},
                    {"path": ["vc", "credentialSubject", "departureDateTime"]}
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

    private final CheckinStore store;
    private final GraphQLHandler graphQLHandler;
    private final DcqlEvaluator evaluator = new DcqlEvaluator();
    private final int port;

    public CheckinRoutes(CheckinStore store, int port) {
        this.store = store;
        this.graphQLHandler = new GraphQLHandler(store);
        this.port = port;
    }

    @Override
    public void configure() {

        from("undertow:http://0.0.0.0:" + port + "/checkin?httpMethodRestrict=POST")
                .process(this::handleCheckinRequest);

        from("undertow:http://0.0.0.0:" + port + "/checkin/response?httpMethodRestrict=POST")
                .process(this::handleCheckinResponse);

        from("undertow:http://0.0.0.0:" + port + "/graphql?httpMethodRestrict=POST")
                .process(exchange -> {
                    var body = exchange.getIn().getBody(String.class);
                    var result = graphQLHandler.execute(body);
                    exchange.getIn().setBody(result);
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });
    }

    private void handleCheckinRequest(Exchange exchange) throws Exception {
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

    private void handleCheckinResponse(Exchange exchange) throws Exception {
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
            var vcJwt = entry.getValue().asText();
            var signedJwt = SignedJWT.parse(vcJwt);
            var claims = JSON.readTree(signedJwt.getPayload().toString());
            vpTokenBuilder.addCredential(credId, claims);
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

        var ticketClaims = vpToken.getCredentials("airline_ticket").getFirst();
        var ticket = ticketClaims.at("/vc/credentialSubject");
        var personClaims = vpToken.getCredentials("natural_person").getFirst();

        var firstName = personClaims.at("/vc/credentialSubject/firstName").asText("");
        var familyName = personClaims.at("/vc/credentialSubject/familyName").asText("");
        var passengerName = firstName + " " + familyName;

        var boardingPass = new BoardingPass(
                passengerName,
                ticket.path("flightNumber").asText(),
                "14A",
                "B",
                ticket.path("departureDateTime").asText(),
                "G12"
        );

        store.putBoardingPass(passengerId, boardingPass);

        var response = new LinkedHashMap<String, Object>();
        response.put("status", "approved");
        response.put("boardingPass", boardingPass);
        exchange.getIn().setBody(JSON.writeValueAsString(response));
        exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
    }
}
