package io.nessus.oid4vc.demo.checkin;

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
import java.util.Map;
import java.util.UUID;

public class CheckinRoutes extends RouteBuilder {

    static final String DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "airline_ticket_jwt",
                  "format": "jwt_vc_json",
                  "claims": [
                    {"path": ["vc", "credentialSubject", "flightNumber"]},
                    {"path": ["vc", "credentialSubject", "passengerName"]},
                    {"path": ["vc", "credentialSubject", "departureDateTime"]}
                  ]
                },
                {
                  "id": "airline_ticket_sd",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"path": ["flightNumber"]},
                    {"path": ["passengerName"]},
                    {"path": ["departureDateTime"]}
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
                {"options": [["airline_ticket_jwt"], ["airline_ticket_sd"]]},
                {"options": [["natural_person_jwt"], ["natural_person_sd"]]}
              ]
            }
            """;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper DCQL_MAPPER = JacksonSupport.getMapper();

    private final CheckinStore store;
    private final GraphQLHandler graphQLHandler;
    private final DcqlEvaluator evaluator = new DcqlEvaluator();
    final VcJwtVerifier jwtVerifier = new VcJwtVerifier();
    final VpJwtVerifier vpJwtVerifier = new VpJwtVerifier();
    private final int port;

    public CheckinRoutes(CheckinStore store, int port) {
        this.store = store;
        this.graphQLHandler = new GraphQLHandler(store);
        this.port = port;
        var keycloakUrl = System.getenv("KEYCLOAK_URL");
        if (keycloakUrl != null) jwtVerifier.setIssuerBaseUrl(keycloakUrl);
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

        from("undertow:http://0.0.0.0:" + port + "/?httpMethodRestrict=GET")
                .process(exchange -> serveResource(exchange, "webapp/index.html"));

        from("undertow:http://0.0.0.0:" + port + "/passes.html?httpMethodRestrict=GET")
                .process(exchange -> serveResource(exchange, "webapp/passes.html"));

        from("undertow:http://0.0.0.0:" + port + "/graphql.html?httpMethodRestrict=GET")
                .process(exchange -> serveResource(exchange, "webapp/graphql.html"));

        from("undertow:http://0.0.0.0:" + port + "/api/passes?httpMethodRestrict=GET")
                .process(exchange -> {
                    exchange.getIn().setBody(JSON.writeValueAsString(store.getAllBoardingPasses()));
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });

        from("undertow:http://0.0.0.0:" + port + "/api/passes?httpMethodRestrict=DELETE")
                .process(exchange -> {
                    store.clear();
                    exchange.getIn().setBody("{\"status\":\"cleared\"}");
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });
    }

    private void serveResource(Exchange exchange, String path) throws Exception {
        var html = new String(getClass().getClassLoader().getResourceAsStream(path).readAllBytes());
        exchange.getIn().setBody(html);
        exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "text/html");
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

        var ticketCreds = vpToken.getCredentials("airline_ticket_jwt");
        boolean ticketSd = ticketCreds.isEmpty();
        if (ticketSd) ticketCreds = vpToken.getCredentials("airline_ticket_sd");
        var ticketClaims = ticketCreds.getFirst();
        // The GraphQL claim mapper spreads the booking object's fields into individual top-level claims
        // (not nested under claim.name; see keycloak/keycloak#53956), directly under credentialSubject.
        var ticket = ticketSd ? ticketClaims : ticketClaims.at("/vc/credentialSubject");

        var personCreds = vpToken.getCredentials("natural_person_jwt");
        boolean personSd = personCreds.isEmpty();
        if (personSd) personCreds = vpToken.getCredentials("natural_person_sd");
        var personClaims = personCreds.getFirst();

        var boardingRef = "BP" + UUID.randomUUID().toString().substring(0, 4).toUpperCase();

        var firstName = personSd
                ? personClaims.path("firstName").asText("")
                : personClaims.at("/vc/credentialSubject/firstName").asText("");
        var familyName = personSd
                ? personClaims.path("familyName").asText("")
                : personClaims.at("/vc/credentialSubject/familyName").asText("");
        var passengerName = firstName + " " + familyName;

        var boardingPass = new BoardingPass(
                boardingRef,
                passengerName,
                ticket.path("flightNumber").asText(),
                "14A",
                "B",
                ticket.path("departureDateTime").asText(),
                "G12"
        );

        store.putBoardingPass(boardingRef, boardingPass);

        var response = new LinkedHashMap<String, Object>();
        response.put("status", "approved");
        response.put("boardingPass", boardingPass);
        exchange.getIn().setBody(JSON.writeValueAsString(response));
        exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
    }
}
