package io.nessus.oid4vc.demo.checkin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.camel.CamelContext;
import org.apache.camel.impl.DefaultCamelContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CheckinServiceTest {

    static final int PORT = 18091;
    static final String BASE = "http://localhost:" + PORT;
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final ObjectMapper JSON = new ObjectMapper();

    static CamelContext camelContext;
    static CheckinStore store;

    @BeforeAll
    static void startService() throws Exception {
        store = new CheckinStore();
        var ctx = new DefaultCamelContext();
        ctx.addRoutes(new CheckinRoutes(store, PORT));
        ctx.start();
        camelContext = ctx;
    }

    @AfterAll
    static void stopService() throws Exception {
        if (camelContext != null) camelContext.close();
    }

    @Test
    void checkinRequestReturnsDcqlQuery() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/checkin"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var body = JSON.readTree(resp.body());
        assertNotNull(body.get("dcql_query"));
        assertNotNull(body.get("nonce"));
        assertNotNull(body.get("response_uri"));

        var credentials = body.at("/dcql_query/credentials");
        assertTrue(credentials.isArray());
        assertEquals(2, credentials.size());
        assertEquals("airline_ticket", credentials.get(0).get("id").asText());
        assertEquals("natural_person", credentials.get(1).get("id").asText());
    }

    @Test
    void checkinResponseApproved() throws Exception {
        var ticketJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_airline_ticket"),
                "credentialSubject", Map.of(
                        "flightNumber", "BA123",
                        "passengerName", "Alice Wonderland",
                        "departureDateTime", "2026-10-15T08:30:00Z",
                        "route", "LHR-JFK",
                        "bookingReference", "ABC123",
                        "id", "alice"
                )
        ));

        var personJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_natural_person"),
                "credentialSubject", Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland",
                        "email", "alice@email.com",
                        "id", "alice"
                )
        ));

        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("airline_ticket", ticketJwt);
        vpToken.put("natural_person", personJwt);

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/checkin/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var body = JSON.readTree(resp.body());
        assertEquals("approved", body.get("status").asText());

        var bp = body.get("boardingPass");
        assertEquals("Alice Wonderland", bp.get("passengerName").asText());
        assertEquals("BA123", bp.get("flightNumber").asText());
        assertEquals("2026-10-15T08:30:00Z", bp.get("departureDateTime").asText());
        assertNotNull(bp.get("seat").asText());
        assertNotNull(bp.get("boardingGroup").asText());
        assertNotNull(bp.get("gate").asText());
    }

    @Test
    void checkinResponseDeniedMissingCredential() throws Exception {
        var personJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_natural_person"),
                "credentialSubject", Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland",
                        "id", "alice"
                )
        ));

        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("natural_person", personJwt);

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/checkin/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var body = JSON.readTree(resp.body());
        assertEquals("denied", body.get("status").asText());
    }

    @Test
    void checkinResponseDeniedMissingPassengerId() throws Exception {
        var requestBody = Map.of("vp_token", Map.of("airline_ticket", "dummy"));

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/checkin/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    @Test
    void boardingPassAvailableViaGraphql() throws Exception {
        store.putBoardingPass("bob", new BoardingPass(
                "Bob Builder", "LH456", "22C", "A", "2026-11-01T10:00:00Z", "G5"));

        var graphqlQuery = """
                {"query":"query($id: String!) { boardingPass(passengerId: $id) { passengerName flightNumber seat boardingGroup departureDateTime gate } }",
                 "variables":{"id":"bob"}}""";

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/graphql"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(graphqlQuery))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var data = JSON.readTree(resp.body()).get("data").get("boardingPass");
        assertEquals("Bob Builder", data.get("passengerName").asText());
        assertEquals("LH456", data.get("flightNumber").asText());
        assertEquals("22C", data.get("seat").asText());
        assertEquals("A", data.get("boardingGroup").asText());
        assertEquals("G5", data.get("gate").asText());
    }

    @Test
    void graphqlNonExistentPassenger() throws Exception {
        var graphqlQuery = """
                {"query":"{ boardingPass(passengerId: \\"nobody\\") { passengerName } }"}""";

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/graphql"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(graphqlQuery))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var data = JSON.readTree(resp.body()).get("data");
        assertTrue(data.get("boardingPass").isNull());
    }

    static String buildVcJwt(Map<String, Object> vcClaims) throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("vc+jwt"))
                .keyID(ecKey.getKeyID())
                .build();
        var claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:30800/realms/test")
                .subject("alice")
                .issueTime(new Date())
                .claim("vc", vcClaims)
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }
}
