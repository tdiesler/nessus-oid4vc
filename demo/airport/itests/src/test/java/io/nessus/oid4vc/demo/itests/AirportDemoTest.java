package io.nessus.oid4vc.demo.itests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AirportDemoTest {

    static final String TICKET_URL = "http://localhost:30100";
    static final String CHECKIN_URL = "http://localhost:30200";
    static final String GATE_URL = "http://localhost:30300";

    static final Path WALLET_FILE = Path.of(".config/wallet.json");
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final ObjectMapper JSON = new ObjectMapper();

    static JsonNode wallet;
    static Map<String, String> credentials;
    static ECKey holderKey;

    @BeforeAll
    static void checkEnvironment() throws Exception {
        assumeTrue(isReachable(TICKET_URL), "Ticket service not running at " + TICKET_URL);
        assumeTrue(isReachable(CHECKIN_URL), "Checkin service not running at " + CHECKIN_URL);
        assumeTrue(isReachable(GATE_URL), "Gate service not running at " + GATE_URL);
        assumeTrue(Files.exists(WALLET_FILE), "Wallet not found at " + WALLET_FILE);

        wallet = JSON.readTree(WALLET_FILE.toFile());
        var defaultRealm = wallet.path("defaultRealm").asText(null);
        assumeTrue(defaultRealm != null, "No default realm in wallet");

        var realmState = wallet.at("/realms/" + defaultRealm);
        var defaultUser = realmState.path("defaultUser").asText(null);
        assumeTrue(defaultUser != null, "No default user in wallet");

        var credNode = realmState.at("/users/" + defaultUser + "/credentials");
        assumeTrue(!credNode.isMissingNode() && credNode.isObject(), "No credentials in wallet");

        credentials = new LinkedHashMap<>();
        credNode.fields().forEachRemaining(e -> credentials.put(e.getKey(), e.getValue().asText()));

        assumeTrue(findCredential("natural_person") != null, "No natural_person VC in wallet");
        assumeTrue(findCredential("airline_ticket") != null, "No airline_ticket VC in wallet");
        assumeTrue(findCredential("boarding_pass") != null, "No boarding_pass VC in wallet");

        var keysNode = realmState.at("/users/" + defaultUser + "/keys");
        assumeTrue(keysNode.isArray() && !keysNode.isEmpty(), "No holder keys in wallet");
        holderKey = ECKey.parse(JSON.writeValueAsString(keysNode.get(0)));
    }

    @Test
    @Order(1)
    void createBooking() throws Exception {
        var booking = JSON.writeValueAsString(Map.of(
                "flightNumber", "BA123",
                "route", "LHR-JFK",
                "departureDateTime", "2026-10-15T08:30:00Z",
                "passengerName", "Alice Wonderland"));

        var req = HttpRequest.newBuilder()
                .uri(URI.create(TICKET_URL + "/api/booking"))
                .header("Content-Type", "application/json")
                .header("X-Passenger-Id", "alice")
                .POST(HttpRequest.BodyPublishers.ofString(booking))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), resp.body());

        var body = JSON.readTree(resp.body());
        assertNotNull(body.get("bookingReference"));
    }

    @Test
    @Order(2)
    void checkinWithTicketAndPassport() throws Exception {
        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("airline_ticket", buildVpJwt(findCredential("airline_ticket"), CHECKIN_URL + "/checkin"));
        vpToken.put("natural_person", buildVpJwt(findCredential("natural_person"), CHECKIN_URL + "/checkin"));

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(CHECKIN_URL + "/checkin/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), resp.body());

        var body = JSON.readTree(resp.body());
        assertEquals("approved", body.get("status").asText());

        var bp = body.get("boardingPass");
        assertNotNull(bp, "Expected boardingPass in response");
        assertEquals("BA123", bp.get("flightNumber").asText());
        assertNotNull(bp.get("seat").asText());
        assertNotNull(bp.get("gate").asText());
    }

    @Test
    @Order(3)
    void boardAtGateWithBoardingPassAndPassport() throws Exception {
        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("boarding_pass", buildVpJwt(findCredential("boarding_pass"), GATE_URL + "/gate"));
        vpToken.put("natural_person", buildVpJwt(findCredential("natural_person"), GATE_URL + "/gate"));

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(GATE_URL + "/gate/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), resp.body());

        var body = JSON.readTree(resp.body());
        assertEquals("boarded", body.get("status").asText());
        assertNotNull(body.get("passenger").asText());
        assertNotNull(body.get("flight").asText());
        assertNotNull(body.get("seat").asText());
        assertNotNull(body.get("gate").asText());
    }

    static String buildVpJwt(String vcJwt, String audience) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("jwt"))
                .jwk(holderKey.toPublicJWK())
                .build();
        var vp = new LinkedHashMap<String, Object>();
        vp.put("@context", List.of("https://www.w3.org/2018/credentials/v1"));
        vp.put("type", List.of("VerifiablePresentation"));
        vp.put("verifiableCredential", List.of(vcJwt));
        var claims = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(new Date())
                .claim("vp", vp)
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    static String findCredential(String type) {
        for (var entry : credentials.entrySet()) {
            if (entry.getKey().contains(type)) {
                return entry.getValue();
            }
        }
        return null;
    }

    static boolean isReachable(String url) {
        try {
            var req = HttpRequest.newBuilder()
                    .uri(URI.create(url + "/"))
                    .GET()
                    .timeout(java.time.Duration.ofSeconds(2))
                    .build();
            HTTP.send(req, HttpResponse.BodyHandlers.discarding());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
