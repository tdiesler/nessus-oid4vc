package io.nessus.oid4vc.demo.gate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
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

class GateServiceTest {

    static final int PORT = 18101;
    static final String BASE = "http://localhost:" + PORT;
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final ObjectMapper JSON = new ObjectMapper();

    static final String TEST_ISSUER = "http://localhost:30800/realms/test";

    static CamelContext camelContext;
    static ECKey issuerKey;
    static ECKey holderKey;

    @BeforeAll
    static void startService() throws Exception {
        issuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-key").generate();
        holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder-key").generate();

        var routes = new GateRoutes(PORT);
        var jwks = JSON.readTree("{\"keys\":[" + issuerKey.toPublicJWK().toJSONString() + "]}");
        routes.jwtVerifier.preloadJwks(TEST_ISSUER, jwks);

        var ctx = new DefaultCamelContext();
        ctx.addRoutes(routes);
        ctx.start();
        camelContext = ctx;
    }

    @AfterAll
    static void stopService() throws Exception {
        if (camelContext != null) camelContext.close();
    }

    @Test
    void gateRequestReturnsDcqlQuery() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/gate"))
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
        assertEquals("boarding_pass", credentials.get(0).get("id").asText());
        assertEquals("natural_person", credentials.get(1).get("id").asText());
    }

    @Test
    void gateResponseBoarded() throws Exception {
        var boardingPassVcJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_boarding_pass"),
                "credentialSubject", Map.of(
                        "passengerName", "Alice Wonderland",
                        "flightNumber", "BA123",
                        "seat", "14A",
                        "boardingGroup", "B",
                        "departureDateTime", "2026-10-15T08:30:00Z",
                        "gate", "G12",
                        "id", "alice"
                )
        ));

        var personVcJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_natural_person"),
                "credentialSubject", Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland",
                        "email", "alice@email.com",
                        "id", "alice"
                )
        ));

        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("boarding_pass", buildVpJwt(boardingPassVcJwt));
        vpToken.put("natural_person", buildVpJwt(personVcJwt));

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/gate/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var body = JSON.readTree(resp.body());
        assertEquals("boarded", body.get("status").asText());
        assertEquals("Alice Wonderland", body.get("passenger").asText());
        assertEquals("BA123", body.get("flight").asText());
        assertEquals("14A", body.get("seat").asText());
        assertEquals("G12", body.get("gate").asText());
    }

    @Test
    void gateResponseDeniedMissingCredential() throws Exception {
        var personVcJwt = buildVcJwt(Map.of(
                "type", List.of("VerifiableCredential", "oid4vc_natural_person"),
                "credentialSubject", Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland",
                        "id", "alice"
                )
        ));

        var vpToken = new LinkedHashMap<String, Object>();
        vpToken.put("natural_person", buildVpJwt(personVcJwt));

        var requestBody = new LinkedHashMap<String, Object>();
        requestBody.put("vp_token", vpToken);
        requestBody.put("passenger_id", "alice");

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/gate/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var body = JSON.readTree(resp.body());
        assertEquals("denied", body.get("status").asText());
    }

    @Test
    void gateResponseDeniedMissingPassengerId() throws Exception {
        var requestBody = Map.of("vp_token", Map.of("boarding_pass", "dummy"));

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/gate/response"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(requestBody)))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    static String buildVcJwt(Map<String, Object> vcClaims) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("vc+jwt"))
                .keyID(issuerKey.getKeyID())
                .build();
        var claims = new JWTClaimsSet.Builder()
                .issuer(TEST_ISSUER)
                .subject("alice")
                .issueTime(new Date())
                .claim("vc", vcClaims)
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(issuerKey));
        return jwt.serialize();
    }

    static String buildVpJwt(String vcJwt) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("jwt"))
                .jwk(holderKey.toPublicJWK())
                .build();
        var vp = new LinkedHashMap<String, Object>();
        vp.put("@context", List.of("https://www.w3.org/2018/credentials/v1"));
        vp.put("type", List.of("VerifiablePresentation"));
        vp.put("verifiableCredential", List.of(vcJwt));
        var claims = new JWTClaimsSet.Builder()
                .audience(BASE + "/gate")
                .issueTime(new Date())
                .claim("nonce", "test-nonce")
                .claim("vp", vp)
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }
}
