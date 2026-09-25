package io.nessus.oid4vc.mapper;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static io.nessus.oid4vc.mapper.OID4VCGraphQLClaimMapper.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OID4VCGraphQLClaimMapperTest {

    static HttpServer server;
    static String endpoint;

    @BeforeAll
    static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/graphql", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes());
            String response;
            if (body.contains("booking")) {
                response = """
                    {"data":{"booking":{
                        "flightNumber":"BA123",
                        "route":"LHR-JFK",
                        "departure":"2026-10-15T08:30:00Z",
                        "bookingRef":"XKCD42"
                    }}}""";
            } else {
                response = """
                    {"errors":[{"message":"Unknown query"}]}""";
            }
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length());
            try (var os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        });
        server.start();
        endpoint = "http://localhost:" + server.getAddress().getPort() + "/graphql";
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    @Test
    void testSetClaimFromGraphQL() {
        var mapper = new OID4VCGraphQLClaimMapper();

        var config = new HashMap<String, String>();
        config.put(CLAIM_NAME, "ticket");
        config.put(GRAPHQL_ENDPOINT, endpoint);
        config.put(GRAPHQL_QUERY, "query($id: String!) { booking(passengerId: $id) { flightNumber route departure bookingRef } }");
        config.put(GRAPHQL_VARIABLE_MAPPING, "id=username");
        config.put(RESPONSE_PATH, "booking");

        var mapperModel = new ProtocolMapperModel();
        mapperModel.setConfig(config);
        mapper.setMapperModel(mapperModel, "jwt_vc_json");

        var user = mock(UserModel.class);
        when(user.getAttributeStream("username")).thenReturn(Stream.of("alice"));
        var session = mock(UserSessionModel.class);
        when(session.getUser()).thenReturn(user);

        var claims = new HashMap<String, Object>();
        mapper.setClaim(claims, session);

        assertEquals("BA123", claims.get("flightNumber"));
        assertEquals("LHR-JFK", claims.get("route"));
        assertEquals("2026-10-15T08:30:00Z", claims.get("departure"));
        assertEquals("XKCD42", claims.get("bookingRef"));
    }

    @Test
    void testSetClaimScalarValue() {
        var mapper = new OID4VCGraphQLClaimMapper();

        var config = new HashMap<String, String>();
        config.put(CLAIM_NAME, "flightNumber");
        config.put(GRAPHQL_ENDPOINT, endpoint);
        config.put(GRAPHQL_QUERY, "query($id: String!) { booking(passengerId: $id) { flightNumber } }");
        config.put(GRAPHQL_VARIABLE_MAPPING, "id=username");
        config.put(RESPONSE_PATH, "booking.flightNumber");

        var mapperModel = new ProtocolMapperModel();
        mapperModel.setConfig(config);
        mapper.setMapperModel(mapperModel, "jwt_vc_json");

        var user = mock(UserModel.class);
        when(user.getAttributeStream("username")).thenReturn(Stream.of("alice"));
        var session = mock(UserSessionModel.class);
        when(session.getUser()).thenReturn(user);

        var claims = new HashMap<String, Object>();
        mapper.setClaim(claims, session);

        assertEquals("BA123", claims.get("flightNumber"));
        assertNull(claims.get("route"));
    }

    @Test
    void testGraphQLError() {
        var mapper = new OID4VCGraphQLClaimMapper();

        var config = new HashMap<String, String>();
        config.put(CLAIM_NAME, "data");
        config.put(GRAPHQL_ENDPOINT, endpoint);
        config.put(GRAPHQL_QUERY, "{ unknownField }");
        config.put(RESPONSE_PATH, "result");

        var mapperModel = new ProtocolMapperModel();
        mapperModel.setConfig(config);
        mapper.setMapperModel(mapperModel, "jwt_vc_json");

        var session = mock(UserSessionModel.class);

        var claims = new HashMap<String, Object>();
        var ex = assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, session));
        assertTrue(ex.getMessage().contains("GraphQL errors:"));
    }

    @Test
    void testMissingEndpoint() {
        var mapper = new OID4VCGraphQLClaimMapper();

        var config = new HashMap<String, String>();
        config.put(CLAIM_NAME, "data");

        var mapperModel = new ProtocolMapperModel();
        mapperModel.setConfig(config);
        mapper.setMapperModel(mapperModel, "jwt_vc_json");

        var session = mock(UserSessionModel.class);

        var claims = new HashMap<String, Object>();
        var ex = assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, session));
        assertTrue(ex.getMessage().contains("misconfigured"));
    }
}
