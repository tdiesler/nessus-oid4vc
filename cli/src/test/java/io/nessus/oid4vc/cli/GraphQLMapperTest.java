package io.nessus.oid4vc.cli;

import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class GraphQLMapperTest extends AbstractCmdTest {

    static HttpServer graphqlServer;
    static final int GRAPHQL_PORT = 18080;

    @BeforeAll
    static void startGraphQLServer() throws IOException {
        graphqlServer = HttpServer.create(new InetSocketAddress(GRAPHQL_PORT), 0);
        graphqlServer.createContext("/graphql", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes());
            String response;
            if (body.contains("booking")) {
                response = """
                    {"data":{"booking":{
                        "flightNumber":"BA123",
                        "route":"LHR-JFK",
                        "departureDateTime":"2026-10-15T08:30:00Z",
                        "bookingReference":"XKCD42",
                        "passengerName":"Alice Wonderland"
                    }}}""";
            } else {
                response = """
                    {"errors":[{"message":"Unknown query"}]}""";
            }
            var bytes = response.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        graphqlServer.start();
    }

    @AfterAll
    static void stopGraphQLServer() {
        if (graphqlServer != null) graphqlServer.stop(0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void airlineTicketCredentialFromGraphQL() throws Exception {
        assumeTrue(walletExists, "No wallet session");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        var realm = "cli-test-graphql";
        cli("realm", "create", realm);
        try {
            cli("key", "create", "--realm", realm, "--algo", "ES256", "--priority", "120");
            cli("key", "create", "--realm", realm, "--algo", "ECDH-ES", "--priority", "130");

            cli("scope", "create", "oid4vc_airline_ticket_jwt",
                "--realm", realm,
                "--credential-type", "AirlineTicketCredential",
                "--graphql-endpoint", "http://host.docker.internal:" + GRAPHQL_PORT + "/graphql",
                "--graphql-query", "query($id: String!) { booking(passengerId: $id) { flightNumber route departureDateTime bookingReference passengerName } }",
                "--graphql-variable-mapping", "id=username",
                "--graphql-response-path", "booking",
                "--graphql-claim-name", "ticket");

            cli("client", "create", "oid4vci-client",
                "--realm", realm,
                "--vc-scope", "oid4vc_airline_ticket_jwt");

            cli("user", "create", "alice",
                "--realm", realm,
                "--first-name", "Alice", "--last-name", "Wonderland",
                "--email", "alice@test.com", "--password", "password",
                "--vc-scope", "oid4vc_airline_ticket_jwt");

            cli("login", "--realm", realm, "--client-id", "oid4vci-client",
                "--user", "alice", "--password", "password",
                "--scope", "oid4vc_airline_ticket_jwt");

            cli("key", "create", "--user", "alice", "--algo", "ES256");

            var result = cli("vc", "get", "--credential-id", "oid4vc_airline_ticket_jwt_0000");
            assertEquals(0, result.exitCode(), result.stderr());

            var vcJwt = result.stdout().trim();
            var signedJwt = SignedJWT.parse(vcJwt);
            var claims = signedJwt.getJWTClaimsSet();

            var vc = claims.getJSONObjectClaim("vc");
            assertNotNull(vc, "vc claim required");

            var subject = (Map<String, Object>) vc.get("credentialSubject");
            assertNotNull(subject, "credentialSubject required");

            assertEquals("BA123", subject.get("flightNumber"));
            assertEquals("LHR-JFK", subject.get("route"));
            assertEquals("2026-10-15T08:30:00Z", subject.get("departureDateTime"));
            assertEquals("XKCD42", subject.get("bookingReference"));
            assertEquals("Alice Wonderland", subject.get("passengerName"));
        } finally {
            cli("logout", "--realm", realm, "--user", "alice");
            cli("realm", "delete", realm);
        }
    }
}
