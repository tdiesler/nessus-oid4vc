package io.nessus.oid4vc.demo.ticket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.CamelContext;
import org.apache.camel.impl.DefaultCamelContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

class TicketServiceTest {

    static final int PORT = 18090;
    static final String BASE = "http://localhost:" + PORT;
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final ObjectMapper JSON = new ObjectMapper();

    static CamelContext camelContext;
    static TicketStore store;

    @BeforeAll
    static void startService() throws Exception {
        store = new TicketStore();
        var ctx = new DefaultCamelContext();
        ctx.addRoutes(new TicketRoutes(store, PORT));
        ctx.start();
        camelContext = ctx;
    }

    @AfterAll
    static void stopService() throws Exception {
        if (camelContext != null) camelContext.close();
    }

    @Test
    void createAndQueryBooking() throws Exception {
        var booking = """
            {"flightNumber":"BA123","route":"LHR-JFK",
             "departureDateTime":"2026-10-15T08:30:00Z",
             "passengerName":"Alice Wonderland"}""";

        var createReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/api/booking"))
                .header("Content-Type", "application/json")
                .header("X-Passenger-Id", "alice")
                .POST(HttpRequest.BodyPublishers.ofString(booking))
                .build();
        var createResp = HTTP.send(createReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, createResp.statusCode());

        var graphqlQuery = """
            {"query":"query($id: String!) { booking(passengerId: $id) { flightNumber route departureDateTime bookingReference passengerName } }",
             "variables":{"id":"alice"}}""";

        var queryReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/graphql"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(graphqlQuery))
                .build();
        var queryResp = HTTP.send(queryReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryResp.statusCode());

        var data = JSON.readTree(queryResp.body()).get("data").get("booking");
        assertEquals("BA123", data.get("flightNumber").asText());
        assertEquals("LHR-JFK", data.get("route").asText());
        assertEquals("2026-10-15T08:30:00Z", data.get("departureDateTime").asText());
        assertNotNull(data.get("bookingReference").asText());
        assertEquals(6, data.get("bookingReference").asText().length());
        assertEquals("Alice Wonderland", data.get("passengerName").asText());
    }

    @Test
    void queryNonExistentBooking() throws Exception {
        var graphqlQuery = """
            {"query":"{ booking(passengerId: \\"nobody\\") { flightNumber } }"}""";

        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/graphql"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(graphqlQuery))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        var data = JSON.readTree(resp.body()).get("data");
        assertTrue(data.get("booking").isNull());
    }

    @Test
    void createBookingMissingPassengerId() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/api/booking"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    @Test
    void webappReturnsHtml() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/"))
                .GET()
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("Airline Ticket Booking"));
    }

    @Test
    void graphqlExplorerReturnsHtml() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/graphql.html"))
                .GET()
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("GraphQL Explorer"));
    }

    @Test
    void listAndClearBookings() throws Exception {
        store.clear();
        store.putBooking("bob", new Booking("LH456", "FRA-MUC", "2026-11-01T10:00:00Z", "ABC123", "Bob Builder"));

        var listReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/api/bookings"))
                .GET()
                .build();
        var listResp = HTTP.send(listReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, listResp.statusCode());
        var bookings = JSON.readTree(listResp.body());
        assertEquals("LH456", bookings.get("bob").get("flightNumber").asText());

        var clearReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/api/bookings"))
                .DELETE()
                .build();
        var clearResp = HTTP.send(clearReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, clearResp.statusCode());

        var afterClear = HTTP.send(listReq, HttpResponse.BodyHandlers.ofString());
        assertEquals("{}", JSON.readTree(afterClear.body()).toString());
    }

    @Test
    void bookingsPageReturnsHtml() throws Exception {
        var req = HttpRequest.newBuilder()
                .uri(URI.create(BASE + "/bookings.html"))
                .GET()
                .build();
        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("Bookings"));
    }
}
