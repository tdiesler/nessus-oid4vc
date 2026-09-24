package io.nessus.oid4vc.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.Callable;

import static io.nessus.oid4vc.cli.RootCmd.*;

@Command(name = "demo", mixinStandardHelpOptions = true, description = "Demo helper commands",
    subcommands = { DemoCmd.BookTicket.class })
class DemoCmd implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @Command(name = "booking", description = "Create a booking via the airline ticket service")
    static class BookTicket implements Callable<Integer> {

        @Option(names = "--endpoint", description = "Ticket service URL (default: http://localhost:30100)", defaultValue = "http://localhost:30100")
        String endpoint;

        @Option(names = "--passenger-id", required = true, description = "Passenger identifier")
        String passengerId;

        @Option(names = "--passenger-name", required = true, description = "Passenger full name")
        String passengerName;

        @Option(names = "--flight", required = true, description = "Flight number (e.g. BA123)")
        String flightNumber;

        @Option(names = "--route", required = true, description = "Route (e.g. LHR-JFK)")
        String route;

        @Option(names = "--departure", required = true, description = "Departure date/time (ISO-8601, e.g. 2026-10-15T08:30:00Z)")
        String departure;

        @Override
        public Integer call() {
            try {
                var booking = MAPPER.createObjectNode()
                        .put("flightNumber", flightNumber)
                        .put("route", route)
                        .put("departureDateTime", departure)
                        .put("passengerName", passengerName);

                var body = MAPPER.writeValueAsString(booking);
                var url = endpoint + "/api/booking";

                var request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .header("X-Passenger-Id", passengerId)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

                if (verbose) System.out.println("POST " + url);

                var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    System.err.println("Booking failed: HTTP " + response.statusCode() + " " + response.body());
                    return 1;
                }

                var result = MAPPER.readTree(response.body());
                System.out.println("Booking created: " + result.get("bookingReference").asText());
                return 0;
            } catch (Exception ex) {
                System.err.println("Booking failed: " + ex.getMessage());
                return 1;
            }
        }
    }
}
