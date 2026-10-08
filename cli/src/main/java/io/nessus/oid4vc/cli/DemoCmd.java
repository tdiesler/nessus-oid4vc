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

        @Option(names = "--endpoint", description = "Ticket service URL")
        String endpoint;

        String resolveEndpoint() {
            if (endpoint != null) return endpoint;
            var host = System.getenv("EXTERNAL_IP");
            return "http://" + (host != null ? host : "localhost") + ":30100";
        }

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
                var url = resolveEndpoint() + "/api/booking";

                var request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

                if (verbose) System.err.println("POST " + url);

                var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    System.err.println("Booking failed: HTTP " + response.statusCode() + " " + response.body());
                    return 1;
                }

                System.out.println(response.body());
                return 0;
            } catch (Exception ex) {
                System.err.println("Booking failed: " + ex.getMessage());
                return 1;
            }
        }
    }
}
