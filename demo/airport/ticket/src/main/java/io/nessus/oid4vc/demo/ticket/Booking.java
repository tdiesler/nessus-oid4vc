package io.nessus.oid4vc.demo.ticket;

public record Booking(
    String ticketRef,
    String flightNumber,
    String route,
    String departureDateTime,
    String passengerName
) {}
