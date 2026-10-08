package io.nessus.oid4vc.demo.ticket;

public record Booking(
    String credentialId,
    String flightNumber,
    String route,
    String departureDateTime,
    String bookingReference,
    String passengerName
) {}
