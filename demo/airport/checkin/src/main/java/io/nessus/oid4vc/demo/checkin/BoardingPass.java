package io.nessus.oid4vc.demo.checkin;

public record BoardingPass(
    String boardingRef,
    String passengerName,
    String flightNumber,
    String seat,
    String boardingGroup,
    String departureDateTime,
    String gate
) {}
