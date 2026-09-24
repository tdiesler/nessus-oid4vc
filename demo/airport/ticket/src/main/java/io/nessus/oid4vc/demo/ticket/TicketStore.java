package io.nessus.oid4vc.demo.ticket;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TicketStore {

    private final Map<String, Booking> bookings = new ConcurrentHashMap<>();

    public Booking getBooking(String passengerId) {
        return bookings.get(passengerId);
    }

    public void putBooking(String passengerId, Booking booking) {
        bookings.put(passengerId, booking);
    }
}
