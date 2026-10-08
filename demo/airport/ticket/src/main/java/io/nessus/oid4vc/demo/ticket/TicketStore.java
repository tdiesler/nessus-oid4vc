package io.nessus.oid4vc.demo.ticket;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TicketStore {

    private final Map<String, Booking> bookings = new ConcurrentHashMap<>();

    public Booking getBooking(String credentialId) {
        return bookings.get(credentialId);
    }

    public Map<String, Booking> getAllBookings() {
        return Map.copyOf(bookings);
    }

    public void putBooking(String credentialId, Booking booking) {
        bookings.put(credentialId, booking);
    }

    public void clear() {
        bookings.clear();
    }
}
