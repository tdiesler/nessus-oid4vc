package io.nessus.oid4vc.demo.ticket;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;

import java.util.UUID;

public class TicketRoutes extends RouteBuilder {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final GraphQLHandler graphQLHandler;
    private final TicketStore store;
    private final int port;

    public TicketRoutes(TicketStore store, int port) {
        this.store = store;
        this.graphQLHandler = new GraphQLHandler(store);
        this.port = port;
    }

    @Override
    public void configure() {

        from("undertow:http://0.0.0.0:" + port + "/graphql?httpMethodRestrict=POST")
                .process(exchange -> {
                    var body = exchange.getIn().getBody(String.class);
                    var result = graphQLHandler.execute(body);
                    exchange.getIn().setBody(result);
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });

        from("undertow:http://0.0.0.0:" + port + "/api/booking?httpMethodRestrict=POST")
                .unmarshal().json(Booking.class)
                .process(exchange -> {
                    var booking = exchange.getIn().getBody(Booking.class);
                    var credentialId = "ticket" + UUID.randomUUID().toString().substring(0, 4).toUpperCase();
                    var bookingRef = UUID.randomUUID().toString().substring(0, 4).toUpperCase();
                    var withRef = new Booking(credentialId, booking.flightNumber(), booking.route(),
                            booking.departureDateTime(), bookingRef, booking.passengerName());
                    store.putBooking(credentialId, withRef);
                    var response = JSON.createObjectNode()
                            .put("credentialId", credentialId)
                            .put("bookingReference", bookingRef);
                    exchange.getIn().setBody(JSON.writeValueAsString(response));
                })
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"));

        from("undertow:http://0.0.0.0:" + port + "/?httpMethodRestrict=GET")
                .process(exchange -> {
                    var html = new String(getClass().getClassLoader()
                            .getResourceAsStream("webapp/index.html").readAllBytes());
                    exchange.getIn().setBody(html);
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "text/html");
                });

        from("undertow:http://0.0.0.0:" + port + "/api/bookings?httpMethodRestrict=GET")
                .process(exchange -> {
                    exchange.getIn().setBody(JSON.writeValueAsString(store.getAllBookings()));
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });

        from("undertow:http://0.0.0.0:" + port + "/api/bookings?httpMethodRestrict=DELETE")
                .process(exchange -> {
                    store.clear();
                    exchange.getIn().setBody("{\"status\":\"cleared\"}");
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "application/json");
                });

        from("undertow:http://0.0.0.0:" + port + "/bookings.html?httpMethodRestrict=GET")
                .process(exchange -> {
                    var html = new String(getClass().getClassLoader()
                            .getResourceAsStream("webapp/bookings.html").readAllBytes());
                    exchange.getIn().setBody(html);
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "text/html");
                });

        from("undertow:http://0.0.0.0:" + port + "/graphql.html?httpMethodRestrict=GET")
                .process(exchange -> {
                    var html = new String(getClass().getClassLoader()
                            .getResourceAsStream("webapp/graphql.html").readAllBytes());
                    exchange.getIn().setBody(html);
                    exchange.getIn().setHeader(Exchange.CONTENT_TYPE, "text/html");
                });
    }
}
