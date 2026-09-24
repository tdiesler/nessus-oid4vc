package io.nessus.oid4vc.demo.ticket;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;

import java.util.UUID;

public class TicketRoutes extends RouteBuilder {

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
                    var passengerId = exchange.getIn().getHeader("X-Passenger-Id", String.class);
                    if (passengerId == null || passengerId.isBlank()) {
                        exchange.getIn().setHeader(Exchange.HTTP_RESPONSE_CODE, 400);
                        exchange.getIn().setBody("{\"error\":\"X-Passenger-Id header required\"}");
                        return;
                    }
                    var bookingRef = UUID.randomUUID().toString().substring(0, 6).toUpperCase();
                    var withRef = new Booking(booking.flightNumber(), booking.route(),
                            booking.departureDateTime(), bookingRef, booking.passengerName());
                    store.putBooking(passengerId, withRef);
                    exchange.getIn().setBody("{\"bookingReference\":\"" + bookingRef + "\"}");
                })
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"));

        from("undertow:http://0.0.0.0:" + port + "/?httpMethodRestrict=GET")
                .process(exchange -> {
                    var html = new String(getClass().getClassLoader()
                            .getResourceAsStream("webapp/index.html").readAllBytes());
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
