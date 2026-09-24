package io.nessus.oid4vc.demo.ticket;

import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.GraphQL;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;

import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;

import static graphql.schema.idl.RuntimeWiring.newRuntimeWiring;

public class GraphQLHandler {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final GraphQL graphQL;

    public GraphQLHandler(TicketStore store) {
        var schemaStream = getClass().getClassLoader().getResourceAsStream("ticket.graphqls");
        var typeDefinition = new SchemaParser().parse(new InputStreamReader(schemaStream));
        var wiring = newRuntimeWiring()
                .type("Query", builder -> builder
                        .dataFetcher("booking", env -> {
                            String passengerId = env.getArgument("passengerId");
                            var booking = store.getBooking(passengerId);
                            if (booking == null) return null;
                            var map = new LinkedHashMap<String, Object>();
                            map.put("flightNumber", booking.flightNumber());
                            map.put("route", booking.route());
                            map.put("departureDateTime", booking.departureDateTime());
                            map.put("bookingReference", booking.bookingReference());
                            map.put("passengerName", booking.passengerName());
                            return map;
                        }))
                .build();
        var schema = new SchemaGenerator().makeExecutableSchema(typeDefinition, wiring);
        this.graphQL = GraphQL.newGraphQL(schema).build();
    }

    @SuppressWarnings("unchecked")
    public String execute(String requestBody) throws Exception {
        var request = JSON.readValue(requestBody, Map.class);
        var query = (String) request.get("query");
        var variables = (Map<String, Object>) request.get("variables");

        var executionInput = graphql.ExecutionInput.newExecutionInput()
                .query(query)
                .variables(variables != null ? variables : Map.of())
                .build();

        var result = graphQL.execute(executionInput);
        var response = new LinkedHashMap<String, Object>();
        response.put("data", result.getData());
        if (!result.getErrors().isEmpty()) {
            response.put("errors", result.getErrors());
        }
        return JSON.writeValueAsString(response);
    }
}
