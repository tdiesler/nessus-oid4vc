package io.nessus.oid4vc.demo.checkin;

import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.GraphQL;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;

import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;

import static graphql.schema.idl.RuntimeWiring.newRuntimeWiring;

public class GraphQLHandler {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final GraphQL graphQL;

    public GraphQLHandler(CheckinStore store) {
        var schemaStream = getClass().getClassLoader().getResourceAsStream("checkin.graphqls");
        var typeDefinition = new SchemaParser().parse(new InputStreamReader(schemaStream));
        var wiring = newRuntimeWiring()
                .type("Query", builder -> builder
                        .dataFetcher("boardingPass", env -> {
                            String passengerId = env.getArgument("passengerId");
                            var bp = store.getBoardingPass(passengerId);
                            if (bp == null) return null;
                            var map = new LinkedHashMap<String, Object>();
                            map.put("passengerName", bp.passengerName());
                            map.put("flightNumber", bp.flightNumber());
                            map.put("seat", bp.seat());
                            map.put("boardingGroup", bp.boardingGroup());
                            map.put("departureDateTime", bp.departureDateTime());
                            map.put("gate", bp.gate());
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
