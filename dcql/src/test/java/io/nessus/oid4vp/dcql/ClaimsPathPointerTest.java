package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaimsPathPointerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void resolveSimpleKey() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"given_name": "John", "family_name": "Doe"}
            """);
        var pointer = new ClaimsPathPointer(List.of("given_name"));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(1, result.size());
        assertEquals("John", result.getFirst().asText());
    }

    @Test
    void resolveNestedKey() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"address": {"street_address": "123 Main St", "locality": "Anytown"}}
            """);
        var pointer = new ClaimsPathPointer(List.of("address", "street_address"));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(1, result.size());
        assertEquals("123 Main St", result.getFirst().asText());
    }

    @Test
    void resolveArrayIndex() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"nationalities": ["US", "DE"]}
            """);
        var pointer = new ClaimsPathPointer(List.of("nationalities", 1));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(1, result.size());
        assertEquals("DE", result.getFirst().asText());
    }

    @Test
    void resolveArrayWildcard() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"nationalities": ["US", "DE", "FR"]}
            """);
        var pointer = new ClaimsPathPointer(Arrays.asList("nationalities", null));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(3, result.size());
        assertEquals("US", result.get(0).asText());
        assertEquals("DE", result.get(1).asText());
        assertEquals("FR", result.get(2).asText());
    }

    @Test
    void resolveMissingKey() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"given_name": "John"}
            """);
        var pointer = new ClaimsPathPointer(List.of("missing_field"));
        List<JsonNode> result = pointer.resolve(root);
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveDeepNested() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"a": {"b": {"c": {"d": "deep_value"}}}}
            """);
        var pointer = new ClaimsPathPointer(List.of("a", "b", "c", "d"));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(1, result.size());
        assertEquals("deep_value", result.getFirst().asText());
    }

    @Test
    void resolveArrayOfObjects() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"contacts": [{"type": "email", "value": "j@example.com"}, {"type": "phone", "value": "555-1234"}]}
            """);
        var pointer = new ClaimsPathPointer(Arrays.asList("contacts", null, "value"));
        List<JsonNode> result = pointer.resolve(root);
        assertEquals(2, result.size());
        assertEquals("j@example.com", result.get(0).asText());
        assertEquals("555-1234", result.get(1).asText());
    }

    @Test
    void resolveOutOfBoundsIndex() throws Exception {
        JsonNode root = MAPPER.readTree("""
            {"items": ["a", "b"]}
            """);
        var pointer = new ClaimsPathPointer(List.of("items", 5));
        List<JsonNode> result = pointer.resolve(root);
        assertTrue(result.isEmpty());
    }

    @Test
    void resolveNullRoot() {
        var pointer = new ClaimsPathPointer(List.of("key"));
        List<JsonNode> result = pointer.resolve(null);
        assertTrue(result.isEmpty());
    }
}
