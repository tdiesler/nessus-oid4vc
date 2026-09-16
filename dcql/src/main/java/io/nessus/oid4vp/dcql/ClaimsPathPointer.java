package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Resolves a DCQL claims path against a JSON structure.
 *
 * Path elements: String (object key), Integer (array index), null (all array elements).
 */
public final class ClaimsPathPointer {

    private final List<Object> path;

    public ClaimsPathPointer(List<Object> path) {
        this.path = Collections.unmodifiableList(new ArrayList<>(path));
    }

    public List<JsonNode> resolve(JsonNode root) {
        if (root == null) {
            return List.of();
        }
        List<JsonNode> current = List.of(root);
        for (Object element : path) {
            List<JsonNode> next = new ArrayList<>();
            for (JsonNode node : current) {
                switch (element) {
                    case null -> {
                        if (node.isArray()) {
                            node.forEach(next::add);
                        }
                    }
                    case String key -> {
                        if (node.isObject() && node.has(key)) {
                            next.add(node.get(key));
                        }
                    }
                    case Integer index -> {
                        if (node.isArray() && index >= 0 && index < node.size()) {
                            next.add(node.get(index));
                        }
                    }
                    default -> throw new IllegalStateException(
                        "Invalid path element type: " + element.getClass());
                }
            }
            current = next;
            if (current.isEmpty()) {
                return List.of();
            }
        }
        return Collections.unmodifiableList(current);
    }

    public List<Object> path() {
        return path;
    }
}
