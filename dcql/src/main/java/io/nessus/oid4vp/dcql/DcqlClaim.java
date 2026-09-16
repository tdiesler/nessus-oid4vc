package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@JsonInclude(Include.NON_NULL)
public record DcqlClaim(
    String id,
    List<Object> path,
    List<Object> values
) {
    public DcqlClaim {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("path must not be empty");
        }
        path = Collections.unmodifiableList(new ArrayList<>(path));
        values = values != null ? List.copyOf(values) : null;
        for (Object element : path) {
            if (element != null && !(element instanceof String) && !(element instanceof Integer)) {
                throw new IllegalArgumentException(
                    "path elements must be String, Integer, or null, got: " + element.getClass());
            }
        }
    }
}
