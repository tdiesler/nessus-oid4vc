package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

@JsonInclude(Include.NON_NULL)
public record DcqlCredential(
    String id,
    String format,
    JsonNode meta,
    List<DcqlClaim> claims,
    List<List<String>> claimSets
) {
    public DcqlCredential {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (format == null || format.isBlank()) {
            throw new IllegalArgumentException("format must not be blank");
        }
        claims = claims != null ? List.copyOf(claims) : null;
        claimSets = claimSets != null
            ? claimSets.stream().map(List::copyOf).toList()
            : null;
    }
}
