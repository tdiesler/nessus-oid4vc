package io.nessus.oid4vc.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.util.List;

@JsonInclude(Include.NON_NULL)
public record DcqlCredentialSet(
    List<List<String>> options,
    Boolean required
) {
    public DcqlCredentialSet {
        if (options == null || options.isEmpty()) {
            throw new IllegalArgumentException("options must not be empty");
        }
        options = options.stream().map(List::copyOf).toList();
    }

    public boolean isRequired() {
        return required == null || required;
    }
}
