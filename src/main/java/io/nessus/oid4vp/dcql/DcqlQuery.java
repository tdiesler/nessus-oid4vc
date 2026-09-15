package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.util.List;

@JsonInclude(Include.NON_NULL)
public record DcqlQuery(
    List<DcqlCredential> credentials,
    List<DcqlCredentialSet> credentialSets
) {
    public DcqlQuery {
        if (credentials == null || credentials.isEmpty()) {
            throw new IllegalArgumentException("credentials must not be empty");
        }
        credentials = List.copyOf(credentials);
        credentialSets = credentialSets != null ? List.copyOf(credentialSets) : null;
    }
}
