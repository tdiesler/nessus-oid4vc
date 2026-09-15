package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;

public record DcqlResult(
    boolean satisfied,
    Map<String, CredentialMatch> credentials
) {
    public record CredentialMatch(
        String credentialId,
        boolean satisfied,
        List<ClaimMatch> claims
    ) {}

    public record ClaimMatch(
        String claimId,
        List<Object> path,
        boolean satisfied,
        List<JsonNode> resolvedValues
    ) {}
}
