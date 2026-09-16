package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import io.nessus.oid4vp.model.VpToken;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class DcqlEvaluator {

    public DcqlResult evaluate(VpToken vpToken, DcqlQuery query) {
        Map<String, DcqlResult.CredentialMatch> credentialMatches = new LinkedHashMap<>();

        for (DcqlCredential credQuery : query.credentials()) {
            List<JsonNode> presentations = vpToken.getCredentials(credQuery.id());
            DcqlResult.CredentialMatch match = evaluateCredential(credQuery, presentations);
            credentialMatches.put(credQuery.id(), match);
        }

        boolean satisfied = checkOverallSatisfaction(query, credentialMatches);
        return new DcqlResult(satisfied, credentialMatches);
    }

    private DcqlResult.CredentialMatch evaluateCredential(DcqlCredential query, List<JsonNode> presentations) {
        if (presentations.isEmpty()) {
            return new DcqlResult.CredentialMatch(query.id(), false, List.of());
        }

        JsonNode claims = presentations.getFirst();

        if (query.claims() == null || query.claims().isEmpty()) {
            return new DcqlResult.CredentialMatch(query.id(), true, List.of());
        }

        List<DcqlResult.ClaimMatch> claimMatches = new ArrayList<>();
        for (DcqlClaim claimQuery : query.claims()) {
            DcqlResult.ClaimMatch match = evaluateClaim(claimQuery, claims);
            claimMatches.add(match);
        }

        boolean satisfied = checkClaimsSatisfaction(query, claimMatches);
        return new DcqlResult.CredentialMatch(query.id(), satisfied, claimMatches);
    }

    private DcqlResult.ClaimMatch evaluateClaim(DcqlClaim claimQuery, JsonNode claims) {
        ClaimsPathPointer pointer = new ClaimsPathPointer(claimQuery.path());
        List<JsonNode> resolved = pointer.resolve(claims);

        if (resolved.isEmpty()) {
            return new DcqlResult.ClaimMatch(claimQuery.id(), claimQuery.path(), false, List.of());
        }

        boolean valueMatch = true;
        if (claimQuery.values() != null) {
            valueMatch = resolved.stream().anyMatch(node -> matchesAnyValue(node, claimQuery.values()));
        }

        return new DcqlResult.ClaimMatch(claimQuery.id(), claimQuery.path(), valueMatch, resolved);
    }

    private boolean matchesAnyValue(JsonNode node, List<Object> allowedValues) {
        for (Object allowed : allowedValues) {
            if (nodeMatchesValue(node, allowed)) {
                return true;
            }
        }
        return false;
    }

    private boolean nodeMatchesValue(JsonNode node, Object value) {
        if (value == null) {
            return node.isNull();
        }
        if (value instanceof String s) {
            return node.isTextual() && node.asText().equals(s);
        }
        if (value instanceof Number n) {
            if (node.isInt() || node.isLong()) {
                return node.asLong() == n.longValue();
            }
            if (node.isDouble() || node.isFloat()) {
                return Double.compare(node.asDouble(), n.doubleValue()) == 0;
            }
        }
        if (value instanceof Boolean b) {
            return node.isBoolean() && node.asBoolean() == b;
        }
        return false;
    }

    private boolean checkClaimsSatisfaction(DcqlCredential query, List<DcqlResult.ClaimMatch> claimMatches) {
        if (query.claimSets() == null) {
            return claimMatches.stream().allMatch(DcqlResult.ClaimMatch::satisfied);
        }

        Set<String> referencedClaimIds = new HashSet<>();
        for (List<String> claimSet : query.claimSets()) {
            referencedClaimIds.addAll(claimSet);
        }

        for (DcqlResult.ClaimMatch match : claimMatches) {
            boolean unreferenced = match.claimId() == null || !referencedClaimIds.contains(match.claimId());
            if (unreferenced && !match.satisfied()) {
                return false;
            }
        }

        Map<String, DcqlResult.ClaimMatch> matchById = new LinkedHashMap<>();
        for (DcqlResult.ClaimMatch match : claimMatches) {
            if (match.claimId() != null) {
                matchById.put(match.claimId(), match);
            }
        }

        for (List<String> claimSet : query.claimSets()) {
            boolean setFullySatisfied = true;
            for (String claimId : claimSet) {
                DcqlResult.ClaimMatch match = matchById.get(claimId);
                if (match == null || !match.satisfied()) {
                    setFullySatisfied = false;
                    break;
                }
            }
            if (setFullySatisfied) {
                return true;
            }
        }

        return false;
    }

    private boolean checkOverallSatisfaction(DcqlQuery query, Map<String, DcqlResult.CredentialMatch> matches) {
        if (query.credentialSets() == null) {
            return matches.values().stream().allMatch(DcqlResult.CredentialMatch::satisfied);
        }

        Set<String> referencedCredIds = new HashSet<>();
        for (DcqlCredentialSet credSet : query.credentialSets()) {
            for (List<String> option : credSet.options()) {
                referencedCredIds.addAll(option);
            }
        }

        for (Map.Entry<String, DcqlResult.CredentialMatch> entry : matches.entrySet()) {
            if (!referencedCredIds.contains(entry.getKey())) {
                if (!entry.getValue().satisfied()) {
                    return false;
                }
            }
        }

        for (DcqlCredentialSet credSet : query.credentialSets()) {
            if (!credSet.isRequired()) {
                continue;
            }

            boolean anyOptionSatisfied = false;
            for (List<String> option : credSet.options()) {
                boolean optionSatisfied = option.stream()
                    .allMatch(id -> matches.containsKey(id) && matches.get(id).satisfied());
                if (optionSatisfied) {
                    anyOptionSatisfied = true;
                    break;
                }
            }

            if (!anyOptionSatisfied) {
                return false;
            }
        }

        return true;
    }
}
