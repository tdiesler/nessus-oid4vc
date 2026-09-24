package io.nessus.oid4vc.model;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Holds decoded credential claims from a VP Token, keyed by credential ID.
 * Each credential ID maps to one or more decoded claim sets (JsonNode).
 */
public final class VpToken {

    private final Map<String, List<JsonNode>> credentials;

    private VpToken(Map<String, List<JsonNode>> credentials) {
        this.credentials = Collections.unmodifiableMap(credentials);
    }

    public static Builder builder() {
        return new Builder();
    }

    public List<JsonNode> getCredentials(String credentialId) {
        return credentials.getOrDefault(credentialId, List.of());
    }

    public Map<String, List<JsonNode>> allCredentials() {
        return credentials;
    }

    public static final class Builder {
        private final Map<String, List<JsonNode>> credentials = new LinkedHashMap<>();

        public Builder addCredential(String id, JsonNode claims) {
            credentials.put(id, List.of(claims));
            return this;
        }

        public Builder addCredentials(String id, List<JsonNode> claimsList) {
            credentials.put(id, List.copyOf(claimsList));
            return this;
        }

        public VpToken build() {
            return new VpToken(new LinkedHashMap<>(credentials));
        }
    }
}
