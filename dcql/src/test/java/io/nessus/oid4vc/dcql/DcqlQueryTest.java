package io.nessus.oid4vc.dcql;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class DcqlQueryTest {

    private static final ObjectMapper MAPPER = JacksonSupport.getMapper();

    @Test
    void deserializeSimpleQuery() throws Exception {
        String json = """
            {
              "credentials": [
                {
                  "id": "identity_credential",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"id": "given_name", "path": ["given_name"]},
                    {"id": "family_name", "path": ["family_name"]},
                    {"id": "address", "path": ["address", "street_address"]}
                  ]
                }
              ]
            }
            """;

        DcqlQuery query = MAPPER.readValue(json, DcqlQuery.class);
        assertEquals(1, query.credentials().size());
        assertNull(query.credentialSets());

        DcqlCredential cred = query.credentials().getFirst();
        assertEquals("identity_credential", cred.id());
        assertEquals("dc+sd-jwt", cred.format());
        assertEquals(3, cred.claims().size());

        DcqlClaim addressClaim = cred.claims().get(2);
        assertEquals("address", addressClaim.id());
        assertEquals(List.of("address", "street_address"), addressClaim.path());
    }

    @Test
    void deserializeWithClaimSets() throws Exception {
        String json = """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"id": "given_name", "path": ["given_name"]},
                    {"id": "family_name", "path": ["family_name"]},
                    {"id": "email", "path": ["email"]},
                    {"id": "phone", "path": ["phone_number"]}
                  ],
                  "claim_sets": [
                    ["given_name", "family_name"],
                    ["email"],
                    ["phone"]
                  ]
                }
              ]
            }
            """;

        DcqlQuery query = MAPPER.readValue(json, DcqlQuery.class);
        DcqlCredential cred = query.credentials().getFirst();
        assertEquals(4, cred.claims().size());
        assertEquals(3, cred.claimSets().size());
        assertEquals(List.of("given_name", "family_name"), cred.claimSets().get(0));
    }

    @Test
    void deserializeWithCredentialSets() throws Exception {
        String json = """
            {
              "credentials": [
                {"id": "eu_pid", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]},
                {"id": "us_dl", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]}
              ],
              "credential_sets": [
                {
                  "options": [["eu_pid"], ["us_dl"]],
                  "required": true
                }
              ]
            }
            """;

        DcqlQuery query = MAPPER.readValue(json, DcqlQuery.class);
        assertEquals(2, query.credentials().size());
        assertNotNull(query.credentialSets());
        assertEquals(1, query.credentialSets().size());
        assertEquals(2, query.credentialSets().getFirst().options().size());
    }

    @Test
    void deserializeWithValuesConstraint() throws Exception {
        String json = """
            {
              "credentials": [
                {
                  "id": "age_check",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"id": "age_over_18", "path": ["age_over_18"], "values": [true]}
                  ]
                }
              ]
            }
            """;

        DcqlQuery query = MAPPER.readValue(json, DcqlQuery.class);
        DcqlClaim claim = query.credentials().getFirst().claims().getFirst();
        assertNotNull(claim.values());
        assertEquals(1, claim.values().size());
        assertEquals(true, claim.values().getFirst());
    }

    @Test
    void roundTrip() throws Exception {
        String json = """
            {
              "credentials": [
                {
                  "id": "identity",
                  "format": "dc+sd-jwt",
                  "claims": [
                    {"id": "name", "path": ["given_name"]},
                    {"id": "addr", "path": ["address", "locality"]}
                  ],
                  "claim_sets": [["name"], ["addr"]]
                }
              ]
            }
            """;

        DcqlQuery query = MAPPER.readValue(json, DcqlQuery.class);
        String serialized = MAPPER.writeValueAsString(query);
        DcqlQuery roundTripped = MAPPER.readValue(serialized, DcqlQuery.class);

        assertEquals(query.credentials().size(), roundTripped.credentials().size());
        assertEquals(query.credentials().getFirst().id(), roundTripped.credentials().getFirst().id());
        assertEquals(query.credentials().getFirst().claimSets(), roundTripped.credentials().getFirst().claimSets());
    }
}
