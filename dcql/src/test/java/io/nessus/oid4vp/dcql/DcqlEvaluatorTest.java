package io.nessus.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.nessus.oid4vp.model.VpToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DcqlEvaluatorTest {

    private static final ObjectMapper MAPPER = JacksonSupport.getMapper();
    private static final ObjectMapper JSON = new ObjectMapper();
    private final DcqlEvaluator evaluator = new DcqlEvaluator();

    @Test
    void simpleClaimsMatch() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt",
                "claims": [
                  {"path": ["given_name"]},
                  {"path": ["family_name"]}
                ]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"given_name": "John", "family_name": "Doe", "email": "john@example.com"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("identity", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
        assertTrue(result.credentials().get("identity").satisfied());
    }

    @Test
    void missingClaim() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt",
                "claims": [
                  {"path": ["given_name"]},
                  {"path": ["date_of_birth"]}
                ]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"given_name": "John", "family_name": "Doe"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("identity", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
    }

    @Test
    void missingCredential() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt",
                "claims": [{"path": ["given_name"]}]
              }]
            }
            """, DcqlQuery.class);

        VpToken vpToken = VpToken.builder().build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
        assertFalse(result.credentials().get("identity").satisfied());
    }

    @Test
    void nestedClaimMatch() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt",
                "claims": [
                  {"path": ["address", "locality"]},
                  {"path": ["address", "country"]}
                ]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"address": {"locality": "Anytown", "country": "US", "postal_code": "12345"}}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("identity", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void valuesConstraintSatisfied() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "age_check",
                "format": "dc+sd-jwt",
                "claims": [
                  {"path": ["age_over_18"], "values": [true]}
                ]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"age_over_18": true}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("age_check", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void valuesConstraintNotSatisfied() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "age_check",
                "format": "dc+sd-jwt",
                "claims": [
                  {"path": ["age_over_18"], "values": [true]}
                ]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"age_over_18": false}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("age_check", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
    }

    @Test
    void claimSetsOneSetSatisfied() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "claims": [
                  {"id": "name", "path": ["given_name"]},
                  {"id": "email", "path": ["email"]},
                  {"id": "phone", "path": ["phone_number"]}
                ],
                "claim_sets": [
                  ["name", "email"],
                  ["phone"]
                ]
              }]
            }
            """, DcqlQuery.class);

        // Has phone but not name or email — second claim_set is satisfied
        JsonNode claims = JSON.readTree("""
            {"phone_number": "+1-555-1234"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("pid", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void claimSetsNoSetSatisfied() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "claims": [
                  {"id": "name", "path": ["given_name"]},
                  {"id": "email", "path": ["email"]},
                  {"id": "phone", "path": ["phone_number"]}
                ],
                "claim_sets": [
                  ["name", "email"],
                  ["phone"]
                ]
              }]
            }
            """, DcqlQuery.class);

        // Has name but not email (first set incomplete), no phone (second set incomplete)
        JsonNode claims = JSON.readTree("""
            {"given_name": "John"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("pid", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
    }

    @Test
    void claimSetsUnreferencedClaimsAlwaysRequired() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "claims": [
                  {"id": "name", "path": ["given_name"]},
                  {"id": "email", "path": ["email"]},
                  {"path": ["family_name"]}
                ],
                "claim_sets": [
                  ["name"],
                  ["email"]
                ]
              }]
            }
            """, DcqlQuery.class);

        // Has name (first set satisfied), but missing family_name (unreferenced, always required)
        JsonNode claims = JSON.readTree("""
            {"given_name": "John"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("pid", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
    }

    @Test
    void credentialSetsAlternatives() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [
                {"id": "eu_pid", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]},
                {"id": "us_dl", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]}
              ],
              "credential_sets": [{
                "options": [["eu_pid"], ["us_dl"]],
                "required": true
              }]
            }
            """, DcqlQuery.class);

        // Only US driver's license provided — second option satisfied
        JsonNode claims = JSON.readTree("""
            {"given_name": "Jane", "license_number": "DL123"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("us_dl", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void credentialSetsNoneProvided() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [
                {"id": "eu_pid", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]},
                {"id": "us_dl", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]}
              ],
              "credential_sets": [{
                "options": [["eu_pid"], ["us_dl"]],
                "required": true
              }]
            }
            """, DcqlQuery.class);

        VpToken vpToken = VpToken.builder().build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertFalse(result.satisfied());
    }

    @Test
    void credentialSetsOptional() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [
                {"id": "eu_pid", "format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}]},
                {"id": "bonus", "format": "dc+sd-jwt", "claims": [{"path": ["reward_level"]}]}
              ],
              "credential_sets": [{
                "options": [["bonus"]],
                "required": false
              }]
            }
            """, DcqlQuery.class);

        // eu_pid is unreferenced → always required. bonus is optional → not needed.
        JsonNode claims = JSON.readTree("""
            {"given_name": "John"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("eu_pid", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void noClaimsConstraint() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt"
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"given_name": "John"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("identity", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        assertTrue(result.satisfied());
    }

    @Test
    void resultContainsResolvedValues() throws Exception {
        DcqlQuery query = MAPPER.readValue("""
            {
              "credentials": [{
                "id": "identity",
                "format": "dc+sd-jwt",
                "claims": [{"id": "name", "path": ["given_name"]}]
              }]
            }
            """, DcqlQuery.class);

        JsonNode claims = JSON.readTree("""
            {"given_name": "John"}
            """);

        VpToken vpToken = VpToken.builder()
            .addCredential("identity", claims)
            .build();

        DcqlResult result = evaluator.evaluate(vpToken, query);
        DcqlResult.CredentialMatch cred = result.credentials().get("identity");
        assertEquals(1, cred.claims().size());
        assertEquals("John", cred.claims().getFirst().resolvedValues().getFirst().asText());
    }
}
