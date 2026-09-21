package io.nessus.oid4vp.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

class LoginCmdTest extends AbstractCmdTest {

    @Test
    void loginMissingServer() throws Exception {
        var result = cli("login");
        assertNotEquals(0, result.exitCode());
    }
}
