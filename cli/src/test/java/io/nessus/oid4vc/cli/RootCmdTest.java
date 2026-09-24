package io.nessus.oid4vc.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RootCmdTest extends AbstractCmdTest {

    @Test
    void help() throws Exception {
        var result = cli("--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("login"), result.stdout());
        assertTrue(result.stdout().contains("realm"), result.stdout());
    }
}
