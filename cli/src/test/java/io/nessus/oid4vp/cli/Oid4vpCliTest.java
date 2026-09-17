package io.nessus.oid4vp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class Oid4vpCliTest {

    private static final Path WALLET_FILE = Path.of(System.getProperty("user.home"), ".config", "nessus-oid4vp", "wallet.json");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static boolean walletExists;
    private static boolean keycloakAvailable;

    @BeforeAll
    static void checkPrerequisites() {
        walletExists = Files.exists(WALLET_FILE);
        if (walletExists) {
            try {
                JsonNode wallet = MAPPER.readTree(WALLET_FILE.toFile());
                String serverUrl = wallet.at("/connection/serverUrl").asText();
                var conn = (HttpURLConnection) URI.create(serverUrl).toURL().openConnection();
                conn.setConnectTimeout(2000);
                conn.setReadTimeout(2000);
                conn.connect();
                keycloakAvailable = true;
            } catch (Exception e) {
                keycloakAvailable = false;
            }
        }
    }

    @Test
    void help() throws Exception {
        var result = cli("--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("login"), result.stdout());
        assertTrue(result.stdout().contains("realm"), result.stdout());
    }

    @Test
    void realmHelp() throws Exception {
        var result = cli("realm", "--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("create"), result.stdout());
        assertTrue(result.stdout().contains("delete"), result.stdout());
    }

    @Test
    void loginMissingServer() throws Exception {
        var result = cli("login");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void realmCreateMissingName() throws Exception {
        var result = cli("realm", "create");
        assertNotEquals(0, result.exitCode());
    }

    @Test
    void realmCreateDeleteRoundTrip() throws Exception {
        assumeTrue(walletExists, "No wallet session — run 'oid4vp login' first");
        assumeTrue(keycloakAvailable, "Keycloak not reachable");

        var create = cli("realm", "create", "oid4vci-test", "--display-name", "CLI Test");
        assertEquals(0, create.exitCode(), create.stderr());
        assertTrue(create.stdout().contains("Created realm"), create.stdout());

        var delete = cli("realm", "delete", "oid4vci-test");
        assertEquals(0, delete.exitCode(), delete.stderr());
        assertTrue(delete.stdout().contains("Deleted realm"), delete.stdout());
    }

    record CliResult(int exitCode, String stdout, String stderr) {}

    private CliResult cli(String... args) throws Exception {
        var cmd = new ArrayList<String>();
        cmd.add("jbang");
        cmd.add("src/main/java/io/nessus/oid4vp/cli/oid4vp.java");
        cmd.addAll(Arrays.asList(args));
        var pb = new ProcessBuilder(cmd);
        pb.directory(new File(System.getProperty("user.dir")));
        var p = pb.start();
        var stdout = new String(p.getInputStream().readAllBytes());
        var stderr = new String(p.getErrorStream().readAllBytes());
        var exitCode = p.waitFor();
        return new CliResult(exitCode, stdout, stderr);
    }
}
