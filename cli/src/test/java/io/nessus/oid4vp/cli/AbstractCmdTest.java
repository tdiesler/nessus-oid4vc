package io.nessus.oid4vp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

class AbstractCmdTest {

    static final Path WALLET_FILE = Path.of(".config", "wallet.json");
    static final ObjectMapper MAPPER = new ObjectMapper();

    static boolean walletExists;
    static boolean keycloakAvailable;

    @BeforeAll
    static void checkPrerequisites() {
        walletExists = Files.exists(WALLET_FILE);
        if (walletExists) {
            try {
                JsonNode wallet = MAPPER.readTree(WALLET_FILE.toFile());
                String serverUrl = wallet.at("/serverUrl").asText();
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

    record CliResult(int exitCode, String stdout, String stderr) {}

    static CliResult cli(String... args) throws Exception {
        var cmd = new ArrayList<String>();
        cmd.add("jbang");
        cmd.add("cli/src/main/java/io/nessus/oid4vp/cli/RootCmd.java");
        cmd.addAll(Arrays.asList(args));
        var pb = new ProcessBuilder(cmd);
        var p = pb.start();
        var stdout = new String(p.getInputStream().readAllBytes());
        var stderr = new String(p.getErrorStream().readAllBytes());
        var exitCode = p.waitFor();
        return new CliResult(exitCode, stdout, stderr);
    }
}
