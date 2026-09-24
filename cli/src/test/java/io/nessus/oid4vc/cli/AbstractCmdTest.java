package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.BeforeAll;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

class AbstractCmdTest {

    static final ObjectMapper MAPPER = new ObjectMapper();

    static Path projectRoot;
    static Path walletFile;
    static boolean walletExists;
    static boolean keycloakAvailable;

    @BeforeAll
    static void checkPrerequisites() {
        projectRoot = findProjectRoot();
        walletFile = projectRoot.resolve(".config/wallet.json");
        walletExists = Files.exists(walletFile);
        if (walletExists) {
            try {
                JsonNode wallet = MAPPER.readTree(walletFile.toFile());
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

    static Path findProjectRoot() {
        var dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            if (Files.exists(dir.resolve("bin/oid4vc"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("Cannot find project root (looking for bin/oid4vc)");
    }

    @Nonnull
    String getJwksUrl(String realm) throws IOException {
        String realmUrl = getRealmUrl(realm);
        return realmUrl + "/protocol/openid-connect/certs";
    }

    @Nonnull
    String getRealmUrl(String realm) throws IOException {
        var serverUrl = getServerUrl();
        return serverUrl + "/realms/" + realm;
    }

    @Nonnull
    String getServerUrl() throws IOException {
        var wallet = MAPPER.readTree(walletFile.toFile());
        return wallet.at("/serverUrl").asText();
    }

    record CliResult(int exitCode, String stdout, String stderr) {}

    CliResult cli(String... args) throws Exception {
        var cmd = new ArrayList<String>();
        cmd.add("jbang");
        cmd.add(projectRoot.resolve("cli/src/main/java/io/nessus/oid4vc/cli/RootCmd.java").toString());
        cmd.addAll(Arrays.asList(args));
        var pb = new ProcessBuilder(cmd);
        pb.directory(projectRoot.toFile());
        var p = pb.start();
        var stdout = new String(p.getInputStream().readAllBytes());
        var stderr = new String(p.getErrorStream().readAllBytes());
        var exitCode = p.waitFor();
        return new CliResult(exitCode, stdout, stderr);
    }
}
