package io.nessus.oid4vc.cli;

import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

class AbstractCmdTest {

    static final String DEFAULT_REALM = "oid4vci";
    static final String SERVER_URL = "http://localhost:30800";

    static Path projectRoot;
    static Path walletFile;
    static boolean walletExists;
    static boolean keycloakAvailable;
    static boolean realmAvailable;

    private static byte[] walletSnapshot;

    @BeforeAll
    static void checkPrerequisites() {
        projectRoot = findProjectRoot();
        walletFile = projectRoot.resolve(".config/wallet.json");
        walletExists = Files.exists(walletFile);
        if (walletExists) {
            try { walletSnapshot = Files.readAllBytes(walletFile); }
            catch (Exception e) { walletSnapshot = null; }
        }
        keycloakAvailable = checkKeycloak();
        realmAvailable = keycloakAvailable && checkRealm(DEFAULT_REALM);
    }

    @AfterAll
    static void restoreWallet() {
        if (walletSnapshot != null) {
            try { Files.write(walletFile, walletSnapshot); }
            catch (Exception e) { /* best effort */ }
        }
    }

    private static boolean checkKeycloak() {
        try {
            var conn = (HttpURLConnection) URI.create(SERVER_URL).toURL().openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.connect();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean checkRealm(String realm) {
        try {
            var url = SERVER_URL + "/realms/" + realm + "/.well-known/openid-configuration";
            var conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            return conn.getResponseCode() == 200;
        } catch (Exception e) {
            return false;
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
    String getServerUrl() {
        return SERVER_URL;
    }

    @Nonnull
    String getRealmUrl(String realm) {
        return getServerUrl() + "/realms/" + realm;
    }

    @Nonnull
    String getJwksUrl(String realm) {
        return getRealmUrl(realm) + "/protocol/openid-connect/certs";
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
