package io.nessus.oid4vc.cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nonnull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

class AbstractCmdTest {

    static final String DEFAULT_REALM = "oid4vci";
    static final String PROBE_URL = "http://localhost:30800";

    static Path projectRoot;
    static Path walletFile;
    static boolean walletExists;
    static boolean keycloakAvailable;
    static boolean realmAvailable;
    static String serverUrl;

    private static byte[] walletSnapshot;

    @BeforeAll
    static void checkPrerequisites() {
        projectRoot = findProjectRoot();
        walletFile = projectRoot.resolve(".config/wallet.json");

        // Well-known fixture for test baseline
        Path fixtureFile = projectRoot.resolve("cli/src/test/resources/wallet-fixture.json");

        try {
            var mapper = new ObjectMapper();

            if (!Files.exists(fixtureFile)) {
                // First run or after deletion: copy current wallet to create fixture
                if (Files.exists(walletFile)) {
                    Files.createDirectories(fixtureFile.getParent());
                    Files.copy(walletFile, fixtureFile);
                    System.out.println("Created wallet fixture from current wallet: " + fixtureFile);
                } else {
                    System.err.println("No wallet found at " + walletFile + " - run scripts/oid4vc-setup first");
                }
            }

            if (Files.exists(fixtureFile)) {
                // Step 1: Check if current wallet has admin credentials (from make keycloak-login)
                WalletState current = null;
                WalletState.Connection adminConn = null;
                if (Files.exists(walletFile)) {
                    current = mapper.readValue(walletFile.toFile(), WalletState.class);
                    if (current.realms != null && current.realms.containsKey("master")) {
                        var masterRealm = current.realms.get("master");
                        if (masterRealm.users != null && masterRealm.users.containsKey("admin")) {
                            adminConn = masterRealm.users.get("admin");
                            if (adminConn.accessToken == null) {
                                adminConn = null; // No token means not logged in
                            } else {
                                // Validate admin token is still valid
                                if (!validateAdminToken(current.serverUrl, adminConn.accessToken)) {
                                    System.err.println("WARNING: Admin token from wallet is expired or invalid");
                                    adminConn = null;
                                }
                            }
                        }
                    }
                }

                // Step 2: Load fixture and merge in admin credentials if present
                var baseline = mapper.readValue(fixtureFile.toFile(), WalletState.class);
                if (adminConn != null) {
                    // Use serverUrl from current wallet (admin token was issued by this server)
                    baseline.serverUrl = current.serverUrl;
                    if (baseline.realms == null) baseline.realms = new java.util.HashMap<>();
                    if (!baseline.realms.containsKey("master")) {
                        baseline.realms.put("master", new WalletState.RealmState());
                    }
                    var masterRealm = baseline.realms.get("master");
                    if (masterRealm.users == null) masterRealm.users = new java.util.HashMap<>();
                    if (masterRealm.defaultUser == null) masterRealm.defaultUser = "admin";
                    masterRealm.users.put("admin", adminConn);
                }

                Files.createDirectories(walletFile.getParent());
                // Configure mapper to exclude null values when serializing (preserves admin connection shape)
                var writer = mapper.copy().setDefaultPropertyInclusion(JsonInclude.Include.NON_NULL)
                    .writerWithDefaultPrettyPrinter();
                Files.writeString(walletFile, writer.writeValueAsString(baseline));
                walletSnapshot = Files.readAllBytes(walletFile);
                walletExists = true;

                // Step 3: Validate admin token still works after fixture merge
                if (adminConn != null) {
                    var merged = mapper.readValue(walletFile.toFile(), WalletState.class);
                    var mergedServerUrl = merged.serverUrl != null ? merged.serverUrl : current.serverUrl;
                    if (mergedServerUrl != null) {
                        if (!validateAdminToken(mergedServerUrl, adminConn.accessToken)) {
                            System.err.println("WARNING: Admin token validation failed after fixture merge");
                            System.err.println("  serverUrl: " + mergedServerUrl);
                            System.err.println("  accessToken present: " + (adminConn.accessToken != null));
                        }
                    }
                }

                // Verify fixture has credentials (created by oid4vc-setup)
                var fixtureState = mapper.readValue(fixtureFile.toFile(), WalletState.class);
                var hasCredentials = false;
                if (fixtureState.realms != null) {
                    for (var realmState : fixtureState.realms.values()) {
                        if (realmState.users != null) {
                            for (var conn : realmState.users.values()) {
                                if (conn.credentials != null && !conn.credentials.isEmpty()) {
                                    hasCredentials = true;
                                    break;
                                }
                            }
                        }
                        if (hasCredentials) break;
                    }
                }
                if (!hasCredentials) {
                    System.err.println("WARNING: Wallet fixture has no credentials.");
                    System.err.println("Run scripts/oid4vc-setup with services running, then delete " + fixtureFile);
                }
            } else {
                walletExists = false;
                walletSnapshot = null;
            }
        } catch (Exception e) {
            walletExists = Files.exists(walletFile);
            walletSnapshot = null;
        }

        keycloakAvailable = checkKeycloak();
        realmAvailable = keycloakAvailable && checkRealm(DEFAULT_REALM);
    }

    @BeforeEach
    void restoreWalletBeforeEach() {
        // Restore baseline wallet state before each test for isolation
        // (snapshot already includes admin credentials if they were present at test start)
        if (walletSnapshot != null) {
            try {
                Files.write(walletFile, walletSnapshot);
            } catch (Exception e) {
                /* best effort */
            }
        }
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
            var conn = (HttpURLConnection) URI.create(PROBE_URL).toURL().openConnection();
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
            var url = PROBE_URL + "/realms/" + realm + "/.well-known/openid-configuration";
            var conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            if (conn.getResponseCode() != 200) return false;
            var body = new String(conn.getInputStream().readAllBytes());
            var issuer = new ObjectMapper().readTree(body).get("issuer").asText();
            serverUrl = issuer.replaceAll("/realms/.*$", "");
            return true;
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

    static boolean validateAdminToken(String serverUrl, String token) {
        if (serverUrl == null || token == null) return false;
        try {
            var url = URI.create(serverUrl + "/admin/realms/master");
            var conn = (java.net.HttpURLConnection) url.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                System.err.println("  HTTP response: " + responseCode);
            }
            return responseCode == 200;
        } catch (Exception e) {
            System.err.println("  Exception: " + e.getMessage());
            return false;
        }
    }

    @Nonnull
    String getServerUrl() {
        return serverUrl != null ? serverUrl : PROBE_URL;
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
