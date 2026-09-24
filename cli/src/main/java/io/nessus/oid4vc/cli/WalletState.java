package io.nessus.oid4vc.cli;

import java.util.List;
import java.util.Map;

class WalletState {
    public String serverUrl;
    public String defaultRealm;
    public Map<String, WalletState.RealmState> realms;

    static class RealmState {
        public String defaultUser;
        public Map<String, WalletState.Connection> users;
    }

    static class Connection {
        public String clientId;
        public String defaultKey;
        public List<Map<String, Object>> keys;
        public String accessToken;
        public String refreshToken;
        public String expiresAt;
    }
}
