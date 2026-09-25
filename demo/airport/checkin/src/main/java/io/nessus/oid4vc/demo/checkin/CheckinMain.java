package io.nessus.oid4vc.demo.checkin;

import org.apache.camel.main.Main;

public class CheckinMain {

    public static void main(String[] args) throws Exception {
        var port = Integer.getInteger("checkin.port", 18090);
        var store = new CheckinStore();

        var main = new Main();
        main.configure().addRoutesBuilder(new CheckinRoutes(store, port));
        main.run(args);
    }
}
