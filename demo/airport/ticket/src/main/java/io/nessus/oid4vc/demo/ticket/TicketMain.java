package io.nessus.oid4vc.demo.ticket;

import org.apache.camel.main.Main;

public class TicketMain {

    public static void main(String[] args) throws Exception {
        var port = Integer.getInteger("ticket.port", 18080);
        var store = new TicketStore();

        var main = new Main();
        main.configure().addRoutesBuilder(new TicketRoutes(store, port));
        main.run(args);
    }
}
