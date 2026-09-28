package io.nessus.oid4vc.demo.gate;

import org.apache.camel.main.Main;

public class GateMain {

    public static void main(String[] args) throws Exception {
        var port = Integer.getInteger("gate.port", 18100);

        var main = new Main();
        main.configure().addRoutesBuilder(new GateRoutes(port));
        main.run(args);
    }
}
