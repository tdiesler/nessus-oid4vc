package io.nessus.oid4vc.dcql;

public class VcVerificationException extends Exception {

    public VcVerificationException(String message) {
        super(message);
    }

    public VcVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
