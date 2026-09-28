package io.nessus.oid4vc.verifier;

public class VcVerificationException extends Exception {

    public VcVerificationException(String message) {
        super(message);
    }

    public VcVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
