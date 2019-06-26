package io.peacemakr.crypto.exception;

public class PeacemakrException extends Exception {

    PeacemakrException() {
        super();
    }

    PeacemakrException(String message) {
        super(message);
    }

    public PeacemakrException(Exception e) {
        super(e);
    }
}
