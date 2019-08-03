package io.peacemakr.crypto.exception;

public class InvalidCipherException extends PeacemakrException {
    InvalidCipherException() {
        super();
    }

    public InvalidCipherException(String message) {
        super(message);
    }

    public InvalidCipherException(Exception e) {
        super(e);
    }
}
