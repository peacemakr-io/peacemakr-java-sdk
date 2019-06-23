package io.peacemakr.crypto.exception;

public class ServerError extends PeacemakrException {

    ServerError() {
        super();
    }

    public ServerError(Exception e) {
        super(e);
    }

    public ServerError(String message) {
        super(message);
    }
}
