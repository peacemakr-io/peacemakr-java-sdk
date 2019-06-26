package io.peacemakr.crypto.exception;

public class ServerException extends PeacemakrException {

    ServerException() {
        super();
    }

    public ServerException(Exception e) {
        super(e);
    }

    public ServerException(String message) {
        super(message);
    }
}
