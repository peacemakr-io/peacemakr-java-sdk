package io.peacemakr.crypto.exception;

public class FailedToDownloadKey extends ServerException {

    public FailedToDownloadKey() {
        super();
    }

    public FailedToDownloadKey(String message) {
        super(message);
    }
}
