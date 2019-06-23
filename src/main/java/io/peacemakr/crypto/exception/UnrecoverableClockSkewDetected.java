package io.peacemakr.crypto.exception;

public class UnrecoverableClockSkewDetected extends PeacemakrException {


    UnrecoverableClockSkewDetected() {
        super();
    }

    public UnrecoverableClockSkewDetected(Exception e) {
        super(e);
    }

    public UnrecoverableClockSkewDetected(String message) {
        super(message);
    }
}
