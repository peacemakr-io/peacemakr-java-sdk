package io.peacemakr.crypto.exception;

public class UnrecoverableClockSkewDetectedException extends PeacemakrException {


    UnrecoverableClockSkewDetectedException() {
        super();
    }

    public UnrecoverableClockSkewDetectedException(Exception e) {
        super(e);
    }

    public UnrecoverableClockSkewDetectedException(String message) {
        super(message);
    }
}
