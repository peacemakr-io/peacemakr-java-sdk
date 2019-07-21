package io.peacemakr.crypto.exception;

public class PersistenceLayerCorruptionDetected extends PeacemakrException {

    public PersistenceLayerCorruptionDetected() {
        super();
    }

    public PersistenceLayerCorruptionDetected(String message) {
        super(message);
    }

    public PersistenceLayerCorruptionDetected(Exception e) {
        super(e);
    }

}
