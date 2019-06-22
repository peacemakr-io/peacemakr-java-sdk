package io.peacemakr.crypto.impl.persister;

import io.peacemakr.crypto.Persister;

public class FilePersister implements Persister {
    @Override
    public void save(String key, String value) {

    }

    @Override
    public String load(String key) {
        return null;
    }

    @Override
    public boolean exists(String key) {
        return false;
    }
}
