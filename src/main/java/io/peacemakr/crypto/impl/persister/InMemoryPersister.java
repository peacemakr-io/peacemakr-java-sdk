package io.peacemakr.crypto.impl.persister;

import io.peacemakr.crypto.Persister;

import java.util.Map;

public class InMemoryPersister implements Persister {

    Map<String, String> m;

    public InMemoryPersister() {}

    @Override
    public void save(String key, String value) {
        m.put(key, value);
    }

    @Override
    public String load(String key) {
        return m.get(key);
    }

    @Override
    public boolean exists(String key) {
        return m.containsKey(key);
    }
}
