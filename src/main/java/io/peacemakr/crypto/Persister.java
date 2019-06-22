package io.peacemakr.crypto;

public interface Persister {

    void save(String key, String value);
    String load(String key);
    boolean exists(String key);

}
