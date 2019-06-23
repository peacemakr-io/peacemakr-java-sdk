package io.peacemakr.crypto;

public class TestUtils {

    public static String getHostname() {
        String hostname = System.getenv("PEACEMAKR_TEST_HOSTNAME");
        if (hostname == null) {
            return "http://localhost:8080";
        }
        return hostname;
    }

    public static String getApiKey() {
        String apiKey = System.getenv("PEACEMAKR_TEST_API_KEY");
        if (apiKey == null) {
            return "peacemaker-key-123-123-123";
        }
        return apiKey;
    }

}
