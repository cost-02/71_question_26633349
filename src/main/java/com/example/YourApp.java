package com.example;

import javax.net.ssl.HttpsURLConnection;

public class YourApp {
    public static void setupTLS() {
        TLSOnlySocketFactory tlsOnlySocketFactory = new TLSOnlySocketFactory(HttpsURLConnection.getDefaultSSLSocketFactory());
        HttpsURLConnection.setDefaultSSLSocketFactory(tlsOnlySocketFactory);
    }
}
