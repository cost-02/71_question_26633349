package com.example;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.ArrayList;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TLSOnlySocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;

    public TLSOnlySocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return filterCipherSuites(this.delegate.getDefaultCipherSuites());
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return filterCipherSuites(this.delegate.getSupportedCipherSuites());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        Socket socket = this.delegate.createSocket(s, host, port, autoClose);
        applyTLSProtocol((SSLSocket) socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        Socket socket = this.delegate.createSocket(host, port);
        applyTLSProtocol((SSLSocket) socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        Socket socket = this.delegate.createSocket(host, port, localHost, localPort);
        applyTLSProtocol((SSLSocket) socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket socket = this.delegate.createSocket(host, port);
        applyTLSProtocol((SSLSocket) socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = this.delegate.createSocket(address, port, localAddress, localPort);
        applyTLSProtocol((SSLSocket) socket);
        return socket;
    }

    private void applyTLSProtocol(SSLSocket socket) {
        socket.setEnabledProtocols(new String[]{"TLSv1.2"}); // Forza TLS 1.2
        socket.setEnabledCipherSuites(filterCipherSuites(socket.getEnabledCipherSuites()));
    }

    private String[] filterCipherSuites(String[] cipherSuites) {
        ArrayList<String> filteredSuites = new ArrayList<>(Arrays.asList(cipherSuites));
        filteredSuites.removeIf(s -> s.contains("SSL")); // Rimuove tutte le suite che includono SSL
        return filteredSuites.toArray(new String[0]);
    }
}
