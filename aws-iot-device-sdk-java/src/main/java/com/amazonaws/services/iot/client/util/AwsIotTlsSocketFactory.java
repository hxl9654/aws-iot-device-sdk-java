/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazonaws.services.iot.client.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import android.net.SSLCertificateSocketFactory;
import android.os.Build;
import android.util.Log;
import java.net.InetSocketAddress;
import java.lang.Error;
import com.amazonaws.services.iot.client.AWSIotException;

/**
 * This class extends {@link SSLSocketFactory} to enforce TLS v1.2 to be used
 * for SSL sockets created by the library.
 */
public class AwsIotTlsSocketFactory extends SSLSocketFactory {
    private static final String TLS_V_1_2 = "TLSv1.2";

    /**
     * SSL Socket Factory A SSL socket factory is created and passed into this
     * class which decorates it to enable TLS 1.2 when sockets are created.
     */
    private final SSLCertificateSocketFactory sslSocketFactory;
    private String endpoint;
    public AwsIotTlsSocketFactory(KeyStore keyStore, String keyPassword, String endpoint) throws AWSIotException {
        try {
        	this.endpoint = endpoint;
            //SSLContext context = SSLContext.getInstance(TLS_V_1_2);
            KeyManagerFactory managerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            managerFactory.init(keyStore, keyPassword.toCharArray());
            //context.init(managerFactory.getKeyManagers(), null, null);
            //sslSocketFactory = context.getSocketFactory();
            sslSocketFactory = (SSLCertificateSocketFactory) SSLCertificateSocketFactory.getDefault(0, null);
            sslSocketFactory.setKeyManagers(managerFactory.getKeyManagers());
            
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new AWSIotException(e);
        }
    }

    public AwsIotTlsSocketFactory(SSLCertificateSocketFactory sslSocketFactory) {
        this.sslSocketFactory = sslSocketFactory;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslSocketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslSocketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return ensureTls(sslSocketFactory.createSocket());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return ensureTls(sslSocketFactory.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return ensureTls(sslSocketFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return ensureTls(sslSocketFactory.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return ensureTls(sslSocketFactory.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return ensureTls(sslSocketFactory.createSocket(address, port, localAddress, localPort));
    }

    /**
     * Enable TLS 1.2 on any socket created by the underlying SSL Socket
     * Factory.
     *
     * @param socket
     *            newly created socket which may not have TLS 1.2 enabled.
     * @return TLS 1.2 enabled socket.
     */
    private Socket ensureTls(Socket socket) {
    	if (socket != null) {
            ((SSLSocket) socket).setEnabledProtocols(new String[]{TLS_V_1_2});

            // Ensure hostname is validated againt the CN in the certificate
            SSLParameters sslParams = new SSLParameters();
	    	if(java.lang.System.getProperty("java.vendor").equalsIgnoreCase("The Android Project"))
	    	{
	    		try {
	                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
	                    sslParams.setEndpointIdentificationAlgorithm("HTTPS");
	                } else {
	                	Log.i("AwsIotTlsSocketFactory.ensureTls", "Using Android older than 7.0, SSLParameters.setEndpointIdentificationAlgorithm() is not supported");
	                	if(!((SSLSocket) socket).isConnected()) {
	                		Log.i("AwsIotTlsSocketFactory.ensureTls", "socket is not connect, connecting to " + endpoint + ":8883");
	                		((SSLSocket) socket).connect(new InetSocketAddress(endpoint, 8883));
	                		Log.i("AwsIotTlsSocketFactory.ensureTls", "connected to " + endpoint + ":8883");
	                		((SSLSocket) socket).startHandshake();
	                	}
	                	HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
	                	SSLSession s = ((SSLSocket) socket).getSession();
	                	Log.d("AwsIotTlsSocketFactory.ensureTls", ((SSLSocket) socket).getRemoteSocketAddress().toString());
	                	Log.i("AwsIotTlsSocketFactory.ensureTls", "Expected " + endpoint + ", found " + s.getPeerPrincipal());
	                	// Verify that the certicate hostname is for endpoint
	                	if (!hv.verify(this.endpoint, s)) {
	                		throw new Error("BAD SSL CERT! MAYBE A MIM ATTACT!", new SSLHandshakeException("Expected " + endpoint + ", found " + s.getPeerPrincipal()));
	                	}
	                	// At this point SSLSocket performed certificate verificaiton and
	                	// we have performed hostname verification, so it is safe to proceed.
                        sslParams = SSLContext.getDefault().getDefaultSSLParameters();
                        ((SSLSocket) socket).close();
                        
                        socket = sslSocketFactory.createSocket();
                        ((SSLSocket) socket).setEnabledProtocols(new String[]{TLS_V_1_2});
                        return socket;
	                }
	    		} catch(Exception e) {
	        		Log.e("AwsIotTlsSocketFactory.ensureTls", "Exception occer", e);
	        	}
	    	} else {
	            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
	    	}
	    	((SSLSocket) socket).setSSLParameters(sslParams);
    	}
	
    	return socket;
    }

}
