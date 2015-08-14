/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.dane;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.LRUCache;
import de.measite.minidns.Record;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.record.TLSA;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DaneVerifier {
    private Logger LOGGER = Logger.getLogger(DaneVerifier.class.getName());

    private final AbstractDNSClient client;

    public DaneVerifier() {
        this(new DNSSECClient(new LRUCache(1024)));
    }

    public DaneVerifier(AbstractDNSClient client) {
        this.client = client;
    }

    public boolean verify(HttpsURLConnection conn) throws CertificateException {
        try {
            conn.connect();
            return verifyCertificateChain(convert(conn.getServerCertificates()), conn.getURL().getHost(),
                    conn.getURL().getPort() < 0 ? conn.getURL().getDefaultPort() : conn.getURL().getPort());
        } catch (IOException e) {
            throw new CertificateException("Peer not verified", e);
        }
    }

    private X509Certificate[] convert(Certificate[] certificates) {
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
                certs.add((X509Certificate) certificate);
            }
        }
        return certs.toArray(new X509Certificate[certs.size()]);
    }

    public boolean verify(SSLSocket socket) throws CertificateException {
        if (!socket.isConnected()) {
            throw new IllegalStateException("Socket not yet connected.");
        }
        return verify(socket.getSession());
    }

    public boolean verify(SSLSession session) throws CertificateException {
        try {
            return verifyCertificateChain(convert(session.getPeerCertificateChain()), session.getPeerHost(), session.getPeerPort());
        } catch (SSLPeerUnverifiedException e) {
            throw new CertificateException("Peer not verified", e);
        }
    }

    private X509Certificate[] convert(javax.security.cert.X509Certificate[] certificates) {
        X509Certificate[] certs = new X509Certificate[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            try {
                certs[i] = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificates[i].getEncoded()));
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Could not convert", e);
            }
        }
        return certs;
    }

    public boolean verifyCertificateChain(X509Certificate[] chain, String hostName, int port) throws CertificateException {
        String req = "_" + port + "._tcp." + hostName;
        DNSMessage res = client.query(req, Record.TYPE.TLSA);
        if (res.isAuthenticData()) {
            TLSA tlsa = null;
            for (Record record : res.getAnswers()) {
                if (record.type == Record.TYPE.TLSA && record.name.equals(req)) {
                    tlsa = (TLSA) record.payloadData;
                }
            }
            if (tlsa != null) {
                switch (tlsa.certUsage) {
                    case TLSA.CERT_USAGE_SERVICE_CERTIFICATE_CONSTRAINT:
                    case TLSA.CERT_USAGE_DOMAIN_ISSUED_CERTIFICATE:
                        if (!checkCertificateMatches(chain[0], tlsa)) {
                            throw new CertificateException("Verification using TLSA failed: certificate differs");
                        }
                        // domain issued certificate does not require further verification, 
                        // service certificate constraint does.
                        return tlsa.certUsage == TLSA.CERT_USAGE_DOMAIN_ISSUED_CERTIFICATE;
                    case TLSA.CERT_USAGE_CA_CONSTRAINT:
                    case TLSA.CRET_USAGE_TRUST_ANCHOR_ASSERTION:
                    default:
                        LOGGER.info("TLSA certificate usage " + tlsa.certUsage + " not supported for " + hostName);
                        return false;
                }
            }
        } else {
            LOGGER.info("Got TLSA response from DNS server, but was not signed properly...");
        }
        return false;
    }

    private static boolean checkCertificateMatches(X509Certificate cert, TLSA tlsa) throws CertificateException {
        byte[] comp = null;
        switch (tlsa.selector) {
            case TLSA.SELECTOR_FULL_CERTIFICATE:
                comp = cert.getEncoded();
                break;
            case TLSA.SELECTOR_SUBJECT_PUBLIC_KEY_INFO:
                comp = cert.getPublicKey().getEncoded();
                break;
        }
        if (comp == null) {
            throw new CertificateException("Verification using TLSA failed: could not create matching bytes");
        }
        switch (tlsa.matchingType) {
            case TLSA.MATCHING_TYPE_NO_HASH:
                break;
            case TLSA.MATCHING_TYPE_SHA_256:
                try {
                    comp = MessageDigest.getInstance("SHA-256").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-256 for matching", e);
                }
                break;
            case TLSA.MATCHING_TYPE_SHA_512:
                try {
                    comp = MessageDigest.getInstance("SHA-512").digest(comp);
                } catch (NoSuchAlgorithmException e) {
                    throw new CertificateException("Verification using TLSA failed: could not SHA-512 for matching", e);
                }
                break;
        }
        return Arrays.equals(comp, tlsa.certificateAssociation);
    }
}
