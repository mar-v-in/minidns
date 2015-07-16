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
package de.measite.minidns.sec;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

class AlgorithmMap {

    private Map<Byte, DigestCalculator> dsDigestMap;
    private Map<Byte, SignatureVerifier> signatureMap;
    private Map<Byte, DigestCalculator> nsecDigestMap;

    public AlgorithmMap() {
        dsDigestMap = new ConcurrentHashMap<>();
        nsecDigestMap = new ConcurrentHashMap<>();
        try {
            dsDigestMap.put((byte) 1, new JavaSecDigestCalculator("SHA-1"));
            nsecDigestMap.put((byte) 1, new JavaSecDigestCalculator("SHA-1"));
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is MANDATORY
            throw new RuntimeException(e);
        }
        try {
            dsDigestMap.put((byte) 2, new JavaSecDigestCalculator("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is MANDATORY
            throw new RuntimeException(e);
        }

        signatureMap = new ConcurrentHashMap<>();
        try {
            signatureMap.put((byte) 1, new RSASignatureVerifier("MD5withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/MD5 is DEPRECATED
        }
        try {
            signatureMap.put((byte) 5, new RSASignatureVerifier("SHA1withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/SHA-1 is MANDATORY
            throw new RuntimeException(e);
        }
        try {
            signatureMap.put((byte) 8, new RSASignatureVerifier("SHA256withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/SHA-256 is RECOMMENDED
        }
        try {
            signatureMap.put((byte) 10, new RSASignatureVerifier("SHA512withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/SHA-512 is RECOMMENDED
        }
    }

    public DigestCalculator getDsDigestCalculator(byte algorithm) {
        return dsDigestMap.get(algorithm);
    }

    public SignatureVerifier getSignatureVerifier(byte algorithm) {
        return signatureMap.get(algorithm);
    }

    public DigestCalculator getNsecDigestCalculator(byte algorithm) {
        return nsecDigestMap.get(algorithm);
    }
}
