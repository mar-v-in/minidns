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
package de.measite.minidns.dnssec;

import de.measite.minidns.record.NSEC3;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static de.measite.minidns.DNSSECConstants.DIGEST_ALGORITHM_SHA1;
import static de.measite.minidns.DNSSECConstants.DIGEST_ALGORITHM_SHA256;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_DSA;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_DSA_NSEC3_SHA1;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSAMD5;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA1;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA1_NSEC3_SHA1;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA256;
import static de.measite.minidns.DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA512;

class AlgorithmMap {
    private Logger LOGGER = Logger.getLogger(AlgorithmMap.class.getName());

    private Map<Byte, DigestCalculator> dsDigestMap;
    private Map<Byte, SignatureVerifier> signatureMap;
    private Map<Byte, DigestCalculator> nsecDigestMap;

    @SuppressWarnings("deprecation")
    public AlgorithmMap() {
        dsDigestMap = new ConcurrentHashMap<>();
        nsecDigestMap = new ConcurrentHashMap<>();
        try {
            dsDigestMap.put(DIGEST_ALGORITHM_SHA1, new JavaSecDigestCalculator("SHA-1"));
            nsecDigestMap.put(NSEC3.HASH_ALGORITHM_SHA1, new JavaSecDigestCalculator("SHA-1"));
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is MANDATORY
            throw new DNSSECValidatorInitializationException("SHA-1 is mandatory", e);
        }
        try {
            dsDigestMap.put(DIGEST_ALGORITHM_SHA256, new JavaSecDigestCalculator("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is MANDATORY
            throw new DNSSECValidatorInitializationException("SHA-256 is mandatory", e);
        }

        signatureMap = new ConcurrentHashMap<>();
        try {
            signatureMap.put(SIGNATURE_ALGORITHM_RSAMD5, new RSASignatureVerifier("MD5withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/MD5 is DEPRECATED
        }
        try {
            DSASignatureVerifier sha1withDSA = new DSASignatureVerifier("SHA1withDSA");
            signatureMap.put(SIGNATURE_ALGORITHM_DSA, sha1withDSA);
            signatureMap.put(SIGNATURE_ALGORITHM_DSA_NSEC3_SHA1, sha1withDSA);
        } catch (NoSuchAlgorithmException e) {
            // DSA/SHA-1 is OPTIONAL
            LOGGER.log(Level.INFO, "Platform does not support DSA/SHA-1", e);
        }
        try {
            RSASignatureVerifier sha1withRSA = new RSASignatureVerifier("SHA1withRSA");
            signatureMap.put(SIGNATURE_ALGORITHM_RSASHA1, sha1withRSA);
            signatureMap.put(SIGNATURE_ALGORITHM_RSASHA1_NSEC3_SHA1, sha1withRSA);
        } catch (NoSuchAlgorithmException e) {
            throw new DNSSECValidatorInitializationException("RSA/SHA-1 is mandatory", e);
        }
        try {
            signatureMap.put(SIGNATURE_ALGORITHM_RSASHA256, new RSASignatureVerifier("SHA256withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/SHA-256 is RECOMMENDED
            LOGGER.log(Level.INFO, "Platform does not support RSA/SHA-256", e);
        }
        try {
            signatureMap.put(SIGNATURE_ALGORITHM_RSASHA512, new RSASignatureVerifier("SHA512withRSA"));
        } catch (NoSuchAlgorithmException e) {
            // RSA/SHA-512 is RECOMMENDED
            LOGGER.log(Level.INFO, "Platform does not support RSA/SHA-512", e);
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
