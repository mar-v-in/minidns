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
package de.measite.minidns.dnssec.algorithms;

import de.measite.minidns.dnssec.DNSSECValidationFailedException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;

class DSASignatureVerifier extends BaseDSASignatureVerifier {
    private static final int LENGTH = 20;

    public DSASignatureVerifier(String algorithm) throws NoSuchAlgorithmException {
        super(LENGTH, "DSA", algorithm);
    }

    protected PublicKey getPublicKey(byte[] key) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(key));

            int t = dis.readUnsignedByte();

            byte[] subPrimeBytes = new byte[LENGTH];
            dis.read(subPrimeBytes);
            BigInteger subPrime = new BigInteger(1, subPrimeBytes);

            byte[] primeBytes = new byte[64 + t * 8];
            dis.read(primeBytes);
            BigInteger prime = new BigInteger(1, primeBytes);

            byte[] baseBytes = new byte[64 + t * 8];
            dis.read(baseBytes);
            BigInteger base = new BigInteger(1, baseBytes);

            byte[] pubKeyBytes = new byte[64 + t * 8];
            dis.read(pubKeyBytes);
            BigInteger pubKey = new BigInteger(1, pubKeyBytes);

            return getKeyFactory().generatePublic(new DSAPublicKeySpec(pubKey, prime, subPrime, base));
        } catch (Exception e) {
            throw new DNSSECValidationFailedException("Invalid public key!", e);
        }
    }
}
