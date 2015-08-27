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
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.NoSuchAlgorithmException;

abstract class BaseDSASignatureVerifier extends JavaSecSignatureVerifier {
    private int length;

    public BaseDSASignatureVerifier(int length, String keyAlgorithm, String signatureAlgorithm) throws NoSuchAlgorithmException {
        super(keyAlgorithm, signatureAlgorithm);
        this.length = length;
    }

    @Override
    protected byte[] getSignature(byte[] rrsigData) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rrsigData));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);

            byte[] r = new byte[length];
            dis.read(r);
            int rlen = (r[0] < 0) ? length + 1 : length;

            byte[] s = new byte[length];
            dis.read(s);
            int slen = (r[0] < 0) ? length + 1 : length;

            dos.writeByte(0x30);
            dos.writeByte(rlen + slen + 4);

            dos.writeByte(0x2);
            dos.writeByte(rlen);
            if (rlen > length) dos.writeByte(0);
            dos.write(r);

            dos.writeByte(0x2);
            dos.writeByte(slen);
            if (slen > length) dos.writeByte(0);
            dos.write(s);

            return bos.toByteArray();
        } catch (Exception e) {
            throw new DNSSECValidationFailedException("Invalid signature!", e);
        }
    }
}
