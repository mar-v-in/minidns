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

import de.measite.minidns.Record;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.util.NameUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Verifier {
    public enum VerificationState {
        UNVERIFIED, FAILED, VERIFIED
    }

    private Map<Byte, DigestCalculator> digestMap;
    private Map<Byte, SignatureVerifier> signatureMap;

    public Verifier() {
        digestMap = new ConcurrentHashMap<>();
        try {
            digestMap.put((byte) 1, new JavaSecDigestCalculator("SHA-1"));
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is MANDATORY
            throw new RuntimeException(e);
        }
        try {
            digestMap.put((byte) 2, new JavaSecDigestCalculator("SHA-256"));
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
            // RSA/SHA-256 is RECOMMENDED
        }
    }

    public VerificationState verify(Record dnskeyRecord, DS ds) {
        DNSKEY dnskey = (DNSKEY) dnskeyRecord.getPayload();
        if (!digestMap.containsKey(ds.digestType)) {
            return VerificationState.UNVERIFIED;
        }

        byte[] dnskeyData = dnskey.toByteArray();
        byte[] dnskeyOwner = NameUtil.toByteArray(dnskeyRecord.getName());
        byte[] combined = new byte[dnskeyOwner.length + dnskeyData.length];
        System.arraycopy(dnskeyOwner, 0, combined, 0, dnskeyOwner.length);
        System.arraycopy(dnskeyData, 0, combined, dnskeyOwner.length, dnskeyData.length);
        DigestCalculator digestCalculator = digestMap.get(ds.digestType);
        byte[] digest = digestCalculator.digest(combined);

        if (!Arrays.equals(digest, ds.digest)) return VerificationState.FAILED;
        return VerificationState.VERIFIED;
    }

    public VerificationState verify(List<Record> records, RRSIG rrsig, DNSKEY key) {
        if (!signatureMap.containsKey(rrsig.algorithm)) {
            return VerificationState.UNVERIFIED;
        }

        SignatureVerifier signatureVerifier = signatureMap.get(rrsig.algorithm);
        byte[] combine = combine(rrsig, records);
        if (signatureVerifier.verify(combine, rrsig.signature, key.key)) {
            return VerificationState.VERIFIED;
        } else {
            return VerificationState.FAILED;
        }
    }

    private byte[] combine(RRSIG rrsig, List<Record> records) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        // Write RRSIG without signature
        try {
            rrsig.writePartialSignature(dos);
        } catch (IOException ignored) {
            // Never happens
        }

        String sigName = records.get(0).name;
        if (!sigName.isEmpty()) {
            String[] name = sigName.split("\\.");
            if (name.length > rrsig.labels) {
                // Expand wildcards
                sigName = name[name.length - 1];
                for (int i = 1; i < rrsig.labels; i++) {
                    sigName = name[name.length - i - 1] + "." + sigName;
                }
                sigName = "*." + sigName;
            } else if (name.length < rrsig.labels) {
                throw new SecurityException("Invalid RRsig record");
            }
        }

        List<byte[]> recordBytes = new ArrayList<>();
        for (Record record : records) {
            Record ref = new Record(sigName, record.type, record.clazzValue, rrsig.originalTtl, record.payloadData);
            recordBytes.add(ref.toByteArray());
        }

        // Sort correctly (cause they might be ordered randomly)
        final int offset = NameUtil.size(sigName) + 10; // Where the RDATA begins
        Collections.sort(recordBytes, new Comparator<byte[]>() {
            @Override
            public int compare(byte[] b1, byte[] b2) {
                for (int i = offset; i < b1.length && i < b2.length; i++) {
                    if (b1[i] != b2[i]) {
                        return (b1[i] & 0xFF) - (b2[i] & 0xFF);
                    }
                }
                return b1.length - b2.length;
            }
        });


        try {
            for (byte[] recordByte : recordBytes) {
                dos.write(recordByte);
            }
            dos.flush();
        } catch (IOException ignored) {
            // Never happens
        }
        return bos.toByteArray();
    }
}
