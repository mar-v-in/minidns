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
package de.measite.minidns;

import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.OPT;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.sec.Verifier;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DNSSECClient extends RecursiveDNSClient {
    private static final BigInteger rootEntryKey = new BigInteger("03010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d", 16);

    public DNSSECClient(DNSCache dnsCache) {
        super(dnsCache);
        addSecureEntryPoint("", rootEntryKey.toByteArray());
    }

    public DNSSECClient(Map<Question, DNSMessage> cache) {
        super(cache);
        addSecureEntryPoint("", rootEntryKey.toByteArray());
    }

    private Verifier verifier = new Verifier();
    private Map<String, byte[]> knownSeps = new ConcurrentHashMap<>();

    @Override
    public DNSMessage query(Question q, InetAddress address, int port) {
        DNSMessage dnsMessage = super.query(q, address, port);
        if (dnsMessage != null && dnsMessage.authoritativeAnswer && !dnsMessage.authenticData) {
            verify(dnsMessage);
        }
        return dnsMessage;
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        dnsMessage.authenticData = false; // At this state, a DNSMessage is never authentic!
        return super.isResponseCacheable(q, dnsMessage);
    }

    private void verify(DNSMessage dnsMessage) {
        if (dnsMessage.answers.length > 0) {
            verifyAnswer(dnsMessage);
        } else {
            verifyNsec(dnsMessage);
        }
    }

    private void verifyAnswer(DNSMessage dnsMessage) {
        Question q = dnsMessage.questions[0];
        List<Record> toBeVerified = new ArrayList<Record>(Arrays.asList(dnsMessage.answers));
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, dnsMessage.answers, toBeVerified);
        dnsMessage.authenticData = verifiedSignatures.authenticData;
        if (!verifiedSignatures.signaturesPresent) return;
        for (Iterator<Record> iterator = toBeVerified.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type == Record.TYPE.DNSKEY && (((DNSKEY) record.payloadData).flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                if (!verifySecureEntryPoint(q, record)) {
                    dnsMessage.authenticData = false;
                    LOGGER.info("Verification of answer to " + q + " failed: SEP key is not properly verified.");
                }
                if (!verifiedSignatures.sepSignaturePresent) {
                    // TODO: Not sure if this is a problem or should be noted at all? It's at least abnormal...
                    LOGGER.info("SEP key is not self-signed.");
                }
                iterator.remove();
            }
        }
        if (verifiedSignatures.sepSignatureRequired && !verifiedSignatures.sepSignaturePresent) {
            dnsMessage.authenticData = false;
            LOGGER.info("Verification of answer to " + q + " failed: DNSKEY records need to be signed using a SEP key.");
        }
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != dnsMessage.answers.length) {
                throw new SecurityException("Verification of answer to " + q + " failed: Only some records are signed!");
            } else {
                LOGGER.info("Answer to " + q + " is unsigned!");
                dnsMessage.authenticData = false;
            }
        }
    }

    private void verifyNsec(DNSMessage dnsMessage) {
        Question q = dnsMessage.questions[0];
        boolean validNsec = false;
        boolean nsecPresent = false;
        String zone = null;
        for (Record nameserverRecord : dnsMessage.nameserverRecords) {
            if (nameserverRecord.type == Record.TYPE.SOA)
                zone = nameserverRecord.name;
        }
        if (zone == null)
            throw new IllegalStateException("NSECs must always match to a SOA");
        for (Record record : dnsMessage.nameserverRecords) {
            Verifier.VerificationState result = null;

            if (record.type == Record.TYPE.NSEC) {
                result = verifier.verifyNsec(record, q);
            } else if (record.type == Record.TYPE.NSEC3) {
                result = verifier.verifyNsec3(zone, record, q);
            }
            if (result != null) {
                switch (result) {
                    case VERIFIED:
                        nsecPresent = true;
                        validNsec = true;
                        break;
                    case FAILED:
                        nsecPresent = true;
                        break;
                }
            }
        }
        if (nsecPresent && !validNsec) {
            throw new SecurityException("Verification of answer to " + q + " failed: Invalid NSEC!");
        }
        List<Record> toBeVerified = new ArrayList<Record>(Arrays.asList(dnsMessage.nameserverRecords));
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, dnsMessage.nameserverRecords, toBeVerified);
        dnsMessage.authenticData = validNsec && verifiedSignatures.authenticData;
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != dnsMessage.answers.length) {
                throw new SecurityException("Verification of answer to " + q + " failed: Only some nameserver records are signed!");
            } else {
                LOGGER.info("Answer to " + q + " is unsigned!");
                dnsMessage.authenticData = false;
            }
        }
    }

    private class VerifySignaturesResult {
        boolean sepSignatureRequired = false;
        boolean sepSignaturePresent = false;
        boolean authenticData = true; // assume to be authentic until we know it's not
        boolean signaturesPresent = false;
    }

    private VerifySignaturesResult verifySignatures(Question q, Record[] reference, List<Record> toBeVerified) {
        Record sigRecord;
        VerifySignaturesResult result = new VerifySignaturesResult();
        while ((sigRecord = nextSignature(toBeVerified)) != null) {
            result.signaturesPresent = true;
            RRSIG rrsig = (RRSIG) sigRecord.payloadData;
            List<Record> records = new ArrayList<>();
            for (Record record : reference) {
                if (record.type == rrsig.typeCovered && record.name.equals(sigRecord.name)) {
                    records.add(record);
                }
            }

            if (!verifySignedRecords(q, rrsig, records)) {
                result.authenticData = false;
                LOGGER.info("Verification of answer to " + q + " failed: " + records.size() + " " + rrsig.typeCovered + " records failed!");
            }

            if (q.name.equals(rrsig.signerName) && rrsig.typeCovered == Record.TYPE.DNSKEY) {
                for (Iterator<Record> iterator = records.iterator(); iterator.hasNext(); ) {
                    DNSKEY dnskey = (DNSKEY) iterator.next().payloadData;
                    if ((dnskey.flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                        // SEPs are verified separately, so don't mark them verified now.
                        iterator.remove();
                        if (dnskey.getKeyTag() == rrsig.keyTag) {
                            result.sepSignaturePresent = true;
                        }
                    }
                }
                // DNSKEY's should be signed by a SEP
                result.sepSignatureRequired = true;
            }

            if (!isParentOrSelf(sigRecord.name, rrsig.signerName)) {
                LOGGER.info("You cross-signed your records at " + sigRecord.name + " with a key from " + rrsig.signerName + ". That's nice, but we don't care.");
            } else {
                toBeVerified.removeAll(records);
            }
            toBeVerified.remove(sigRecord);
        }
        return result;
    }

    private boolean isParentOrSelf(String child, String parent) {
        if (child.equals(parent)) return true;
        if (parent.isEmpty()) return true;
        String[] childSplit = child.split("\\.");
        String[] parentSplit = parent.split("\\.");
        if (parentSplit.length > childSplit.length) return false;
        for (int i = 1; i <= parentSplit.length; i++) {
            if (!parentSplit[parentSplit.length - i].equals(childSplit[childSplit.length - i])) {
                return false;
            }
        }
        return true;
    }

    private boolean verifySignedRecords(Question q, RRSIG rrsig, List<Record> records) {
        DNSKEY dnskey = null;
        if (rrsig.typeCovered == Record.TYPE.DNSKEY) {
            // Key must be present
            for (Record record : records) {
                if (record.type == Record.TYPE.DNSKEY && ((DNSKEY) record.payloadData).getKeyTag() == rrsig.keyTag) {
                    dnskey = (DNSKEY) record.payloadData;
                }
            }
        } else {
            DNSMessage verify = query(rrsig.signerName, Record.TYPE.DNSKEY);
            for (Record record : verify.answers) {
                if (record.type == Record.TYPE.DNSKEY && ((DNSKEY) record.payloadData).getKeyTag() == rrsig.keyTag) {
                    dnskey = (DNSKEY) record.payloadData;
                }
            }
        }
        if (dnskey == null) {
            throw new SecurityException("Verification of answer to " + q + " failed: " + records.size() + " " + rrsig.typeCovered + " record(s) are signed using an unknown key.");
        }
        Verifier.VerificationState verificationState = verifier.verify(records, rrsig, dnskey);
        switch (verificationState) {
            case FAILED:
                throw new SecurityException("Verification of answer to " + q + " failed: " + records.size() + " " + rrsig.typeCovered + " record(s) are not signed properly.");
            case VERIFIED:
                return true;
            case UNVERIFIED:
                return false;
        }
        return false;
    }

    private boolean verifySecureEntryPoint(Question q, Record sepRecord) {
        if (knownSeps.containsKey(sepRecord.name)) {
            if (Arrays.equals(((DNSKEY) sepRecord.payloadData).key, knownSeps.get(sepRecord.name))) {
                return true;
            } else {
                throw new SecurityException("Verification of answer to " + q + " failed: Secure entry point " + sepRecord.name + " is in list of known SEPs, but mismatches response!");
            }
        }
        DNSMessage verify = query(sepRecord.name, Record.TYPE.DS);
        if (verify == null || !verify.authenticData) {
            return false;
        }
        DS ds = null;
        for (Record record : verify.answers) {
            if (record.type == Record.TYPE.DS && ((DNSKEY) sepRecord.payloadData).getKeyTag() == ((DS) record.payloadData).keyTag) {
                ds = (DS) record.payloadData;
            }
        }
        if (ds == null) {
            return false;
        }
        Verifier.VerificationState verificationState;
        try {
            verificationState = verifier.verify(sepRecord, ds);
        } catch (UnsupportedOperationException e) {
            LOGGER.warning("Verification of answer to " + q + " failed: " + e);
            return false;
        }
        switch (verificationState) {
            case FAILED:
                throw new SecurityException("Verification of answer to " + q + " failed: SEP is not properly signed by parent DS!");
            case UNVERIFIED:
                return false;
            case VERIFIED:
                return true;
        }
        return false;
    }

    private void addSecureEntryPoint(String name, byte[] key) {
        knownSeps.put(name, key);
    }

    private static Record nextSignature(List<Record> records) {
        for (Record record : records) {
            if (record.type == Record.TYPE.RRSIG) {
                return record;
            }
        }
        return null;
    }

    @Override
    protected DNSMessage buildMessage(Question question) {
        DNSMessage message = super.buildMessage(question);
        message.setOptPseudoRecord(getDataSource().getUdpPayloadSize(), OPT.FLAG_DNSSEC_OK);
        return message;
    }
}
