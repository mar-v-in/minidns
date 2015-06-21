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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DNSSECClient extends RecursiveDNSClient {
    public DNSSECClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    public DNSSECClient(Map<Question, DNSMessage> cache) {
        super(cache);
    }

    private Verifier verifier = new Verifier();

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
        dnsMessage.authenticData = true; // assume to be authentic until we know it's not
        Question q = dnsMessage.questions[0];
        List<Record> toBeVerified = new ArrayList<Record>(Arrays.asList(dnsMessage.answers));
        Record sigRecord;
        boolean sepSignatureRequired = false;
        boolean sepSignaturePresent = false;
        while ((sigRecord = nextSignature(toBeVerified)) != null) {
            RRSIG rrsig = (RRSIG) sigRecord.payloadData;
            List<Record> records = new ArrayList<Record>();
            for (Record record : dnsMessage.answers) {
                if (record.type == rrsig.typeCovered && record.name.equals(sigRecord.name)) {
                    records.add(record);
                }
            }

            if (!verifySignedRecords(q, rrsig, records)) {
                dnsMessage.authenticData = false;
                LOGGER.info("Verification of answer to " + q + " failed: " + records.size() + " " + rrsig.typeCovered + " records failed!");
            }

            if (q.name.equals(rrsig.signerName) && rrsig.typeCovered == Record.TYPE.DNSKEY) {
                for (Iterator<Record> iterator = records.iterator(); iterator.hasNext(); ) {
                    DNSKEY dnskey = (DNSKEY) iterator.next().payloadData;
                    if ((dnskey.flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                        // SEPs are verified separately, so don't mark them verified now.
                        iterator.remove();
                        if (dnskey.getKeyTag() == rrsig.keyTag) {
                            sepSignaturePresent = true;
                        }
                    }
                }
                // DNSKEY's should be signed by a SEP
                sepSignatureRequired = true;
            }

            toBeVerified.removeAll(records);
            toBeVerified.remove(sigRecord);
        }
        for (Iterator<Record> iterator = toBeVerified.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type == Record.TYPE.DNSKEY && (((DNSKEY) record.payloadData).flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                if (!verifySecureEntryPoint(q, record)) {
                    dnsMessage.authenticData = false;
                    LOGGER.info("Verification of answer to " + q + " failed: SEP key is not properly verified.");
                }
                if (!sepSignaturePresent) {
                    // TODO: Not sure if this is a problem or should be noted at all? It's at least abnormal...
                    LOGGER.info("SEP key is not self-signed.");
                }
                iterator.remove();
            }
        }
        if (sepSignatureRequired && !sepSignaturePresent) {
            dnsMessage.authenticData = false;
            LOGGER.info("Verification of answer to " + q + " failed: DNSKEY records need to be signed using a SEP key.");
        }
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != dnsMessage.answers.length) {
                throw new SecurityException("Verification of answer to " + q + " failed: Only some records are signed!");
            } else {
                LOGGER.info("Answer to " + q + " is unsigned!");
            }
        }
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
        // TODO: Known SEPs
        if (sepRecord.name.isEmpty()) { // root dnskey, this should be done using a known SEP list
            return true;
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
