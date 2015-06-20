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
        if (dnsMessage.authoritativeAnswer) {
            LOGGER.info(q.toString());
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
        while ((sigRecord = nextSignature(toBeVerified)) != null) {
            RRSIG rrsig = (RRSIG) sigRecord.payloadData;
            List<Record> records = new ArrayList<>();
            for (Record record : dnsMessage.answers) {
                if (record.type == rrsig.typeCovered && record.name.equals(sigRecord.name)) {
                    records.add(record);
                }
            }
            if (!q.name.equals(rrsig.signerName) || q.type != Record.TYPE.DNSKEY) {
                DNSMessage verify = query(rrsig.signerName, Record.TYPE.DNSKEY);
                for (Record answer : verify.answers) {
                    if (answer.type == Record.TYPE.DNSKEY && ((DNSKEY) answer.payloadData).getKeyTag() == rrsig.keyTag) {
                        LOGGER.info("Verification of " + records.size() + " " + rrsig.typeCovered + " RR using \"" + sigRecord + "\" and \"" + answer + "\": TODO");
                        // TODO: dnsMessage.authenticData = false;
                    }
                }
            }

            toBeVerified.removeAll(records);
            toBeVerified.remove(sigRecord);
        }
        if (!toBeVerified.isEmpty()) {
            dnsMessage.authenticData = false;
        }
        for (Record record : dnsMessage.answers) {
            if (record.type == Record.TYPE.DNSKEY && !record.name.isEmpty() &&
                    (((DNSKEY) record.payloadData).flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                DNSMessage verify = query(record.name, Record.TYPE.DS);
                if (verify == null || !verify.authenticData) {
                    dnsMessage.authenticData = false;
                } else {
                    for (Record ds : verify.answers) {
                        if (ds.type == Record.TYPE.DS && ((DNSKEY) record.payloadData).getKeyTag() == ((DS) ds.payloadData).keyTag) {
                            Verifier.VerificationState verificationState = verifier.verify(record, (DS) ds.payloadData);
                            switch (verificationState) {
                                case FAILED:
                                    throw new SecurityException("Verification of \"" + record + "\" using \"" + ds + "\" failed!");
                                case UNVERIFIED:
                                    dnsMessage.authenticData = false;
                                    break;
                            }
                        }
                    }
                }
            }
        }
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
