/*
 * Copyright 2015-2016 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.dnssec;

import de.measite.minidns.DNSMessage;
import de.measite.minidns.Record;

import java.util.Collections;
import java.util.Set;

public class DNSSECMessage extends DNSMessage {
    private final Set<Record> signatures;
    private final Set<UnverifiedReason> result;

    DNSSECMessage(DNSMessage copy, Record[] answers, Record[] nameserverRecords, Record[] additionalResourceRecords, Set<Record> signatures, Set<UnverifiedReason> result) {
        super(copy, answers, nameserverRecords, additionalResourceRecords);
        this.signatures = Collections.unmodifiableSet(signatures);
        this.result = result == null ? Collections.<UnverifiedReason>emptySet() : Collections.unmodifiableSet(result);
        setAuthenticData(this.result.isEmpty());
    }

    public Set<Record> getSignatures() {
        return signatures;
    }

    public Set<UnverifiedReason> getUnverifiedReasons() {
        return result;
    }
}
