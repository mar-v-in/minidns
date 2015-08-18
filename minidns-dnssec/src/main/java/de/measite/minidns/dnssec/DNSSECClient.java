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

import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.DLV;
import de.measite.minidns.record.DNSKEY;
import de.measite.minidns.record.DS;
import de.measite.minidns.record.OPT;
import de.measite.minidns.record.RRSIG;
import de.measite.minidns.recursive.RecursiveDNSClient;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DNSSECClient extends RecursiveDNSClient {
    private static final BigInteger rootEntryKey = new BigInteger("03010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d", 16);
    private static final String DEFAULT_DLV = "dlv.isc.org";

    /**
     * Create a new DNSSEC aware DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public DNSSECClient(DNSCache cache) {
        super(cache);
        addSecureEntryPoint("", rootEntryKey.toByteArray());
    }

    /**
     * Creates a new DNSSEC aware client that uses the given Map as cache.
     *
     * @param cache the Map to use as cache for DNS results.
     */
    public DNSSECClient(Map<Question, DNSMessage> cache) {
        super(cache);
        addSecureEntryPoint("", rootEntryKey.toByteArray());
    }

    private Verifier verifier = new Verifier();
    private Map<String, byte[]> knownSeps = new ConcurrentHashMap<>();
    private Map<String, DS> knownDelegations = new ConcurrentHashMap<>();
    private boolean stripSignatureRecords = true;
    private String dlv;

    @Override
    public DNSMessage query(Question q, InetAddress address, int port) {
        DNSMessage dnsMessage = super.query(q, address, port);
        if (dnsMessage != null) {
            if (dnsMessage.isAuthoritativeAnswer()) {
                if (!dnsMessage.isAuthenticData()) {
                    verify(dnsMessage);
                }
                if (stripSignatureRecords) {
                    dnsMessage = dnsMessage.withNewRecords(stripSignatureRecords(dnsMessage.getAnswers()),
                            stripSignatureRecords(dnsMessage.getNameserverRecords()),
                            stripSignatureRecords(dnsMessage.getAdditionalResourceRecords()));
                }
            } else {
                List<Record> dss = new ArrayList<>();
                RRSIG dsSig = null;
                for (Record record : dnsMessage.getNameserverRecords()) {
                    if (record.type == TYPE.DS) dss.add(record);
                    if (record.type == TYPE.RRSIG && ((RRSIG) record.payloadData).typeCovered == TYPE.DS)
                        dsSig = (RRSIG) record.payloadData;
                }
                if (dsSig != null) {
                    try {
                        if (verifySignedRecords(q, dsSig, dss)) {
                            for (Record dsRecord : dss) {
                                knownDelegations.put(dsRecord.name, (DS) dsRecord.payloadData);
                            }
                        }
                    } catch (DNSSECValidationFailedException ignored) {
                        // Not actually a problem, just an incomplete hint.
                    }
                }
            }
        }
        return dnsMessage;
    }

    private Record[] stripSignatureRecords(Record[] records) {
        if (records.length == 0) return records;
        List<Record> recordList = new ArrayList<>();
        for (Record record : records) {
            if (record.type != TYPE.RRSIG) {
                recordList.add(record);
            }
        }
        return recordList.toArray(new Record[recordList.size()]);
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        dnsMessage.setAuthenticData(false); // At this state, a DNSMessage is never authentic!
        return super.isResponseCacheable(q, dnsMessage);
    }

    private void verify(DNSMessage dnsMessage) {
        if (dnsMessage.getAnswers().length > 0) {
            verifyAnswer(dnsMessage);
        } else {
            verifyNsec(dnsMessage);
        }
    }

    private void verifyAnswer(DNSMessage dnsMessage) {
        Question q = dnsMessage.getQuestions()[0];
        Record[] answers = dnsMessage.getAnswers();
        List<Record> toBeVerified = new ArrayList<>(Arrays.asList(answers));
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, answers, toBeVerified);
        dnsMessage.setAuthenticData(verifiedSignatures.authenticData);
        if (!verifiedSignatures.signaturesPresent) return;
        boolean sepSignatureValid = false;
        for (Iterator<Record> iterator = toBeVerified.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type == TYPE.DNSKEY && (((DNSKEY) record.payloadData).flags & DNSKEY.FLAG_SECURE_ENTRY_POINT) > 0) {
                if (verifySecureEntryPoint(q, record)) {
                    sepSignatureValid = true;
                }
                if (!verifiedSignatures.sepSignaturePresent) {
                    // TODO: Not sure if this is a problem or should be noted at all? It's at least abnormal...
                    LOGGER.finer("SEP key is not self-signed.");
                }
                iterator.remove();
            }
        }
        if (verifiedSignatures.sepSignaturePresent && !sepSignatureValid) {
            dnsMessage.setAuthenticData(false);
            LOGGER.fine("Verification of answer to " + q + " failed: SEP key is not properly verified.");
        }
        if (verifiedSignatures.sepSignatureRequired && !verifiedSignatures.sepSignaturePresent) {
            dnsMessage.setAuthenticData(false);
            LOGGER.fine("Verification of answer to " + q + " failed: DNSKEY records need to be signed using a SEP key.");
        }
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != answers.length) {
                throw new DNSSECValidationFailedException(q, "Only some records are signed!");
            } else {
                LOGGER.fine("Answer to " + q + " is unsigned!");
                dnsMessage.setAuthenticData(false);
            }
        }
    }

    private void verifyNsec(DNSMessage dnsMessage) {
        Question q = dnsMessage.getQuestions()[0];
        boolean validNsec = false;
        boolean nsecPresent = false;
        String zone = null;
        Record[] nameserverRecords = dnsMessage.getNameserverRecords();
        for (Record nameserverRecord : nameserverRecords) {
            if (nameserverRecord.type == TYPE.SOA)
                zone = nameserverRecord.name;
        }
        if (zone == null)
            throw new DNSSECValidationFailedException(q, "NSECs must always match to a SOA");
        for (Record record : nameserverRecords) {
            Verifier.VerificationState result = null;

            if (record.type == TYPE.NSEC) {
                result = verifier.verifyNsec(record, q);
            } else if (record.type == TYPE.NSEC3) {
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
            throw new DNSSECValidationFailedException(q, "Invalid NSEC!");
        }
        List<Record> toBeVerified = new ArrayList<>(Arrays.asList(nameserverRecords));
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, nameserverRecords, toBeVerified);
        dnsMessage.setAuthenticData(validNsec && verifiedSignatures.authenticData);
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != nameserverRecords.length) {
                throw new DNSSECValidationFailedException(q, "Only some nameserver records are signed!");
            } else {
                LOGGER.fine("Answer to " + q + " is unsigned!");
                dnsMessage.setAuthenticData(false);
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
            RRSIG rrsig = (RRSIG) sigRecord.payloadData;

            Date now = new Date(); 
            if (rrsig.signatureExpiration.compareTo(now) < 0 || rrsig.signatureInception.compareTo(now) > 0) {
                // This RRSIG is out of date, but there might be one that is not.
                toBeVerified.remove(sigRecord);
                continue;
            }

            result.signaturesPresent = true;

            List<Record> records = new ArrayList<>();
            for (Record record : reference) {
                if (record.type == rrsig.typeCovered && record.name.equals(sigRecord.name)) {
                    records.add(record);
                }
            }

            if (!verifySignedRecords(q, rrsig, records)) {
                result.authenticData = false;
                LOGGER.fine("Verification of answer to " + q + " failed: " + records.size() + " " + rrsig.typeCovered + " records failed!");
            }

            if (q.name.equals(rrsig.signerName) && rrsig.typeCovered == TYPE.DNSKEY) {
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
                LOGGER.finer("Records at " + sigRecord.name + " are cross-signed with a key from " + rrsig.signerName);
            } else {
                toBeVerified.removeAll(records);
            }
            toBeVerified.remove(sigRecord);
        }
        if (!result.signaturesPresent) result.authenticData = false;
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
        boolean verifiedResult = true;
        if (rrsig.typeCovered == TYPE.DNSKEY) {
            // Key must be present
            for (Record record : records) {
                if (record.type == TYPE.DNSKEY && ((DNSKEY) record.payloadData).getKeyTag() == rrsig.keyTag) {
                    dnskey = (DNSKEY) record.payloadData;
                }
            }
        } else {
            DNSMessage verify = query(rrsig.signerName, TYPE.DNSKEY);
            if (verify == null) {
                throw new DNSSECValidationFailedException(q, "There is no DNSKEY " + rrsig.signerName + ", but it is used");
            }
            if (!verify.isAuthenticData()) {
                LOGGER.fine("DNSKEY is not authentic, no chance something signed using it is.");
                verifiedResult = false;
            }
            for (Record record : verify.getAnswers()) {
                if (record.type == TYPE.DNSKEY && ((DNSKEY) record.payloadData).getKeyTag() == rrsig.keyTag) {
                    dnskey = (DNSKEY) record.payloadData;
                }
            }
        }
        if (dnskey == null) {
            throw new DNSSECValidationFailedException(q, records.size() + " " + rrsig.typeCovered + " record(s) are signed using an unknown key.");
        }
        Verifier.VerificationState verificationState = verifier.verify(records, rrsig, dnskey);
        switch (verificationState) {
            case FAILED:
                throw new DNSSECValidationFailedException(q, records.size() + " " + rrsig.typeCovered + " record(s) are not signed properly.");
            case VERIFIED:
                return verifiedResult;
            case UNVERIFIED:
            default:
                return false;
        }
    }

    private boolean verifySecureEntryPoint(Question q, Record sepRecord) {
        if (knownSeps.containsKey(sepRecord.name)) {
            if (Arrays.equals(((DNSKEY) sepRecord.payloadData).key, knownSeps.get(sepRecord.name))) {
                return true;
            } else {
                throw new DNSSECValidationFailedException(q, "Secure entry point " + sepRecord.name + " is in list of known SEPs, but mismatches response!");
            }
        }
        boolean verifiedResult = true;
        DS delegation = null;
        if (knownDelegations.containsKey(sepRecord.name)) {
            DS ds = knownDelegations.get(sepRecord.name);
            if (((DNSKEY) sepRecord.payloadData).getKeyTag() == ds.keyTag) {
                delegation = ds;
            } else {
                LOGGER.fine("There is a differing DS record for " + sepRecord.name);
                return false;
            }
        }
        if (delegation == null) {
            DNSMessage dsResp = query(sepRecord.name, TYPE.DS);
            if (dsResp == null) {
                LOGGER.fine("There is no DS record for " + sepRecord.name + ", server gives no result");
            } else {
                verifiedResult = dsResp.isAuthenticData();
                for (Record record : dsResp.getAnswers()) {
                    if (record.type == TYPE.DS && ((DNSKEY) sepRecord.payloadData).getKeyTag() == ((DS) record.payloadData).keyTag) {
                        delegation = (DS) record.payloadData;
                        break;
                    }
                }
                if (delegation == null) {
                    LOGGER.fine("There is no DS record for " + sepRecord.name + ", server gives empty result");
                }
            }
        }
        if (delegation == null && dlv != null) {
            DNSMessage dlvResp = query(sepRecord.name + "." + dlv, TYPE.DLV);
            if (dlvResp != null) {
                verifiedResult = dlvResp.isAuthenticData();
                for (Record record : dlvResp.getAnswers()) {
                    if (record.type == TYPE.DLV && ((DNSKEY) sepRecord.payloadData).getKeyTag() == ((DLV) record.payloadData).keyTag) {
                        LOGGER.fine("Found DLV for " + sepRecord.name + ", awesome.");
                        delegation = (DLV) record.payloadData;
                        break;
                    }
                }
            }
        }
        if (delegation == null) {
            return false;
        }
        Verifier.VerificationState verificationState = verifier.verify(sepRecord, delegation);
        switch (verificationState) {
            case FAILED:
                throw new DNSSECValidationFailedException(q, "SEP is not properly signed by parent DS!");
            case VERIFIED:
                return verifiedResult;
            case UNVERIFIED:
            default:
                return false;
        }
    }

    private static Record nextSignature(List<Record> records) {
        for (Record record : records) {
            if (record.type == TYPE.RRSIG) {
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

    /**
     * Add a new secure entry point to the list of known secure entry points.
     *
     * A secure entry point acts as a trust anchor. By default, the only secure entry point is the key signing key
     * provided by the root zone.
     *
     * @param name The domain name originating the key. Once the secure entry point for this domain is requested,
     *             the resolver will use this key without further verification instead of using the DNS system to
     *             verify the key.
     * @param key  The secure entry point corresponding to the domain name. This key can be retrieved by requesting
     *             the DNSKEY record for the domain and using the key with first flags bit set
     *             (also called key signing key)
     */
    public void addSecureEntryPoint(String name, byte[] key) {
        knownSeps.put(name, key);
    }

    /**
     * Remove the secure entry point stored for a domain name.
     *
     * @param name The domain name of which the corresponding secure entry point shall be removed. For the root zone,
     *             use the empty string here.
     */
    public void removeSecureEntryPoint(String name) {
        knownSeps.remove(name);
    }

    /**
     * Clears the list of known secure entry points.
     *
     * This will also remove the secure entry point of the root zone and
     * thus render this instance useless until a new secure entry point is added.
     */
    public void clearSecureEntryPoints() {
        knownSeps.clear();
    }

    /**
     * Whether signature records (RRSIG) are stripped from the resulting {@link DNSMessage}.
     *
     * Default is {@code true}.
     *
     * @return Whether signature records are stripped.
     */
    public boolean isStripSignatureRecords() {
        return stripSignatureRecords;
    }

    /**
     * Enable or disable stripping of signature records (RRSIG) from the result {@link DNSMessage}.
     * @param stripSignatureRecords Whether signature records shall be stripped.
     */
    public void setStripSignatureRecords(boolean stripSignatureRecords) {
        this.stripSignatureRecords = stripSignatureRecords;
    }

    /**
     * Enables DNSSEC Lookaside Validation (DLV) using the default DLV service at dlv.isc.org.
     */
    public void enableLookasideValidation() {
        configureLookasideValidation(DEFAULT_DLV);
    }

    /**
     * Disables DNSSEC Lookaside Validation (DLV).
     * DLV is disabled by default, this is only required if {@link #enableLookasideValidation()} was used before.
     */
    public void disableLookasideValidation() {
        configureLookasideValidation(null);
    }

    /**
     * Enables DNSSEC Lookaside Validation (DLV) using the given DLV service.
     *
     * @param dlv The domain name of the DLV service to be used or {@code null} to disable DLV.
     */
    public void configureLookasideValidation(String dlv) {
        this.dlv = dlv;
    }
}
