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

import de.measite.minidns.DNSMessage;
import de.measite.minidns.DNSSECConstants;
import de.measite.minidns.LRUCache;
import de.measite.minidns.Record;
import de.measite.minidns.record.A;
import de.measite.minidns.record.DNSKEY;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.UnknownHostException;
import java.security.PrivateKey;

import static de.measite.minidns.DNSWorld.a;
import static de.measite.minidns.DNSWorld.applyZones;
import static de.measite.minidns.DNSWorld.dnskey;
import static de.measite.minidns.DNSWorld.ns;
import static de.measite.minidns.DNSWorld.record;
import static de.measite.minidns.DNSWorld.rootZone;
import static de.measite.minidns.DNSWorld.zone;
import static de.measite.minidns.dnssec.DNSSECWorld.ds;
import static de.measite.minidns.dnssec.DNSSECWorld.generatePrivateKey;
import static de.measite.minidns.dnssec.DNSSECWorld.publicKey;
import static de.measite.minidns.dnssec.DNSSECWorld.sign;
import static de.measite.minidns.dnssec.DNSSECWorld.signedRootZone;
import static de.measite.minidns.dnssec.DNSSECWorld.signedZone;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DNSSECClientTest {
    private static byte algorithm = DNSSECConstants.SIGNATURE_ALGORITHM_RSASHA256;
    private static byte digestType = DNSSECConstants.DIGEST_ALGORITHM_SHA1;
    private static PrivateKey rootPrivateKSK;
    private static DNSKEY rootKSK;
    private static PrivateKey rootPrivateZSK;
    private static DNSKEY rootZSK;
    private static DNSKEY comKSK;
    private static DNSKEY comZSK;
    private static PrivateKey comPrivateZSK;
    private static PrivateKey comPrivateKSK;
    private DNSSECClient client;

    @BeforeClass
    public static void generateKeys() {
        rootPrivateKSK = generatePrivateKey(algorithm, 2048);
        rootKSK = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, rootPrivateKSK));
        rootPrivateZSK = generatePrivateKey(algorithm, 1024);
        rootZSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, rootPrivateZSK));
        comPrivateKSK = generatePrivateKey(algorithm, 2048);
        comKSK = dnskey(DNSKEY.FLAG_ZONE | DNSKEY.FLAG_SECURE_ENTRY_POINT, algorithm, publicKey(algorithm, comPrivateKSK));
        comPrivateZSK = generatePrivateKey(algorithm, 1024);
        comZSK = dnskey(DNSKEY.FLAG_ZONE, algorithm, publicKey(algorithm, comPrivateZSK));
    }

    @Before
    public void setUp() throws Exception {
        client = new DNSSECClient(new LRUCache(0));
        client.addSecureEntryPoint("", rootKSK.key);
    }

    void checkCorrectExampleMessage(DNSMessage message) {
        Record[] answers = message.getAnswers();
        assertEquals(1, answers.length);
        assertEquals(Record.TYPE.A, answers[0].type);
        assertArrayEquals(new byte[]{1, 1, 1, 2}, ((A) answers[0].payloadData).ip);
    }

    @Test
    public void basicValidTest() throws UnknownHostException {
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertTrue(message.isAuthenticData());
        checkCorrectExampleMessage(message);
    }

    @Test
    public void missingDelegationTest() throws UnknownHostException {
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.isAuthenticData());
        checkCorrectExampleMessage(message);
    }

    @Test
    public void unsignedRootTest() throws UnknownHostException {
        applyZones(client,
                rootZone(
                        record("com", ds("com", digestType, comKSK)),
                        record("com", ns("ns.com")),
                        record("ns.com", a("1.1.1.1"))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.isAuthenticData());
        checkCorrectExampleMessage(message);
    }

    @Test
    public void noRootSepTest() throws UnknownHostException {
        client.clearSecureEntryPoints();
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), signedZone("com", "ns.com", "1.1.1.1",
                        sign(comKSK, "com", comPrivateKSK, algorithm,
                                record("com", comKSK),
                                record("com", comZSK)),
                        sign(comZSK, "com", comPrivateZSK, algorithm,
                                record("example.com", a("1.1.1.2")))
                )
        );
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.isAuthenticData());
        checkCorrectExampleMessage(message);
    }

    @Test
    public void unsignedZoneTest() throws UnknownHostException {
        applyZones(client,
                signedRootZone(
                        sign(rootKSK, "", rootPrivateKSK, algorithm,
                                record("", rootKSK),
                                record("", rootZSK)),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ds("com", digestType, comKSK))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("com", ns("ns.com"))),
                        sign(rootZSK, "", rootPrivateZSK, algorithm,
                                record("ns.com", a("1.1.1.1")))
                ), zone("com", "ns.com", "1.1.1.1",
                        record("example.com", a("1.1.1.2"))
                )
        );
        DNSMessage message = client.query("example.com", Record.TYPE.A);
        assertNotNull(message);
        assertFalse(message.isAuthenticData());
        checkCorrectExampleMessage(message);
    }
}
