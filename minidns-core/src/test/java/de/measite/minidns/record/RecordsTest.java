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
package de.measite.minidns.record;

import de.measite.minidns.Record;
import de.measite.minidns.util.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * These are some tests for all records.
 *
 * The tests main purpose is to test if the output of toByteArray() is parsed into it's original value.
 *
 * Additionally, toString() is tested to be RFC compliant.
 */
public class RecordsTest {
    @Test
    public void testARecord() throws Exception {
        A a = new A(new byte[]{127, 0, 0, 1});
        assertEquals("127.0.0.1", a.toString());
        Assert.assertEquals(Record.TYPE.A, a.getType());
        byte[] ab = a.toByteArray();
        a = new A(new DataInputStream(new ByteArrayInputStream(ab)), ab, ab.length);
        assertArrayEquals(new byte[]{127, 0, 0, 1}, a.ip);
        try {
            new A(new byte[42]);
            assertTrue("Exception thrown", false);
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCnameRecord() throws Exception {
        CNAME cname = new CNAME("www.example.com");
        assertEquals("www.example.com.", cname.toString());
        assertEquals(Record.TYPE.CNAME, cname.getType());
        byte[] cnameb = cname.toByteArray();
        cname = new CNAME(new DataInputStream(new ByteArrayInputStream(cnameb)), cnameb, cnameb.length);
        assertEquals("www.example.com", cname.name);
    }

    @Test
    public void testDnskeyRecord() throws Exception {
        DNSKEY dnskey = new DNSKEY(DNSKEY.FLAG_ZONE, (byte) 3, (byte) 1, new byte[]{42});
        // TODO: Compare with real Base64 once done
        assertEquals("256 3 1 " + Base64.encodeToString(dnskey.key), dnskey.toString());
        assertEquals(Record.TYPE.DNSKEY, dnskey.getType());
        byte[] dnskeyb = dnskey.toByteArray();
        dnskey = new DNSKEY(new DataInputStream(new ByteArrayInputStream(dnskeyb)), dnskeyb, dnskeyb.length);
        assertEquals(256, dnskey.flags);
        assertEquals(3, dnskey.protocol);
        assertEquals(1, dnskey.algorithm);
        assertArrayEquals(new byte[]{42}, dnskey.key);
    }

    @Test
    public void testDsRecord() throws Exception {
        DS ds = new DS(42, (byte) 8, (byte) 2, new byte[]{0x13, 0x37});
        assertEquals("42 8 2 1337", ds.toString());
        assertEquals(Record.TYPE.DS, ds.getType());
        byte[] dsb = ds.toByteArray();
        ds = new DS(new DataInputStream(new ByteArrayInputStream(dsb)), dsb, dsb.length);
        assertEquals(42, ds.keyTag);
        assertEquals(8, ds.algorithm);
        assertEquals(2, ds.digestType);
        assertArrayEquals(new byte[]{0x13, 0x37}, ds.digest);
    }

    @Test
    public void testMxRecord() throws Exception {
        MX mx = new MX(10, "mx.example.com");
        assertEquals("10 mx.example.com.", mx.toString());
        assertEquals(Record.TYPE.MX, mx.getType());
        byte[] mxb = mx.toByteArray();
        mx = new MX(new DataInputStream(new ByteArrayInputStream(mxb)), mxb, mxb.length);
        assertEquals(10, mx.priority);
        assertEquals("mx.example.com", mx.name);
    }

    @Test
    public void testPtrRecord() throws Exception {
        PTR ptr = new PTR("ptr.example.com");
        assertEquals("ptr.example.com.", ptr.toString());
        assertEquals(Record.TYPE.PTR, ptr.getType());
        byte[] ptrb = ptr.toByteArray();
        ptr = new PTR(new DataInputStream(new ByteArrayInputStream(ptrb)), ptrb, ptrb.length);
        assertEquals("ptr.example.com", ptr.name);
    }

    @Test
    public void testRrsigRecord() throws Exception {
        RRSIG rrsig = new RRSIG(Record.TYPE.A, (byte) 8, (byte) 2, 3600, new Date(1000), new Date(0), 42, "example.com", new byte[]{42});
        // TODO: Compare with real Base64 once done
        assertEquals("A 8 2 3600 19700101000001 19700101000000 42 example.com. " + Base64.encodeToString(rrsig.signature), rrsig.toString());
        assertEquals(Record.TYPE.RRSIG, rrsig.getType());
        byte[] rrsigb = rrsig.toByteArray();
        rrsig = new RRSIG(new DataInputStream(new ByteArrayInputStream(rrsigb)), rrsigb, rrsigb.length);
        assertEquals(Record.TYPE.A, rrsig.typeCovered);
        assertEquals(8, rrsig.algorithm);
        assertEquals(2, rrsig.labels);
        assertEquals(3600, rrsig.originalTtl);
        assertEquals(new Date(1000), rrsig.signatureExpiration);
        assertEquals(new Date(0), rrsig.signatureInception);
        assertEquals(42, rrsig.keyTag);
        assertEquals("example.com", rrsig.signerName);
        assertArrayEquals(new byte[]{42}, rrsig.signature);
    }

    @Test
    public void testSoaRecord() throws Exception {
        SOA soa = new SOA("sns.dns.icann.org", "noc.dns.icann.org", 2015060341, 7200, 3600, 1209600, 3600);
        assertEquals("sns.dns.icann.org. noc.dns.icann.org. 2015060341 7200 3600 1209600 3600", soa.toString());
        assertEquals(Record.TYPE.SOA, soa.getType());
        byte[] soab = soa.toByteArray();
        soa = new SOA(new DataInputStream(new ByteArrayInputStream(soab)), soab, soab.length);
        assertEquals("sns.dns.icann.org", soa.mname);
        assertEquals("noc.dns.icann.org", soa.rname);
        assertEquals(2015060341, soa.serial);
        assertEquals(7200, soa.refresh);
        assertEquals(3600, soa.retry);
        assertEquals(1209600, soa.expire);
        assertEquals(3600, soa.minimum);
    }

    @Test
    public void testSrvRecord() throws Exception {
        SRV srv = new SRV(30, 31, 5222, "hermes.jabber.org");
        assertEquals("30 31 5222 hermes.jabber.org.", srv.toString());
        assertEquals(Record.TYPE.SRV, srv.getType());
        byte[] srvb = srv.toByteArray();
        srv = new SRV(new DataInputStream(new ByteArrayInputStream(srvb)), srvb, srvb.length);
        assertEquals(30, srv.priority);
        assertEquals(31, srv.weight);
        assertEquals(5222, srv.port);
        assertEquals("hermes.jabber.org", srv.name);
    }
}
