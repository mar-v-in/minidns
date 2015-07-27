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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VerifierTest {
    @Test
    public void nsecMatchesTest() {
        assertTrue(Verifier.nsecMatches("example.com", "com", "com"));
        assertTrue(Verifier.nsecMatches("example.com", "e.com", "f.com"));
        assertTrue(Verifier.nsecMatches("example.com", "be", "de"));
        assertFalse(Verifier.nsecMatches("example.com", "example1.com", "example2.com"));
        assertFalse(Verifier.nsecMatches("example.com", "test.com", "xxx.com"));
        assertFalse(Verifier.nsecMatches("example.com", "xxx.com", "test.com"));
        assertFalse(Verifier.nsecMatches("example.com", "aaa.com", "bbb.com"));
    }

    @Test
    public void stripToPartsTest() {
        assertEquals("www.example.com", Verifier.stripToParts("www.example.com", 3));
        assertEquals("example.com", Verifier.stripToParts("www.example.com", 2));
        assertEquals("com", Verifier.stripToParts("www.example.com", 1));
        assertEquals("", Verifier.stripToParts("www.example.com", 0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void stripToPartsTestIllegal() {
        Verifier.stripToParts("", 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void stripToPartsTestIllegalLong() {
        Verifier.stripToParts("example.com", 3);
    }
}
