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

import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AlgorithmMapTest {
    /**
     * There is a set of mandatory algorithms that should be supported.
     * If they're not supported by the platform, an exception should be thrown.
     */
    @Test
    public void ensureMandatoryAlgorithmsOrException() {
        try {
            AlgorithmMap algorithmMap = new AlgorithmMap();
            assertNotNull(algorithmMap.getDsDigestCalculator((byte) 1));
            assertNotNull(algorithmMap.getDsDigestCalculator((byte) 2));
            assertNotNull(algorithmMap.getSignatureVerifier((byte) 5));
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof NoSuchAlgorithmException);
        }
    }
}
