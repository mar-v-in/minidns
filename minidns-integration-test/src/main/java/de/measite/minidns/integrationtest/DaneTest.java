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
package de.measite.minidns.integrationtest;

import de.measite.minidns.dane.DaneVerifier;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;

public class DaneTest {

    @IntegrationTest
    public static void testVerisignDaneGood() throws IOException {
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://good.dane.verisignlabs.com/").openConnection());
    }

    @IntegrationTest(expected = IOException.class)
    public static void testVerisignDaneBadHash() throws IOException {
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://bad-hash.dane.verisignlabs.com/").openConnection());
    }

    @IntegrationTest
    public static void testVerisignDaneBadParams() throws IOException {
        // This should invoke a warning message but not cause a failure.
        DaneVerifier daneVerifier = new DaneVerifier();
        daneVerifier.verifiedConnect((HttpsURLConnection) new URL("https://bad-params.dane.verisignlabs.com/").openConnection());
    }
}
