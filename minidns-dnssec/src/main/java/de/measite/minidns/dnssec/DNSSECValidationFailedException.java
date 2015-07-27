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

import de.measite.minidns.Question;

public class DNSSECValidationFailedException extends RuntimeException {
    private static final long serialVersionUID = 5413184667629832742L;

    public DNSSECValidationFailedException(Question question, String reason) {
        super("Validation of request to " + question + " failed: " + reason);
    }

    public DNSSECValidationFailedException(String message) {
        super(message);
    }

    public DNSSECValidationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
