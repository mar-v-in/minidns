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

import de.measite.minidns.Record.TYPE;
import de.measite.minidns.util.Base32;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * NSEC3 record payload.
 */
public class NSEC3 implements Data {

    /**
     * This Flag indicates whether this NSEC3 RR may cover unsigned
     * delegations.
     */
    public static final byte FLAG_OPT_OUT = 0x1;

    /**
     * The cryptographic hash algorithm used.
     */
    public final byte hashAlgorithm;

    /**
     * Bitmap of flags: {@link #FLAG_OPT_OUT}.
     */
    public final byte flags;

    /**
     * The number of iterations the hash algorithm is applied.
     */
    public final int /* unsigned short */ iterations;

    /**
     * The salt appended to the next owner name before hashing.
     */
    public final byte[] salt;

    /**
     * The next hashed owner name in hash order.
     */
    public final byte[] nextHashed;

    private final byte[] typeBitmap;

    /**
     * The RR types existing at the original owner name.
     */
    public final TYPE[] types;

    public NSEC3(DataInputStream dis, byte[] data, int length) throws IOException {
        hashAlgorithm = dis.readByte();
        flags = dis.readByte();
        iterations = dis.readUnsignedShort();
        int saltLength = dis.readUnsignedByte();
        salt = new byte[saltLength];
        dis.read(salt);
        int hashLength = dis.readUnsignedByte();
        nextHashed = new byte[hashLength];
        dis.read(nextHashed);
        typeBitmap = new byte[length - (6 + saltLength + hashLength)];
        dis.read(typeBitmap);
        types = NSEC.readTypeBitMap(typeBitmap);
    }

    @Override
    public TYPE getType() {
        return TYPE.NSEC3;
    }

    @Override
    public byte[] toByteArray() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeByte(hashAlgorithm);
            dos.writeByte(flags);
            dos.writeShort(iterations);
            dos.writeByte(salt.length);
            dos.write(salt);
            dos.writeByte(nextHashed.length);
            dos.write(nextHashed);
            dos.write(typeBitmap);
        } catch (IOException e) {
            // Should never happen
            throw new IllegalStateException(e);
        }

        return baos.toByteArray();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append(hashAlgorithm).append(' ')
                .append(flags).append(' ')
                .append(iterations).append(' ')
                .append(salt.length == 0 ? "-" : new BigInteger(salt).toString(16)).append(' ')
                .append(Base32.encodeToString(nextHashed));
        for (TYPE type : types) {
            sb.append(' ').append(type.name());
        }
        return sb.toString();
    }
}
