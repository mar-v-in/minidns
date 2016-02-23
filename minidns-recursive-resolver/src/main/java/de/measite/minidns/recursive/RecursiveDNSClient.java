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
package de.measite.minidns.recursive;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.NS;
import de.measite.minidns.util.MultipleIoException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

public class RecursiveDNSClient extends AbstractDNSClient {

    protected static final InetAddress[] ROOT_SERVERS = new InetAddress[]{
            rootServerInetAddress("a.root-servers.net", new short[]{198, 41, 0, 4}),
            rootServerInetAddress("a.root-servers.net", new int[]{0x2001, 0x503, 0xba3e, 0x0, 0x0, 0x0, 0x2, 0x30}),
            rootServerInetAddress("b.root-servers.net", new short[]{192, 228, 79, 201}),
            rootServerInetAddress("b.root-servers.net", new int[]{0x2001, 0x500, 0x84, 0x0, 0x0, 0x0, 0x0, 0xb}),
            rootServerInetAddress("c.root-servers.net", new short[]{192, 33, 4, 12}),
            rootServerInetAddress("c.root-servers.net", new int[]{0x2001, 0x500, 0x2, 0x0, 0x0, 0x0, 0x0, 0xc}),
            rootServerInetAddress("d.root-servers.net", new short[]{199, 7, 91, 13}),
            rootServerInetAddress("d.root-servers.net", new int[]{0x2001, 0x500, 0x2d, 0x0, 0x0, 0x0, 0x0, 0xd}),
            rootServerInetAddress("e.root-servers.net", new short[]{192, 203, 230, 10}),
            rootServerInetAddress("f.root-servers.net", new short[]{192, 5, 5, 241}),
            rootServerInetAddress("f.root-servers.net", new int[]{0x2001, 0x500, 0x2f, 0x0, 0x0, 0x0, 0x0, 0xf}),
            rootServerInetAddress("g.root-servers.net", new short[]{192, 112, 36, 4}),
            rootServerInetAddress("h.root-servers.net", new short[]{128, 63, 2, 53}),
            rootServerInetAddress("h.root-servers.net", new int[]{0x2001, 0x500, 0x1, 0x0, 0x0, 0x0, 0x0, 0x53}),
            rootServerInetAddress("i.root-servers.net", new short[]{192, 36, 148, 17}),
            rootServerInetAddress("i.root-servers.net", new int[]{0x2001, 0x7fe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53}),
            rootServerInetAddress("j.root-servers.net", new short[]{192, 58, 128, 30}),
            rootServerInetAddress("j.root-servers.net", new int[]{0x2001, 0x503, 0xc27, 0x0, 0x0, 0x0, 0x2, 0x30}),
            rootServerInetAddress("k.root-servers.net", new short[]{193, 0, 14, 129}),
            rootServerInetAddress("k.root-servers.net", new int[]{0x2001, 0x7fd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}),
            rootServerInetAddress("l.root-servers.net", new short[]{199, 7, 83, 42}),
            rootServerInetAddress("l.root-servers.net", new int[]{0x2001, 0x500, 0x3, 0x0, 0x0, 0x0, 0x0, 0x42}),
            rootServerInetAddress("m.root-servers.net", new short[]{202, 12, 27, 33}),
            rootServerInetAddress("m.root-servers.net", new int[]{0x2001, 0xdc3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35}),
    };

    private int maxDepth = 128;

    /**
     * Create a new recursive DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public RecursiveDNSClient(DNSCache cache) {
        super(cache);
    }

    /**
     * Creates a new recursive DNS client that uses the given Map as cache.
     *
     * @param cache the Map to use as cache for DNS results.
     */
    public RecursiveDNSClient(Map<Question, DNSMessage> cache) {
        super(cache);
    }

    /**
     * Recursively query the DNS system for one entry.
     *
     * @param q The question section of the DNS query.
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    @Override
    public DNSMessage query(Question q) throws IOException {
        DNSMessage message = queryRecursive(0, q);
        if (message == null) return null;
        // TODO: restrict to real answer or accept non-answers?
        return message;
    }

    private DNSMessage queryRecursive(int depth, Question q) throws IOException {
        InetAddress target = ROOT_SERVERS[random.nextInt(ROOT_SERVERS.length)];
        return queryRecursive(depth, q, target);
    }

    private DNSMessage queryRecursive(int depth, Question q, InetAddress address) throws IOException {
        if (depth > maxDepth) return null;

        DNSMessage resMessage = query(q, address);

        if (resMessage == null || resMessage.isAuthoritativeAnswer()) {
            return resMessage;
        }
        List<Record> authorities = new ArrayList<>(Arrays.asList(resMessage.getNameserverRecords()));

        List<IOException> ioExceptions = new LinkedList<>();

        // Glued NS first
        for (Iterator<Record> iterator = authorities.iterator(); iterator.hasNext(); ) {
            Record record = iterator.next();
            if (record.type != TYPE.NS) {
                iterator.remove();
                continue;
            }
            String name = ((NS) record.payloadData).name;
            IpResultSet gluedNs = searchAdditional(resMessage, name);
            for (InetAddress target : gluedNs.getAddresses()) {
                DNSMessage recursive = null;
                try {
                    recursive = queryRecursive(depth + 1, q, target);
                } catch (IOException e) {
                   LOGGER.log(Level.FINER, "Exception while recursing", e);
                   ioExceptions.add(e);
                   iterator.remove();
                   continue;
                }
                return recursive;
            }
        }

        // Try non-glued NS
        for (Record record : authorities) {
            String nsName = ((NS) record.payloadData).name;
            if (!(q.name.equals(nsName) && (q.type == TYPE.A || q.type == TYPE.AAAA))) {
                IpResultSet res = null;
                try {
                    res = resolveIpRecursive(depth + 1, nsName);
                } catch (IOException e) {
                    ioExceptions.add(e);
                }
                if (res == null) {
                    continue;
                }

                for (InetAddress target : res.getAddresses()) {
                    DNSMessage recursive = null;
                    try {
                        recursive = queryRecursive(depth + 1, q, target);
                    } catch (IOException e) {
                        ioExceptions.add(e);
                        continue;
                    }
                    return recursive;
                }
            }
        }

        if (!ioExceptions.isEmpty()) {
            throw new MultipleIoException(ioExceptions);
        }

        return null;
    }

    public enum IpVersionSetting {
        v4only,
        v6only,
        v4v6,
        v6v4,
        ;
    }

    private static IpVersionSetting ipVersionSetting = IpVersionSetting.v4v6;

    public static void setPreferedIpVersion(IpVersionSetting preferedIpVersion) {
        if (preferedIpVersion == null) {
            throw new IllegalArgumentException();
        }
        RecursiveDNSClient.ipVersionSetting = preferedIpVersion;
    }

    private IpResultSet resolveIpRecursive(int depth, String name) throws IOException {
        IpResultSet res = new IpResultSet();

        if (ipVersionSetting != IpVersionSetting.v6only) {
            Question question = new Question(name, TYPE.A);
            DNSMessage aMessage = queryRecursive(depth + 1, question);
            if (aMessage != null) {
                for (Record answer : aMessage.getAnswers()) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name, (A) answer.payloadData);
                        res.ipv4Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(depth + 1, ((CNAME) answer.payloadData).name);
                    }
                }
            }
        }

        if (ipVersionSetting != IpVersionSetting.v4only) {
            Question question = new Question(name, TYPE.AAAA);
            DNSMessage aMessage = queryRecursive(depth + 1, question);
            if (aMessage != null) {
                for (Record answer : aMessage.getAnswers()) {
                    if (answer.isAnswer(question)) {
                        InetAddress inetAddress = inetAddressFromRecord(name, (AAAA) answer.payloadData);
                        res.ipv6Addresses.add(inetAddress);
                    } else if (answer.type == TYPE.CNAME && answer.name.equals(name)) {
                        return resolveIpRecursive(depth + 1, ((CNAME) answer.payloadData).name);
                    }
                }
            }
        }

        return res;
    }

    @SuppressWarnings("incomplete-switch")
    private static IpResultSet searchAdditional(DNSMessage message, String name) {
        IpResultSet res = new IpResultSet();
        for (Record record : message.getAdditionalResourceRecords()) {
            if (!record.name.equals(name)) {
                continue;
            }
            switch (record.type) {
            case A:
                res.ipv4Addresses.add(inetAddressFromRecord(name, ((A) record.payloadData)));
                break;
            case AAAA:
                res.ipv6Addresses.add(inetAddressFromRecord(name, ((AAAA) record.payloadData)));
                break;
            }
        }
        return res;
    }

    private static InetAddress inetAddressFromRecord(String name, A recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.ip);
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    private static InetAddress inetAddressFromRecord(String name, AAAA recordPayload) {
        try {
            return InetAddress.getByAddress(name, recordPayload.ip);
        } catch (UnknownHostException e) {
            // This will never happen
            throw new RuntimeException(e);
        }
    }

    private static InetAddress rootServerInetAddress(String name, short[] addr) {
        try {
            return InetAddress.getByAddress(name, new byte[]{(byte) addr[0], (byte) addr[1], (byte) addr[2], (byte) addr[3]});
        } catch (UnknownHostException e) {
            // This should never happen, if it does it's our fault!
            throw new RuntimeException(e);
        }
    }

    private static InetAddress rootServerInetAddress(String name, int[] addr) {
        try {
            return InetAddress.getByAddress(name, new byte[]{
                    (byte) (addr[0] >> 8), (byte) addr[0], (byte) (addr[1] >> 8), (byte) addr[1],
                    (byte) (addr[2] >> 8), (byte) addr[2], (byte) (addr[3] >> 8), (byte) addr[3],
                    (byte) (addr[4] >> 8), (byte) addr[4], (byte) (addr[5] >> 8), (byte) addr[5],
                    (byte) (addr[6] >> 8), (byte) addr[6], (byte) (addr[7] >> 8), (byte) addr[7]
            });
        } catch (UnknownHostException e) {
            // This should never happen, if it does it's our fault!
            throw new RuntimeException(e);
        }
    }

    @Override
    protected boolean isResponseCacheable(Question q, DNSMessage dnsMessage) {
        return dnsMessage.isAuthoritativeAnswer();
    }

    @Override
    protected DNSMessage buildMessage(Question question) {
        DNSMessage message = new DNSMessage();
        message.setQuestions(question);
        message.setRecursionDesired(false);
        message.setId(random.nextInt());
        message.setOptPseudoRecord(dataSource.getUdpPayloadSize(), 0);
        return message;
    }

    private static class IpResultSet {
        final List<InetAddress> ipv4Addresses = new LinkedList<>();
        final List<InetAddress> ipv6Addresses = new LinkedList<>();

        List<InetAddress> getAddresses() {
            int size;
            switch (ipVersionSetting) {
            case v4only:
                size = ipv4Addresses.size();
                break;
            case v6only:
                size = ipv6Addresses.size();
                break;
            case v4v6:
            case v6v4:
            default:
                size = ipv4Addresses.size() + ipv6Addresses.size();
                break;
            }

            List<InetAddress> addresses = new ArrayList<>(size);

            switch (ipVersionSetting) {
            case v4only:
                addresses.addAll(ipv4Addresses);
                break;
            case v6only:
                addresses.addAll(ipv6Addresses);
                break;
            case v4v6:
                addresses.addAll(ipv4Addresses);
                addresses.addAll(ipv6Addresses);
                break;
            case v6v4:
                addresses.addAll(ipv6Addresses);
                addresses.addAll(ipv4Addresses);
                break;
            }
            return addresses;
        }
    }
}
