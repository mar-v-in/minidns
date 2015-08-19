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
package de.measite.minidns.source;

import de.measite.minidns.DNSMessage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class NetworkDataSource extends DNSDataSource {
    public static final int CONNECTION_LIFETIME = 2000;
    private Map<InetAddress, Socket> openedConnections = new ConcurrentHashMap<>();
    private Map<InetAddress, Long> connectionUsage = new ConcurrentHashMap<>();
    private int maxOpenedConnections = 10;
    private Runnable closer = new Runnable() {
        @Override
        public void run() {
            synchronized (this) {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        wait(1000);
                        int destroy = openedConnections.size() - maxOpenedConnections;
                        for (Iterator<Map.Entry<InetAddress, Long>> iterator = connectionUsage.entrySet().iterator(); iterator.hasNext(); ) {
                            Map.Entry<InetAddress, Long> entry = iterator.next();
                            if (entry.getValue() < System.currentTimeMillis() - CONNECTION_LIFETIME) {
                                try {
                                    openedConnections.get(entry.getKey()).close();
                                    destroy--;
                                } catch (IOException ignored) {
                                }
                                openedConnections.remove(entry.getKey());
                                iterator.remove();
                            }
                        }
                        while (destroy > 0) {
                            InetAddress oldest = null;
                            long oldestUsage = Long.MAX_VALUE;
                            for (Map.Entry<InetAddress, Long> entry : connectionUsage.entrySet()) {
                                if (entry.getValue() < oldestUsage) oldest = entry.getKey();
                            }
                            try {
                                openedConnections.get(oldest).close();
                                destroy--;
                            } catch (IOException ignored) {
                            }
                            openedConnections.remove(oldest);
                            connectionUsage.remove(oldest);
                        }
                        if (openedConnections.isEmpty()) {
                            closerThread = null;
                            return;
                        }
                    }
                } catch (InterruptedException e) {
                    // Shutdown
                }
            }
        }
    };
    private Thread closerThread;

    public DNSMessage query(DNSMessage message, InetAddress address, int port) {
        DNSMessage dnsMessage = null;
        if (openedConnections.containsKey(address)) {
            System.out.println("Reusing connection to " + address);
            Socket socket = openedConnections.get(address);
            connectionUsage.put(address, System.currentTimeMillis());
            try {
                return querySocket(message, socket);
            } catch (IOException ignored) {
            }
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            System.out.println("Reusing connection to " + address+" failed!");
            openedConnections.remove(address);
            connectionUsage.remove(address);
        }

        try {
            dnsMessage = queryUdp(message, address, port);
        } catch (IOException ignored) {
        }

        if (dnsMessage == null || dnsMessage.isTruncated()) {
            try {
                dnsMessage = queryTcp(message, address, port);
            } catch (IOException ignored) {
            }
        }

        return dnsMessage;
    }

    protected DNSMessage queryUdp(DNSMessage message, InetAddress address, int port) throws IOException {
        byte[] buf = message.toArray();
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(buf, buf.length,
                    address, port);
            socket.setSoTimeout(timeout);
            socket.send(packet);
            packet = new DatagramPacket(new byte[bufferSize], bufferSize);
            socket.receive(packet);
            DNSMessage dnsMessage = new DNSMessage(packet.getData());
            if (dnsMessage.getId() != message.getId()) {
                return null;
            }
            return dnsMessage;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    protected DNSMessage queryTcp(DNSMessage message, InetAddress address, int port) throws IOException {
        // TODO Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        Socket socket = null;
        try {
            socket = new Socket(address, port);
            socket.setSoTimeout(timeout);
            connectionUsage.put(address, System.currentTimeMillis());
            openedConnections.put(address, socket);
            if (closerThread == null) {
                closerThread = new Thread(closer);
                closerThread.start();
            }
            return querySocket(message, socket);
        } catch (IOException e) {
            if (socket != null) {
                socket.close();
                openedConnections.remove(address);
                connectionUsage.remove(address);
            }
            throw e;
        }
    }

    private DNSMessage querySocket(DNSMessage message, Socket socket) throws IOException {
        byte[] buf = message.toArray();
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeShort(buf.length);
        dos.write(buf);
        dos.flush();
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        int length = dis.readUnsignedShort();
        byte[] data = new byte[length];
        int read = 0;
        while (read < length) {
            read += dis.read(data, read, length - read);
        }
        DNSMessage dnsMessage = new DNSMessage(data);
        if (dnsMessage.getId() != message.getId()) {
            return null;
        }
        return dnsMessage;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (closerThread != null) closerThread.interrupt();
        for (Iterator<Map.Entry<InetAddress, Socket>> iterator = openedConnections.entrySet().iterator(); iterator.hasNext(); ) {
            Map.Entry<InetAddress, Socket> entry = iterator.next();
            try {
                entry.getValue().close();
            } catch (IOException ignored) {
            }
            iterator.remove();
            connectionUsage.remove(entry.getKey());
        }
    }
}
