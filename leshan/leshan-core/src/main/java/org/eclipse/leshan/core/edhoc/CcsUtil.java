/*******************************************************************************
 * Copyright (c) 2026 RISE and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Rikard Höglund (RISE) - initial implementation
 *******************************************************************************/
package org.eclipse.leshan.core.edhoc;

import java.util.Arrays;

/**
 * Helpers for CWT Claims Sets (CCS) used as EDHOC credentials.
 */
public final class CcsUtil {

    private static final long CLAIM_CNF = 8;
    private static final long CNF_COSE_KEY = 1;
    private static final long COSE_KEY_D = -4;

    private CcsUtil() {
    }

    /**
     * Removes the private key (COSE key parameter -4) from the COSE key in a CCS (claim 8 / key 1).
     * <p>
     * The removal is done on the encoded bytes: all other bytes are kept exactly as given, in particular the order of
     * map entries. EDHOC uses the credential bytes as they are (CRED_x in the transcript hashes, MACs and signatures),
     * so the result must be identical to the public CCS the peer was given. Decoding and re-encoding the CCS with a
     * CBOR library could reorder the map entries.
     *
     * @param ccs the CCS, possibly containing the private key
     * @return the CCS without the private key, or a copy of the input if it has none
     * @throws IllegalArgumentException if the CCS is not a well-formed CBOR map with a COSE key in claim 8 / key 1, or
     *         uses indefinite-length items
     */
    public static byte[] removePrivateKey(byte[] ccs) {
        if (ccs == null || ccs.length == 0)
            throw new IllegalArgumentException("CCS is empty");
        Reader r = new Reader(ccs);

        // Find claim 8 (cnf), then key 1 (COSE_Key) in it
        r.pos = findMapValue(r, CLAIM_CNF, "CCS");
        if (r.pos < 0)
            throw new IllegalArgumentException("CCS has no confirmation claim (claim 8)");
        r.pos = findMapValue(r, CNF_COSE_KEY, "CCS claim 8");
        if (r.pos < 0)
            throw new IllegalArgumentException("CCS has no COSE key (claim 8 / key 1)");

        // Find the -4 entry in the COSE_Key map
        int headerStart = r.pos;
        long count = r.readHeader(5, "COSE key");
        int headerEnd = r.pos;
        for (long i = 0; i < count; i++) {
            int entryStart = r.pos;
            Long key = r.readIntKey();
            r.skip();
            if (key != null && key == COSE_KEY_D) {
                int entryEnd = r.pos;
                // Skip the remaining entries, to check that the COSE key is well-formed
                for (long j = i + 1; j < count; j++) {
                    r.skip();
                    r.skip();
                }
                byte[] newHeader = encodeHeader(5, count - 1);
                byte[] out = new byte[ccs.length - (headerEnd - headerStart) + newHeader.length
                        - (entryEnd - entryStart)];
                int o = 0;
                System.arraycopy(ccs, 0, out, o, headerStart);
                o += headerStart;
                System.arraycopy(newHeader, 0, out, o, newHeader.length);
                o += newHeader.length;
                System.arraycopy(ccs, headerEnd, out, o, entryStart - headerEnd);
                o += entryStart - headerEnd;
                System.arraycopy(ccs, entryEnd, out, o, ccs.length - entryEnd);
                return out;
            }
        }
        return Arrays.copyOf(ccs, ccs.length);
    }

    /**
     * Reads the map at the reader's position and returns the position of the value for the given integer key, or -1.
     */
    private static int findMapValue(Reader r, long wantedKey, String what) {
        long count = r.readHeader(5, what);
        for (long i = 0; i < count; i++) {
            Long key = r.readIntKey();
            if (key != null && key == wantedKey)
                return r.pos;
            r.skip();
        }
        return -1;
    }

    private static byte[] encodeHeader(int major, long value) {
        int mt = major << 5;
        if (value < 24)
            return new byte[] { (byte) (mt | value) };
        if (value < 0x100)
            return new byte[] { (byte) (mt | 24), (byte) value };
        if (value < 0x10000)
            return new byte[] { (byte) (mt | 25), (byte) (value >> 8), (byte) value };
        return new byte[] { (byte) (mt | 26), (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
                (byte) value };
    }

    /** Minimal reader of definite-length CBOR items. */
    private static class Reader {
        private final byte[] data;
        private int pos;
        private int major;

        Reader(byte[] data) {
            this.data = data;
        }

        private int next() {
            if (pos >= data.length)
                throw new IllegalArgumentException("CCS is truncated (not valid CBOR)");
            return data[pos++] & 0xff;
        }

        /** Reads an item header, sets {@link #major} and returns its argument (value, length or count). */
        private long header() {
            int b = next();
            major = b >> 5;
            int ai = b & 0x1f;
            if (ai < 24)
                return ai;
            int n;
            switch (ai) {
            case 24:
                n = 1;
                break;
            case 25:
                n = 2;
                break;
            case 26:
                n = 4;
                break;
            case 27:
                n = 8;
                break;
            case 31:
                throw new IllegalArgumentException("CCS uses indefinite-length CBOR items, which are not supported");
            default:
                throw new IllegalArgumentException("CCS is not valid CBOR");
            }
            long v = 0;
            for (int i = 0; i < n; i++)
                v = (v << 8) | next();
            if (v < 0)
                throw new IllegalArgumentException("CCS contains a too large CBOR value");
            return v;
        }

        long readHeader(int expectedMajor, String what) {
            long v = header();
            if (major != expectedMajor)
                throw new IllegalArgumentException(what + " is not a CBOR map");
            return v;
        }

        /** Reads a map key; returns its value if it is an integer, otherwise skips it and returns null. */
        Long readIntKey() {
            int start = pos;
            long v = header();
            if (major == 0)
                return v;
            if (major == 1)
                return -1 - v;
            pos = start;
            skip();
            return null;
        }

        /** Skips one complete item. */
        void skip() {
            long v = header();
            switch (major) {
            case 2:
            case 3:
                if (v > data.length - pos)
                    throw new IllegalArgumentException("CCS is truncated (not valid CBOR)");
                pos += (int) v;
                break;
            case 4:
                for (long i = 0; i < v; i++)
                    skip();
                break;
            case 5:
                for (long i = 0; i < v; i++) {
                    skip();
                    skip();
                }
                break;
            case 6:
                skip();
                break;
            default: // 0, 1, 7: no content after the header
                break;
            }
        }
    }
}
