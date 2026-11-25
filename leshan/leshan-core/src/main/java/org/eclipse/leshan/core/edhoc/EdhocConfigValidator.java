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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.eclipse.leshan.core.util.Hex;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Lightweight validation of an EDHOC configuration (the fields of the LwM2M EDHOC object), shared by the Bootstrap
 * Server, the Device Manager and the Client.
 * <p>
 * Only the structure is checked (required fields, method and cipher suite values, CCS / COSE key structure, key type,
 * curve and lengths matching the cipher suite and method). No key objects are built and no cryptographic operation is
 * done, so the cost is a CBOR decoding of the credentials.
 * <p>
 * The client is always the EDHOC Initiator and the server (BS or DM) the Responder. In the EDHOC object, the "Client"
 * fields describe the client's credential and the "Peer" fields the server's credential.
 */
public final class EdhocConfigValidator {

    /** Which side the EDHOC object is used on, i.e. whose private key must be present. */
    public enum Mode {
        /**
         * EDHOC object used by a server (BS or DM) for one client. The server's private key must be included in the
         * Peer Public Key CCS (COSE key parameter -4).
         */
        SERVER,
        /** EDHOC object used by the client. The client's private key must be present. */
        CLIENT,
        /**
         * EDHOC object the BS writes to the client for another server (e.g. the DM). The client fields may be empty, as
         * the client can fill them from its own configuration (command line).
         */
        WRITTEN_TO_CLIENT,
        /**
         * Only the client's own credentials (e.g. from the client command line), without method, cipher suite or peer
         * information. All fields are optional, but those given must be consistent.
         */
        CLIENT_CREDENTIALS_ONLY
    }

    // Field names as used in the web interfaces
    public static final String METHOD = "Method";
    public static final String CIPHER_SUITE = "Selected Ciphersuite";
    public static final String CLIENT_KEY_ID = "Client Key Identifier";
    public static final String CLIENT_PUBLIC_KEY = "Client Public Key";
    public static final String PRIVATE_KEY = "Private Key";
    public static final String PEER_KEY_ID = "Peer Public Key Identifier";
    public static final String PEER_PUBLIC_KEY = "Peer Public Key";

    // COSE key parameters (RFC 9052/9053) and CCS claim labels (RFC 8392/8747)
    private static final int CCS_CLAIM_CNF = 8;
    private static final int CNF_COSE_KEY = 1;
    private static final int KTY = 1;
    private static final int KID = 2;
    private static final int CRV = -1;
    private static final int X = -2;
    private static final int Y = -3;
    private static final int D = -4;
    private static final int KTY_OKP = 1;
    private static final int KTY_EC2 = 2;
    private static final int CRV_P256 = 1;
    private static final int CRV_X25519 = 4;
    private static final int CRV_ED25519 = 6;
    private static final int KEY_LENGTH = 32;

    /** Result of a validation: errors (configuration unusable) and warnings (usable, but probably not intended). */
    public static final class Result {
        private final List<String> errors = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();

        public boolean isValid() {
            return errors.isEmpty();
        }

        public List<String> getErrors() {
            return Collections.unmodifiableList(errors);
        }

        public List<String> getWarnings() {
            return Collections.unmodifiableList(warnings);
        }

        /** The errors as one message, one per line, each prefixed with the given context. */
        public String errorMessage(String context) {
            return join(context, errors);
        }

        /** The warnings as one message, one per line, each prefixed with the given context. */
        public String warningMessage(String context) {
            return join(context, warnings);
        }

        private static String join(String context, List<String> lines) {
            StringBuilder sb = new StringBuilder();
            for (String line : lines) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                if (context != null && !context.isEmpty()) {
                    sb.append(context).append(": ");
                }
                sb.append(line);
            }
            return sb.toString();
        }

        void error(String field, String message) {
            errors.add(field + ": " + message);
        }

        void warning(String field, String message) {
            warnings.add(field + ": " + message);
        }
    }

    /** The parts of a CCS needed for validation */
    private static final class CoseKey {
        CBORObject map;
    }

    private EdhocConfigValidator() {
    }

    /**
     * Validates an EDHOC configuration.
     *
     * @param mode on which side the configuration is used
     * @param method the authentication method (may be null in {@link Mode#CLIENT_CREDENTIALS_ONLY})
     * @param cipherSuite the selected cipher suite (may be null in {@link Mode#CLIENT_CREDENTIALS_ONLY})
     * @param clientKeyId the Client Key Identifier
     * @param clientPublicKey the Client Public Key (a CCS)
     * @param privateKey the client's private key (raw, 32 bytes); not used in {@link Mode#SERVER}
     * @param peerKeyId the Peer Public Key Identifier (the server's)
     * @param peerPublicKey the Peer Public Key (a CCS; in {@link Mode#SERVER} including the server's private key)
     * @return the validation result, never null
     */
    public static Result validate(Mode mode, Long method, Long cipherSuite, byte[] clientKeyId,
            byte[] clientPublicKey, byte[] privateKey, byte[] peerKeyId, byte[] peerPublicKey) {
        Result result = new Result();
        boolean credentialsOnly = mode == Mode.CLIENT_CREDENTIALS_ONLY;

        // Method and cipher suite
        boolean methodOk = checkRange(result, METHOD, method, 0, 3, !credentialsOnly);
        boolean suiteOk = checkRange(result, CIPHER_SUITE, cipherSuite, 0, 3, !credentialsOnly);

        // Client credential (the Initiator's)
        boolean clientRequired = mode == Mode.SERVER || mode == Mode.CLIENT;
        checkKeyId(result, CLIENT_KEY_ID, clientKeyId, clientRequired);
        CoseKey clientKey = parseCcs(result, CLIENT_PUBLIC_KEY, clientPublicKey, clientRequired);
        if (clientKey != null) {
            if (methodOk && suiteOk) {
                checkKeyTypeAndCurve(result, CLIENT_PUBLIC_KEY, clientKey.map, true, method.intValue(),
                        cipherSuite.intValue());
            }
            checkKidMatches(result, CLIENT_PUBLIC_KEY, CLIENT_KEY_ID, clientKey.map, clientKeyId);
        }

        // Client private key
        if (mode != Mode.SERVER) {
            boolean inCcs = clientKey != null && clientKey.map.ContainsKey(CBORObject.FromObject(D));
            boolean given = privateKey != null && privateKey.length > 0;
            if (given) {
                if (privateKey.length != KEY_LENGTH) {
                    result.error(PRIVATE_KEY, "must be " + KEY_LENGTH + " bytes, but is " + privateKey.length);
                }
            } else if (mode == Mode.CLIENT && !inCcs) {
                result.error(PRIVATE_KEY, "is missing (the client needs its own private key)");
            }
            if ((given || inCcs) && clientPublicKey == null && mode != Mode.WRITTEN_TO_CLIENT) {
                result.error(CLIENT_PUBLIC_KEY, "is missing, but a private key is given");
            }
        }

        // Peer credential (the server's, i.e. the Responder's)
        if (!credentialsOnly) {
            checkKeyId(result, PEER_KEY_ID, peerKeyId, true);
            CoseKey peerKey = parseCcs(result, PEER_PUBLIC_KEY, peerPublicKey, true);
            if (peerKey != null) {
                if (methodOk && suiteOk) {
                    checkKeyTypeAndCurve(result, PEER_PUBLIC_KEY, peerKey.map, false, method.intValue(),
                            cipherSuite.intValue());
                }
                checkKidMatches(result, PEER_PUBLIC_KEY, PEER_KEY_ID, peerKey.map, peerKeyId);
                boolean hasPrivate = peerKey.map.ContainsKey(CBORObject.FromObject(D));
                if (mode == Mode.SERVER) {
                    if (!hasPrivate) {
                        result.error(PEER_PUBLIC_KEY,
                                "must include the server's private key (COSE key parameter -4), as the server needs it");
                    } else {
                        checkLength(result, PEER_PUBLIC_KEY, peerKey.map, D, "private key (-4)");
                    }
                } else if (hasPrivate) {
                    result.warning(PEER_PUBLIC_KEY,
                            "includes a private key (COSE key parameter -4); the client does not need the server's private key");
                }
            }
        }
        return result;
    }

    private static boolean checkRange(Result result, String field, Long value, int min, int max, boolean required) {
        if (value == null) {
            if (required) {
                result.error(field, "is missing");
            }
            return false;
        }
        if (value < min || value > max) {
            result.error(field, value + " is not supported (supported: " + min + "-" + max + ")");
            return false;
        }
        return true;
    }

    private static void checkKeyId(Result result, String field, byte[] kid, boolean required) {
        if (kid == null || kid.length == 0) {
            if (required) {
                result.error(field, "is missing");
            }
        }
    }

    /** Decode a CCS and return its COSE key, or null (with an error added) if the structure is wrong. */
    private static CoseKey parseCcs(Result result, String field, byte[] ccsBytes, boolean required) {
        if (ccsBytes == null || ccsBytes.length == 0) {
            if (required) {
                result.error(field, "is missing");
            }
            return null;
        }
        CBORObject ccs;
        try {
            ccs = CBORObject.DecodeFromBytes(ccsBytes);
        } catch (RuntimeException e) {
            result.error(field, "is not valid CBOR (" + e.getMessage() + ")");
            return null;
        }
        if (ccs.getType() != CBORType.Map) {
            result.error(field, "is not a CCS (CBOR map expected)");
            return null;
        }
        CBORObject cnf = ccs.get(CBORObject.FromObject(CCS_CLAIM_CNF));
        if (cnf == null || cnf.getType() != CBORType.Map) {
            result.error(field, "CCS has no confirmation claim (claim 8 as a map)");
            return null;
        }
        CBORObject coseKey = cnf.get(CBORObject.FromObject(CNF_COSE_KEY));
        if (coseKey == null || coseKey.getType() != CBORType.Map) {
            result.error(field, "CCS has no COSE key (claim 8, key 1 as a map)");
            return null;
        }
        CoseKey key = new CoseKey();
        key.map = coseKey;
        return key;
    }

    /**
     * Check key type, curve and coordinate lengths for the role (client = Initiator, server = Responder), method and
     * cipher suite (RFC 9528: methods 0-3, cipher suites 0-3).
     */
    private static void checkKeyTypeAndCurve(Result result, String field, CBORObject key, boolean initiator,
            int method, int suite) {
        boolean signature = initiator ? (method == 0 || method == 1) : (method == 0 || method == 2);
        String usage = signature ? "signature" : "static Diffie-Hellman";
        String role = initiator ? "client (Initiator)" : "server (Responder)";

        int expectedKty;
        int expectedCrv;
        String expectedName;
        if (suite == 2 || suite == 3) {
            expectedKty = KTY_EC2;
            expectedCrv = CRV_P256;
            expectedName = "P-256 (EC2)";
        } else if (signature) {
            expectedKty = KTY_OKP;
            expectedCrv = CRV_ED25519;
            expectedName = "Ed25519 (OKP)";
        } else {
            expectedKty = KTY_OKP;
            expectedCrv = CRV_X25519;
            expectedName = "X25519 (OKP)";
        }

        Integer kty = intValue(key.get(CBORObject.FromObject(KTY)));
        Integer crv = intValue(key.get(CBORObject.FromObject(CRV)));
        if (kty == null || crv == null || kty != expectedKty || crv != expectedCrv) {
            result.error(field, "cipher suite " + suite + " with method " + method + " requires a " + expectedName
                    + " key as " + usage + " key of the " + role + ", but the key is " + describe(kty, crv));
            return;
        }
        checkLength(result, field, key, X, "x coordinate (-2)");
        if (expectedKty == KTY_EC2) {
            CBORObject y = key.get(CBORObject.FromObject(Y));
            if (y == null) {
                result.error(field, "P-256 key has no y coordinate (-3)");
            } else if (y.getType() == CBORType.ByteString) {
                checkLength(result, field, key, Y, "y coordinate (-3)");
            }
        }
        if (key.ContainsKey(CBORObject.FromObject(D))) {
            checkLength(result, field, key, D, "private key (-4)");
        }
    }

    private static void checkLength(Result result, String field, CBORObject key, int label, String name) {
        CBORObject value = key.get(CBORObject.FromObject(label));
        if (value == null || value.getType() != CBORType.ByteString) {
            result.error(field, "COSE key has no " + name + " (byte string expected)");
        } else if (value.GetByteString().length != KEY_LENGTH) {
            result.error(field, name + " must be " + KEY_LENGTH + " bytes, but is " + value.GetByteString().length);
        }
    }

    private static void checkKidMatches(Result result, String ccsField, String kidField, CBORObject key, byte[] kid) {
        CBORObject ccsKid = key.get(CBORObject.FromObject(KID));
        if (kid == null || kid.length == 0 || ccsKid == null || ccsKid.getType() != CBORType.ByteString) {
            return;
        }
        if (!Arrays.equals(ccsKid.GetByteString(), kid)) {
            result.warning(kidField, Hex.encodeHexString(kid) + " differs from the kid in the " + ccsField + " ("
                    + Hex.encodeHexString(ccsKid.GetByteString()) + ")");
        }
    }

    private static Integer intValue(CBORObject value) {
        if (value == null || value.getType() != CBORType.Integer) {
            return null;
        }
        try {
            return value.AsInt32();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String describe(Integer kty, Integer crv) {
        String type = kty == null ? "of unknown type" : kty == KTY_OKP ? "OKP" : kty == KTY_EC2 ? "EC2" : "kty " + kty;
        String curve = crv == null ? "no curve"
                : crv == CRV_P256 ? "P-256"
                        : crv == CRV_X25519 ? "X25519" : crv == CRV_ED25519 ? "Ed25519" : "curve " + crv;
        return curve + " (" + type + ")";
    }
}
