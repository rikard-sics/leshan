/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/

package org.eclipse.californium.edhoc;

import java.nio.charset.Charset;

import org.eclipse.californium.cose.KeyKeys;


/**
 * Constants for use with the EDHOC protocol.
 * 
 * @author Marco Tiloca and Rikard Höglund
 *
 */
public class Constants {

/**
 * Charset for this library
 */
public static final Charset charset = Charset.forName("UTF-8");


/**
 * CoAP Content-Formats
 * https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
 */
public static final int APPLICATION_EDHOC_CBOR_SEQ     = 64; // application/edhoc+cbor-seq
public static final int APPLICATION_CID_EDHOC_CBOR_SEQ = 65; // application/cid-edhoc+cbor-seq


/**
 * COSE Header Parameters
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
public static final int COSE_HEADER_PARAM_KID     =  4;
public static final int COSE_HEADER_PARAM_KCWT    = 13;
public static final int COSE_HEADER_PARAM_KCCS    = 14;
public static final int COSE_HEADER_PARAM_X5CHAIN = 33;
public static final int COSE_HEADER_PARAM_X5T     = 34;
public static final int COSE_HEADER_PARAM_X5U     = 35;

/**
 * COSE Key Common Parameters
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 */
public static final int COSE_KEY_COMMON_PARAM_KTY     = 1;
public static final int COSE_KEY_COMMON_PARAM_KID     = 2;
public static final int COSE_KEY_COMMON_PARAM_ALG     = 3;
public static final int COSE_KEY_COMMON_PARAM_KEY_OPS = 4;
public static final int COSE_KEY_COMMON_PARAM_BASE_IV = 5;

/**
 * COSE Key Type Parameters
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
public static final int COSE_KEY_TYPE_PARAM_CRV = -1;
public static final int COSE_KEY_TYPE_PARAM_X   = -2;
public static final int COSE_KEY_TYPE_PARAM_Y   = -3;

/**
 * COSE Key Types
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
public static final int COSE_KEY_TYPE_OKP = 1;
public static final int COSE_KEY_TYPE_EC2 = 2;

/**
 * COSE Elliptic Curves
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
public static final int CURVE_P256    = KeyKeys.EC2_P256.AsInt32();    // P-256   (1)
public static final int CURVE_X25519  = KeyKeys.OKP_X25519.AsInt32();  // X25519  (4)
public static final int CURVE_Ed25519 = KeyKeys.OKP_Ed25519.AsInt32(); // Ed25519 (6)

/**
 * CBOR Web Token (CWT) Claims
 * 
 * https://www.iana.org/assignments/cwt/cwt.xhtml#claims-registry
 */
public static final int CWT_CLAIMS_SUB = 2;
public static final int CWT_CLAIMS_EXP = 4;
public static final int CWT_CLAIMS_CNF = 8;

/**
 * CWT Confirmation Methods
 * 
 * https://www.iana.org/assignments/cwt/cwt.xhtml#confirmation-methods
 */
public static final int CWT_CNF_COSE_KEY = 1;


/**
 * Labels for EDHOC_Exporter
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-exporter-labels
 */
public static final int EXPORTER_LABEL_OSCORE_MASTER_SECRET = 0;
public static final int EXPORTER_LABEL_OSCORE_MASTER_SALT   = 1;
public static final int EXPORTER_LABEL_RESERVED             = 23;

/**
 * EDHOC Cipher Suites
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-cipher-suites
 * 
 * - EDHOC AEAD algorithm
 * - EDHOC hash algorithm
 * - EDHOC MAC length in bytes (Static DH)
 * - EDHOC key exchange algorithm (ECDH curve)
 * - EDHOC signature algorithm
 * - Application AEAD algorithm 
 * - Application hash algorithm 
 * 
 * Value: 0
 * Array: 10, -16, 8, 4, -8, 10, -16
 * Desc: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA,
 *       AES-CCM-16-64-128, SHA-256
   
 * Value: 1
 * Array: 30, -16, 16 ,4, -8, 10, -16
 * Desc: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA,
 *       AES-CCM-16-64-128, SHA-256

 * Value: 2
 * Array: 10, -16, 8, 1, -7, 10, -16
 * Desc: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256,
 *       AES-CCM-16-64-128, SHA-256

 * Value: 3
 * Array: 30, -16, 16, 1, -7, 10, -16
 * Desc: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256,
 *       AES-CCM-16-64-128, SHA-256
 * 
 */
public static final int EDHOC_CIPHER_SUITE_0 = 0;
public static final int EDHOC_CIPHER_SUITE_1 = 1;
public static final int EDHOC_CIPHER_SUITE_2 = 2;
public static final int EDHOC_CIPHER_SUITE_3 = 3;


/**
 * EDHOC Method Types
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-method-types
 * 
 * +-------+---------------+---------------+
 * | Value | Initiator     | Responder     |
 * +-------+---------------+---------------|
 * |   0   | Signature Key | Signature Key |
 * |   1   | Signature Key | Static DH Key |
 * |   2   | Static DH Key | Signature Key |
 * |   3   | Static DH Key | Static DH Key |
 * +-------+---------------+---------------+
 * 
 */
public static final int EDHOC_AUTH_METHOD_0        = 0;
public static final int EDHOC_AUTH_METHOD_1        = 1;
public static final int EDHOC_AUTH_METHOD_2        = 2;
public static final int EDHOC_AUTH_METHOD_3        = 3;
public static final int EDHOC_AUTH_METHOD_RESERVED = 23;


/**
 * EDHOC Error Codes
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-error-codes
 */
public static final int ERR_CODE_SUCCESS                       = 0;
public static final int ERR_CODE_UNSPECIFIED_ERROR             = 1;
public static final int ERR_CODE_WRONG_SELECTED_CIPHER_SUITE   = 2;
public static final int ERR_CODE_UNKNOWN_CREDENTIAL_REFERENCED = 3;
public static final int ERR_CODE_RESERVED                      = 23;


/**
 * EDHOC External Authorization Data
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-ead
 */
public static final int EAD_LABEL_PADDING  = 0;
public static final int EAD_LABEL_RESERVED = 23;


/**
 * EDHOC Authentication Credential Types
 * 
 * https://www.iana.org/assignments/edhoc/edhoc.xhtml#edhoc-authentication-credential-types
 */
public static final int CRED_TYPE_CWT  = 0; // RPK as a CWT
public static final int CRED_TYPE_CCS  = 1; // RPK as a CWT Claims Set (CCS)
public static final int CRED_TYPE_X509 = 2; // X.509 certificate


/**
 * The EDHOC AEAD algorithms associated to each cipher suite
 */
public static final String[] EDHOC_AEAD_ALGS = {
		"AES_CCM_16_64_128",   // cipher suite 0
		"AES_CCM_16_128_128",  // cipher suite 1
		"AES_CCM_16_64_128",   // cipher suite 2
		"AES_CCM_16_128_128"   // cipher suite 3
};

/**
 * The EDHOC hash algorithms associated to each cipher suite
 */
public static final String[] EDHOC_HASH_ALGS = {
		"SHA-256",  // cipher suite 0
		"SHA-256",  // cipher suite 1
		"SHA-256",  // cipher suite 2
		"SHA-256",  // cipher suite 3
};

/**
 * The EDHOC key exchange algorithm (ECDH curve) associated to each cipher suite
 */
public static final String[] EDHOC_ECDH_CURVES = {
		"X25519",  // cipher suite 0
		"X25519",  // cipher suite 1
		"P-256",   // cipher suite 2
		"P-256",   // cipher suite 3
};

/**
 * The EDHOC signature algorithms associated to each cipher suite
 */
public static final String[] EDHOC_SIGN_ALGS = {
		"EdDSA",  // cipher suite 0
		"EdDSA",  // cipher suite 1
		"ES256",  // cipher suite 2
		"ES256",  // cipher suite 3
};

/**
 * The EDHOC signature curve associated to each cipher suite
 * 
 * This is implicitly assumed from the pair EDHOC key exchange algorithm
 * (ECDH curve) and EDHOC signature algorithm for a certain cipher suite 
 */
public static final String[] EDHOC_SIGN_ALG_CURVES = {
		"Ed25519",  // cipher suite 0
		"Ed25519",  // cipher suite 1
		"P-256",    // cipher suite 2
		"P-256",    // cipher suite 3
};

/**
 * The application AEAD algorithms associated to each cipher suite
 */
public static final String[] APP_AEAD_ALGS = {
		"AES_CCM_16_64_128",  // cipher suite 0
		"AES_CCM_16_64_128",  // cipher suite 1
		"AES_CCM_16_64_128",  // cipher suite 2
		"AES_CCM_16_64_128"   // cipher suite 3
};

/**
 * The application hash algorithms associated to each cipher suite
 */
public static final String[] APP_HASH_ALGS = {
		"SHA-256",  // cipher suite 0
		"SHA-256",  // cipher suite 1
		"SHA-256",  // cipher suite 2
		"SHA-256",  // cipher suite 3
};


/**
 * EDHOC Message Types
 */
public static final int EDHOC_ERROR_MESSAGE = 0;
public static final int EDHOC_MESSAGE_1     = 1;
public static final int EDHOC_MESSAGE_2     = 2;
public static final int EDHOC_MESSAGE_3     = 3;
public static final int EDHOC_MESSAGE_4     = 4;


/**
 * Labels for EDHOC_KDF
 * 
 * https://www.rfc-editor.org/rfc/rfc9528.html#figure-6
 */
public static final int KDF_LABEL_KEYSTREAM_2        = 0;
public static final int KDF_LABEL_SALT_3E2M          = 1;
public static final int KDF_LABEL_MAC_2              = 2;
public static final int KDF_LABEL_K_3                = 3;
public static final int KDF_LABEL_IV_3               = 4;
public static final int KDF_LABEL_SALT_4E3M          = 5;
public static final int KDF_LABEL_MAC_3              = 6;
public static final int KDF_LABEL_PRK_OUT            = 7;
public static final int KDF_LABEL_K_4                = 8;
public static final int KDF_LABEL_IV_4               = 9;
public static final int KDF_LABEL_PRK_EXPORTER       = 10;
public static final int KDF_LABEL_PRK_OUT_KEY_UPDATE = 11;


/**
 * Temporary keys
 * 
 */
public static final int EDHOC_K_3 = 0;  // Key K_3 for message_3
public static final int EDHOC_K_4 = 1;  // Key K_4 for message_4


/**
 * Temporary IVs
 * 
 */
public static final int EDHOC_IV_3 = 0;  // IV_3 for message_3
public static final int EDHOC_IV_4 = 1;  // IV_4 for message_4


/**
 * Key Usage
 */
public static final int SIGNATURE_KEY = 0;
public static final int ECDH_KEY      = 1;

/**
 * Credential Identifier Type
 */
public static final int ID_CRED_TYPE_KID     = 0; // RPK by reference
public static final int ID_CRED_TYPE_CWT     = 1; // RPK by value (as CWT)
public static final int ID_CRED_TYPE_CCS     = 2; // RPK by value (as CCS)
public static final int ID_CRED_TYPE_X5T     = 3; // X.509 certificate by hash reference
public static final int ID_CRED_TYPE_X5U     = 4; // X.509 certificate by retrieval link
public static final int ID_CRED_TYPE_X5CHAIN = 5; // X.509 certificate by value


/**
 * EDHOC protocol steps
 * 
 */

// Initiator steps
public static final int EDHOC_BEFORE_M1 = 0; // Before preparing/processing EDHOC Message 1
public static final int EDHOC_AFTER_M1  = 1; // After preparing/processing EDHOC Message 1
public static final int EDHOC_SENT_M1   = 2; // After sending EDHOC Message 1

// Responder steps
public static final int EDHOC_BEFORE_M2 = 3; // Before preparing/processing EDHOC Message 2
public static final int EDHOC_SENT_M2   = 4; // After sending EDHOC Message 2

// Common steps
public static final int EDHOC_AFTER_M2  = 5; // After preparing/processing EDHOC Message 2
public static final int EDHOC_AFTER_M3  = 6; // After preparing/processing EDHOC Message 3
public static final int EDHOC_AFTER_M4  = 7; // After preparing/processing EDHOC Message 4

// Initiator steps
public static final int EDHOC_SENT_M3   = 8; // After sending EDHOC Message 3

// Responder steps
public static final int EDHOC_SENT_M4   = 9; // After sending EDHOC Message 4


/**
 * Trust models for verifying authentication credentials of other peers 
 * 
 */
public static final int TRUST_MODEL_NO_LEARNING = 0; // Trust and use an authentication credential only if already stored and still valid.

public static final int TRUST_MODEL_LEARNING    = 1; // Trust and use any (new) authentication credential, as long as it is valid.


/**
 * Side processor objects
 * 
 */

//Results of an EAD item consumption (TODO:redundant to remove?) 
public static final int SIDE_PROCESSOR_CONSUMPTION_ERROR    = -1;
public static final int SIDE_PROCESSOR_CONSUMPTION_SUCCESS  =  0;

//Result maps: outer map keys not associated with EAD labels
public static final int SIDE_PROCESSOR_OUTER_ERROR = -1;
public static final int SIDE_PROCESSOR_OUTER_CRED  =  0;

//Result maps: inner map keys for outer map key -1
public static final int SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION = 0; // Value: the text string to use in the EDHOC error message
public static final int SIDE_PROCESSOR_INNER_ERROR_RESP_CODE =   1; // Value: the response code to use if EDHOC error message is a response

//Result maps: inner map keys for outer map key 0
public static final int SIDE_PROCESSOR_INNER_CRED_VALUE = 0;        // Value: the authentication credential of the other peer

}
