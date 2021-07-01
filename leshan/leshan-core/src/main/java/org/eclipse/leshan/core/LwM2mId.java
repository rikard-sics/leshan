/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
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
 *     Sierra Wireless - initial API and implementation
 *     Rikard Höglund (RISE SICS) - Additions to support OSCORE
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.core;

/**
 * LWM2M Object/Resource IDs
 */
public interface LwM2mId {

    /* OBJECTS */

    public static final int SECURITY = 0;
    public static final int SERVER = 1;
    public static final int ACCESS_CONTROL = 2;
    public static final int DEVICE = 3;
    public static final int CONNECTIVITY_MONITORING = 4;
    public static final int FIRMWARE = 5;
    public static final int LOCATION = 6;
    public static final int CONNECTIVITY_STATISTICS = 7;
    public static final int SOFTWARE_MANAGEMENT = 9;
    public static final int OSCORE = 21;
    public static final int EDHOC = 99;

    /* SECURITY RESOURCES */

    public static final int SEC_SERVER_URI = 0;
    public static final int SEC_BOOTSTRAP = 1;
    public static final int SEC_SECURITY_MODE = 2;
    public static final int SEC_PUBKEY_IDENTITY = 3;
    public static final int SEC_SERVER_PUBKEY = 4;
    public static final int SEC_SECRET_KEY = 5;
    public static final int SEC_SERVER_ID = 10;
    public static final int SEC_CERTIFICATE_USAGE = 15;
    public static final int SEC_OSCORE_SECURITY_MODE = 17;

    /* OSCORE RESOURCES */

    public static final int OSCORE_Master_Secret = 0;
    public static final int OSCORE_Sender_ID = 1;
    public static final int OSCORE_Recipient_ID = 2;
    public static final int OSCORE_AEAD_Algorithm = 3;
    public static final int OSCORE_HMAC_Algorithm = 4;
    public static final int OSCORE_Master_Salt = 5;

    /* EDHOC RESOURCES */

    public static final int Initiator = 0;
    public static final int Authentication_Method = 1;
    public static final int Ciphersuite = 2;
    public static final int Credential_Identifier = 3;
    public static final int Public_Credential = 4;
    public static final int Private_Key = 5;
    public static final int Server_Credential_Identifier = 6;
    public static final int Server_Public_Key = 7;
    public static final int Oscore_Master_Secret_Length = 8;
    public static final int Oscore_Master_Salt_Length = 9;
    public static final int Edhoc_Oscore_Combined = 10;

    /* SERVER RESOURCES */

    public static final int SRV_SERVER_ID = 0;
    public static final int SRV_LIFETIME = 1;
    public static final int SRV_BINDING = 7;

    /* DEVICE RESOURCES */

    public static final int DVC_SUPPORTED_BINDING = 16;
}