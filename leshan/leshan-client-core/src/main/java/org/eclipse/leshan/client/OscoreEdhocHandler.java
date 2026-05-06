/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *     Rikard Höglund (RISE SICS) - Additions to support OSCORE
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.client;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.leshan.client.object.Edhoc;

import com.upokecenter.cbor.CBORObject;

/**
 * Class to hold client config for EDHOC and OSCORE.
 * 
 *
 */
public class OscoreEdhocHandler {

    private static HashMapCtxDB db;
	private static String lwServerUri;
	private static String asServerUri;
	private static ArrayList<Edhoc> asEdhocObjs = new ArrayList<Edhoc>();
	private static boolean edhocWithDmDone;
	private static boolean withEdhoc;

    public static HashMapCtxDB getContextDB() {
        if (db == null) {
            db = new HashMapCtxDB();
        }
        return db;
    }

	public static void setlwServerUri(String toSetlwServerUri) {
		lwServerUri = toSetlwServerUri;
	}

	public static String getlwServerUri() {
		return lwServerUri;
	}

	public static void setAsServerUri(String toSetasServerUri) {
		asServerUri = toSetasServerUri;
	}

	public static String getAsServerUri() {
		return asServerUri;
	}

	public static ArrayList<Edhoc> getAsEdhocObjs() {
		return asEdhocObjs;
	}

	
	public static void setAsEdhocObj(Edhoc asEdhocObj) {
		asEdhocObjs.add(asEdhocObj);
	}

	public static void setEdhocWithDmDone(boolean b) {
		edhocWithDmDone = b;
		
	}

	public static boolean getEdhocWithDmDone() {
		return edhocWithDmDone;
	}
	
	private static Set<CBORObject> usedConnectionIds = new HashSet<>();

	public static Set<CBORObject> getUsedConnectionIds() {

		return usedConnectionIds;
	}

	public static boolean withEdhoc() {
		return withEdhoc;
	}

	public static void setWithEdhoc(boolean b) {
		withEdhoc = b;
	}

	// BS EDHOC peer configuration (set from CLI args)
	private static byte[] bsPeerKeyIdentifier;
	private static byte[] bsPeerPublicKey;
	private static String bsPeerEdhocPath = ".well-known/edhoc";
	private static int bsAuthMethod = 3;
	private static int bsCiphersuite = 2;

	public static byte[] getBsPeerKeyIdentifier() { return bsPeerKeyIdentifier; }
	public static void setBsPeerKeyIdentifier(byte[] b) { bsPeerKeyIdentifier = b; }

	public static byte[] getBsPeerPublicKey() { return bsPeerPublicKey; }
	public static void setBsPeerPublicKey(byte[] b) { bsPeerPublicKey = b; }

	public static String getBsPeerEdhocPath() { return bsPeerEdhocPath; }
	public static void setBsPeerEdhocPath(String p) { bsPeerEdhocPath = p; }

	public static int getBsAuthMethod() { return bsAuthMethod; }
	public static void setBsAuthMethod(int m) { bsAuthMethod = m; }

	public static int getBsCiphersuite() { return bsCiphersuite; }
	public static void setBsCiphersuite(int c) { bsCiphersuite = c; }

}