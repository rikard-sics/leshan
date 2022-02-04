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

import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.leshan.client.object.Edhoc;

//TODO OSCORE : remove this class and static access.
public class OscoreHandler {

    private static HashMapCtxDB db;
	private static String lwServerUri;
	private static String asServerUri;
	private static Edhoc asEdhocObj;
	private static boolean edhocWithDmDone;

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

	public static Edhoc getAsEdhocObj() {
		return asEdhocObj;
	}

	
	public static void setAsEdhocObj(Edhoc asEdhocObj) {
		OscoreHandler.asEdhocObj = asEdhocObj;
	}

	public static void setEdhocWithDmDone(boolean b) {
		edhocWithDmDone = b;
		
	}

	public static boolean getEdhocWithDmDone() {
		return edhocWithDmDone;
		
	}

	
}