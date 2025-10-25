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
package org.eclipse.leshan.server;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.Constants;
import com.upokecenter.cbor.CBORObject;

public class EdhocHandler {

	private static boolean endpointAdded = false;
	private static boolean initiated = false;

	// The asymmetric key pairs of this peer (one per supported curve)
	public static HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();

	// The identifiers of the authentication credentials of this peer
	public static HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

	// The authentication credentials of this peer (one per supported curve)
	public static HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

	// Each element is the ID_CRED_X used for an authentication credential
	// associated to this peer
	public static Set<CBORObject> ownIdCreds = new HashSet<>();

	public static HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	public static HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();

	public static boolean getEndpointAdded() {
		return endpointAdded;
	}

	public static void setEndpointAdded(boolean b) {
		endpointAdded = b;
	}

	public static void init() {
		if (initiated) {
			return;
		}

		System.out.println("Initiating the EDHOC handler");

		// Fill maps
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());

		initiated = true;
	}

}
