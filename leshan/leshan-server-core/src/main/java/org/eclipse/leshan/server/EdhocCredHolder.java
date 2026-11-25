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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.Constants;
import com.upokecenter.cbor.CBORObject;

/**
 * Class store credentials and configuration for EDHOC for this server instance.
 * <p>
 * Thread safety: configs are added on HTTP request threads (possibly many in parallel) while the EDHOC resource reads
 * these collections on CoAP threads. Therefore
 * <ul>
 * <li>all collections are synchronized for single operations ({@link SynchronizedHashMap}, synchronized set), and</li>
 * <li>code that adds credentials or sets up the EDHOC endpoint must hold {@link #LOCK}, so that related updates
 * (e.g. a peer credential and its public key, or the one-time creation of the EDHOC resource) happen together.</li>
 * </ul>
 */
public class EdhocCredHolder {

	/** Lock to hold while adding credentials or setting up the EDHOC endpoint. */
	public static final Object LOCK = new Object();

	private static volatile boolean endpointAdded = false;
	private static boolean initiated = false;

	// The asymmetric key pairs of this peer (one per supported curve)
	public static HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new SynchronizedHashMap<Integer, HashMap<Integer, OneKey>>();

	// The identifiers of the authentication credentials of this peer
	public static HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new SynchronizedHashMap<Integer, HashMap<Integer, CBORObject>>();

	// The authentication credentials of this peer (one per supported curve)
	public static HashMap<Integer, HashMap<Integer, CBORObject>> creds = new SynchronizedHashMap<Integer, HashMap<Integer, CBORObject>>();

	// Each element is the ID_CRED_X used for an authentication credential
	// associated to this peer
	public static Set<CBORObject> ownIdCreds = Collections.synchronizedSet(new HashSet<CBORObject>());

	public static HashMap<CBORObject, OneKey> peerPublicKeys = new SynchronizedHashMap<CBORObject, OneKey>();
	public static HashMap<CBORObject, CBORObject> peerCredentials = new SynchronizedHashMap<CBORObject, CBORObject>();

	public static boolean getEndpointAdded() {
		return endpointAdded;
	}

	public static void setEndpointAdded(boolean b) {
		endpointAdded = b;
	}

	public static void init() {
		synchronized (LOCK) {
			if (initiated) {
				return;
			}

			System.out.println("Initiating the EDHOC handler");

			// Fill maps
			keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new SynchronizedHashMap<Integer, OneKey>());
			keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new SynchronizedHashMap<Integer, OneKey>());
			creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new SynchronizedHashMap<Integer, CBORObject>());
			creds.put(Integer.valueOf(Constants.ECDH_KEY), new SynchronizedHashMap<Integer, CBORObject>());
			idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new SynchronizedHashMap<Integer, CBORObject>());
			idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new SynchronizedHashMap<Integer, CBORObject>());

			initiated = true;
		}
	}

}
