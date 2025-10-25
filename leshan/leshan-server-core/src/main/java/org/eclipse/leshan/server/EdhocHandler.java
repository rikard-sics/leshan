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

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.oscore.HashMapCtxDB;

public class EdhocHandler {

	private static boolean endpointAdded = false;

	public static boolean getEndpointAdded() {
		return endpointAdded;
	}

	public static void setEndpointAdded(boolean b) {
		endpointAdded = b;
	}

}
