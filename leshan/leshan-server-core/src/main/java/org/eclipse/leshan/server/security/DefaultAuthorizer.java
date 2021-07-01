/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
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
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.server.security;

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.request.UplinkRequest;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.server.OscoreHandler;
import org.eclipse.leshan.server.registration.Registration;

/**
 * A default {@link Authorizer} implementation
 *
 * It checks in {@link SecurityStore} if there is a corresponding {@link SecurityInfo} for this registration endpoint.
 * If there is a {@link SecurityInfo} it check the identity is correct, else it checks if the LWM2M client use an
 * unsecure connection.
 */
public class DefaultAuthorizer implements Authorizer {

    private SecurityStore securityStore;
    private SecurityChecker securityChecker;

    public DefaultAuthorizer(SecurityStore store) {
        this(store, new SecurityChecker());
    }

    public DefaultAuthorizer(SecurityStore store, SecurityChecker checker) {
        securityStore = store;
        securityChecker = checker;
    }

    @Override
    public Registration isAuthorized(UplinkRequest<?> request, Registration registration, Identity senderIdentity) {

		// If this client used EDHOC the security info needs to be updated with
		// the context that EDHOC actually created
		if (securityStore.getByEndpoint(registration.getEndpoint()).getBuiltFromEdhoc()) {
			// System.out.println("class " + securityStore.getClass());

			System.out.println("Checking rights for client that started by using EDHOC: " + senderIdentity);
			String[] identityParts = senderIdentity.toString().split("rid=");
			// System.out.println("identityParts[1]: " + identityParts[1]);
			byte[] clientRid = Hex.decodeHex(identityParts[1].replace("]", "").toCharArray());
			OSCoreCtx clientCtx = OscoreHandler.getContextDB().getContext(clientRid);

			// Update info in security store
			if (securityStore instanceof FileSecurityStore) {
				FileSecurityStore myStore = (FileSecurityStore) securityStore;
				myStore.remove(registration.getEndpoint(), false);
				SecurityInfo info = SecurityInfo.newOSCoreInfo(registration.getEndpoint(), clientCtx);
				try {
					myStore.add(info);
				} catch (NonUniqueSecurityInfoException e) {
					System.err.println("Failed to add OSCORE context generated from EDHOC");
					e.printStackTrace();
				}
			}

		}

        // do we have security information for this client?
        SecurityInfo expectedSecurityInfo = null;
        if (securityStore != null)
            expectedSecurityInfo = securityStore.getByEndpoint(registration.getEndpoint());
        if (securityChecker.checkSecurityInfo(registration.getEndpoint(), senderIdentity, expectedSecurityInfo)) {
            return registration;
        } else {
            return null;
        }
    }
}
