/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.leshan.core.util.Validate;

/**
 * This class implements Certificate Usage (0) - CA Constraint
 *
 * From RFC 6698:
 *
 * <pre>
 * 0 -- Certificate usage 0 is used to specify a CA certificate, or
 *       the public key of such a certificate, that MUST be found in any of
 *       the PKIX certification paths for the end entity certificate given
 *       by the server in TLS.  This certificate usage is sometimes
 *       referred to as "CA constraint" because it limits which CA can be
 *       used to issue certificates for a given service on a host.  The
 *       presented certificate MUST pass PKIX certification path
 *       validation, and a CA certificate that matches the TLSA record MUST
 *       be included as part of a valid certification path.  Because this
 *       certificate usage allows both trust anchors and CA certificates,
 *       the certificate might or might not have the basicConstraints
 *       extension present.
 * </pre>
 *
 * For details about Certificate Usage please see: <a href=
 * "https://tools.ietf.org/html/rfc6698#section-2.1.1">rfc6698#section-2.1.1</a>
 * - The Certificate Usage Field
 * <p>
 * The RFC says this certificate usage allows both trust anchors and CA
 * certificates, but this raises some issue like explained in
 * <a href="https://github.com/eclipse/leshan/issues/936">leshan issue #936</a>.
 * So this implementation does not support CA certificate as trust anchors. If
 * you need trust anchor usage, you should rather use
 * {@link TrustAnchorAssertionCertificateVerifier}.
 */
public class CaConstraintCertificateVerifier extends BaseCertificateVerifier {

    private final Certificate caCertificate;
    private final X509Certificate[] trustedCertificates;
	private final String expectedServerName; // for SNI

	public CaConstraintCertificateVerifier(Certificate caCertificate, X509Certificate[] trustedCertificates,
			String expectedServerName) {
        Validate.notNull(caCertificate);
        Validate.notNull(trustedCertificates);
        Validate.notEmpty(trustedCertificates);
        this.caCertificate = caCertificate;
        this.trustedCertificates = trustedCertificates;
		this.expectedServerName = expectedServerName;
    }

    @Override
	public CertPath verifyCertificate(boolean clientUsage, CertificateMessage message, InetSocketAddress peerSocket)
            throws HandshakeException {
        CertPath messageChain = message.getCertificateChain();

		validateCertificateChainNotEmpty(messageChain);
		X509Certificate receivedServerCertificate = validateReceivedCertificateIsSupported(messageChain);
		validateNotDirectTrust(messageChain);

        // - must do PKIX validation with trustStore
        CertPath certPath;
        try {
            certPath = X509Util.applyPKIXValidation(messageChain, trustedCertificates);
        } catch (GeneralSecurityException e) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated", alert, e);
        }

        // - must check that given certificate is part of certPath
        if (!certPath.getCertificates().contains(caCertificate)) {
            // No match found -> throw exception about it
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated", alert);
        }

        // - validate server name
		if (expectedServerName != null) {
			validateSNI(expectedServerName, receivedServerCertificate);
		} else {
			validateSubject(peerSocket, receivedServerCertificate);
		}

        return certPath;
    }

	protected void validateNotDirectTrust(CertPath messageChain) throws HandshakeException {
		Certificate certificate = messageChain.getCertificates().get(0);
		if (certificate.equals(caCertificate)) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			throw new HandshakeException(
					"Invalid certificate path : direct trust is not allowed with 'CA Constraint' usage. Use 'Service Certificate Constraint' instead.",
					alert);
		}
	}
}
