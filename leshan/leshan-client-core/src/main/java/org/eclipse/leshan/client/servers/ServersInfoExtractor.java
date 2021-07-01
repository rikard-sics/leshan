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
 *     Achim Kraus (Bosch Software Innovations GmbH) - use ServerIdentity.SYSTEM
 *     Rikard Höglund (RISE SICS) - Additions to support OSCORE
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.client.servers;

import static org.eclipse.leshan.client.servers.ServerIdentity.SYSTEM;
import static org.eclipse.leshan.core.LwM2mId.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.EnumSet;
import java.util.Map;

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.leshan.client.OscoreHandler;
import org.eclipse.leshan.client.resource.LwM2mInstanceEnabler;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.LwM2mId;
import org.eclipse.leshan.core.SecurityMode;
import org.eclipse.leshan.core.node.LwM2mObject;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.ObjectLink;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.request.BootstrapWriteRequest;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.request.WriteRequest;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.SecurityUtil;
import org.eclipse.leshan.core.util.datatype.ULong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extract from LwM2m object tree all the servers information like server uri, security mode, ...
 */
public class ServersInfoExtractor {
    private static final Logger LOG = LoggerFactory.getLogger(ServersInfoExtractor.class);

    public static ServersInfo getInfo(Map<Integer, LwM2mObjectEnabler> objectEnablers) {
        LwM2mObjectEnabler securityEnabler = objectEnablers.get(SECURITY);
        LwM2mObjectEnabler serverEnabler = objectEnablers.get(SERVER);
        LwM2mObjectEnabler oscoreEnabler = objectEnablers.get(OSCORE);
		LwM2mObjectEnabler edhocEnabler = objectEnablers.get(EDHOC);

        if (securityEnabler == null || serverEnabler == null)
            return null;

        ServersInfo infos = new ServersInfo();
        LwM2mObject securities = (LwM2mObject) securityEnabler.read(SYSTEM, new ReadRequest(SECURITY)).getContent();
        LwM2mObject servers = (LwM2mObject) serverEnabler.read(SYSTEM, new ReadRequest(SERVER)).getContent();

        LwM2mObject oscores = null;

		// If EDHOC is used, first update the OSCORE object
		if (edhocEnabler != null) {
			LwM2mObject edhocs = (LwM2mObject) edhocEnabler.read(SYSTEM, new ReadRequest(EDHOC)).getContent();
			Map<Integer, LwM2mObjectInstance> edhocInstances = edhocs.getInstances();
			if (edhocInstances.size() != 0) {
				/*
				 * System.out.println("EDHOC enabler present.");
				 * 
				 * // Retrieve OSCORE context established by EDHOC String
				 * lwServerUri = OscoreHandler.getlwServerUri(); OSCoreCtx ctx =
				 * null; try { ctx =
				 * OscoreHandler.getContextDB().getContext(lwServerUri); } catch
				 * (OSException e) { System.err.
				 * println("Failed to retrieve OSCORE context established by EDHOC"
				 * ); e.printStackTrace(); } if (ctx != null) {
				 * System.out.println("Found OSCORE Context created by EDHOC");
				 * } else { System.out.
				 * println("Did not find OSCORE Context created by EDHOC"); }
				 * 
				 * // Now write to the OSCORE resource String oscoreMasterSecret
				 * = Hex.encodeHexString(ctx.getMasterSecret()); String
				 * oscoreSenderId = Hex.encodeHexString(ctx.getSenderId());
				 * String oscoreRecipientId =
				 * Hex.encodeHexString(ctx.getRecipientId()); int
				 * oscoreAeadAlgorithm = ctx.getAlg().AsCBOR().AsInt32(); int
				 * oscoreHmacAlgorithm = ctx.getKdf().AsCBOR().AsInt32(); String
				 * oscoreMasterSalt = Hex.encodeHexString(ctx.getSalt());
				 * 
				 * System.out.println("master secret " + oscoreMasterSecret);
				 * System.out.println("master salt " + oscoreMasterSalt);
				 * System.out.println("oscoreSenderId " + oscoreSenderId);
				 * System.out.println("oscoreRecipientId " + oscoreRecipientId);
				 * System.out.println("oscoreAeadAlgorithm " +
				 * oscoreAeadAlgorithm);
				 * System.out.println("oscoreHmacAlgorithm " +
				 * oscoreHmacAlgorithm); System.out.println("oscoreMasterSalt "
				 * + oscoreMasterSalt);
				 * 
				 * oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 0,
				 * oscoreMasterSecret)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 1,
				 * oscoreSenderId)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 2,
				 * oscoreRecipientId)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 3,
				 * oscoreAeadAlgorithm)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 4,
				 * oscoreHmacAlgorithm)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 1, 5,
				 * oscoreMasterSalt));
				 * 
				 * oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 0,
				 * oscoreMasterSecret)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 1,
				 * oscoreSenderId)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 2,
				 * oscoreRecipientId)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 3,
				 * oscoreAeadAlgorithm)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 4,
				 * oscoreHmacAlgorithm)); oscoreEnabler.write(SYSTEM, new
				 * WriteRequest(ContentFormat.TLV, OSCORE, 0, 5,
				 * oscoreMasterSalt));
				 */
			}
		}

		Map<Integer, LwM2mObjectInstance> edhocInstances = null;
		if (edhocEnabler != null) {
			LwM2mObject edhocs = (LwM2mObject) edhocEnabler.read(SYSTEM, new ReadRequest(EDHOC)).getContent();
			edhocInstances = edhocs.getInstances();
		}
		boolean usingEdhoc = edhocInstances != null && !edhocInstances.isEmpty();

		if (oscoreEnabler != null && usingEdhoc == false) {
            oscores = (LwM2mObject) oscoreEnabler.read(SYSTEM, new ReadRequest(OSCORE)).getContent();
        }

        for (LwM2mObjectInstance security : securities.getInstances().values()) {
            try {
                if ((boolean) security.getResource(SEC_BOOTSTRAP).getValue()) {
                    if (infos.bootstrap != null) {
                        LOG.warn("There is more than one bootstrap configuration in security object.");
                    } else {
                        // create bootstrap info
                        ServerInfo info = new ServerInfo();
                        info.bootstrap = true;
                        LwM2mResource serverIdResource = security.getResource(SEC_SERVER_ID);
                        if (serverIdResource != null && serverIdResource.getValue() != null)
                            info.serverId = (long) serverIdResource.getValue();
                        else
                            info.serverId = 0;
                        info.serverUri = new URI((String) security.getResource(SEC_SERVER_URI).getValue());
                        info.secureMode = getSecurityMode(security);

                        // find associated oscore instance (if any)
                        LwM2mObjectInstance oscoreInstance = null;
                        ObjectLink oscoreObjLink = (ObjectLink) security.getResource(SEC_OSCORE_SECURITY_MODE)
                                .getValue();
                        if (oscoreObjLink != null && !oscoreObjLink.isNullLink()) {
                            if (oscoreObjLink.getObjectId() != OSCORE) {
                                LOG.warn(
                                        "Invalid Security info for bootstrap server : 'OSCORE Security Mode' does not link to OSCORE Object but to {} object.",
                                        oscoreObjLink.getObjectId());
                            } else {
                                if (oscores == null) {
                                    LOG.warn(
                                            "Invalid Security info for bootstrap server : OSCORE object enabler is not available.");
                                } else {
                                    oscoreInstance = oscores.getInstance(oscoreObjLink.getObjectInstanceId());
                                    if (oscoreInstance == null) {
                                        LOG.warn(
                                                "Invalid Security info for bootstrap server : OSCORE instance {} does not exist.",
                                                oscoreObjLink.getObjectInstanceId());
                                    }
                                }
                            }
                        }

                        if (oscoreInstance != null) {
                            info.useOscore = true;
                            info.masterSecret = getMasterSecret(oscoreInstance);
                            info.senderId = getSenderId(oscoreInstance);
                            info.recipientId = getRecipientId(oscoreInstance);
                            info.aeadAlgorithm = getAeadAlgorithm(oscoreInstance);
                            info.hkdfAlgorithm = getHkdfAlgorithm(oscoreInstance);
                            info.masterSalt = getMasterSalt(oscoreInstance);
                        } else if (info.secureMode == SecurityMode.PSK) {
                            info.pskId = getPskIdentity(security);
                            info.pskKey = getPskKey(security);
                        } else if (info.secureMode == SecurityMode.RPK) {
                            info.publicKey = getPublicKey(security);
                            info.privateKey = getPrivateKey(security);
                            info.serverPublicKey = getServerPublicKey(security);
                        } else if (info.secureMode == SecurityMode.X509) {
                            info.clientCertificate = getClientCertificate(security);
                            info.serverCertificate = getServerCertificate(security);
                            info.privateKey = getPrivateKey(security);
                            info.certificateUsage = getCertificateUsage(security);
                        }
                        infos.bootstrap = info;
                    }
                } else {
                    // create device management info
                    DmServerInfo info = new DmServerInfo();
                    info.bootstrap = false;
                    info.serverUri = new URI((String) security.getResource(SEC_SERVER_URI).getValue());
                    info.serverId = (long) security.getResource(SEC_SERVER_ID).getValue();
                    info.secureMode = getSecurityMode(security);

                    // find associated oscore instance (if any)
                    LwM2mObjectInstance oscoreInstance = null;
                    ObjectLink oscoreObjLink = (ObjectLink) security.getResource(SEC_OSCORE_SECURITY_MODE).getValue();
                    if (oscoreObjLink != null && !oscoreObjLink.isNullLink()) {
                        if (oscoreObjLink.getObjectId() != OSCORE) {
							// System.out.println("1");
                            LOG.warn(
                                    "Invalid Security info for LWM2M server {} : 'OSCORE Security Mode' does not link to OSCORE Object but to {} object.",
                                    info.serverUri, oscoreObjLink.getObjectId());
                        } else {
							if (oscores == null) {
								// System.out.println("2");
								if (!usingEdhoc) {
									LOG.warn(
                                        "Invalid Security info for LWM2M server {}: OSCORE object enabler is not available.",
											info.serverUri);
								}
                            } else {
                                oscoreInstance = oscores.getInstance(oscoreObjLink.getObjectInstanceId());
                                if (oscoreInstance == null) {
									// System.out.println("3");
                                    LOG.warn(
                                            "Invalid Security info for LWM2M server {} : OSCORE instance {} does not exist.",
                                            info.serverUri, oscoreObjLink.getObjectInstanceId());
                                }
                            }
                        }
                    }

					// Overwrite the information taken from the OSCORE object
					if (oscores == null && usingEdhoc) {
						System.out.println("Client using OSCORE after EDHOC to DM");

						// Retrieve OSCORE context established by EDHOC String
						String lwServerUri = OscoreHandler.getlwServerUri();
						OSCoreCtx ctx = null;
						try {
							ctx = OscoreHandler.getContextDB().getContext(lwServerUri);
						} catch (OSException e) {
							System.err.println("Failed to retrieve OSCORE context established by EDHOC");
							e.printStackTrace();
						}
						if (ctx != null) {
							System.out.println("Found OSCORE Context created by EDHOC");
						} else {
							System.out.println("Did not find OSCORE Context created by EDHOC");
						}

						info.useOscore = true;
						info.builtFromEdhoc = true;
						info.masterSecret = ctx.getMasterSecret();
						info.senderId = ctx.getSenderId();
						info.recipientId = ctx.getRecipientId();
						info.aeadAlgorithm = ctx.getAlg().AsCBOR().AsInt32();
						info.hkdfAlgorithm = ctx.getKdf().AsCBOR().AsInt32();
						info.masterSalt = ctx.getSalt();

					} else if (oscoreInstance != null) {
						System.out.println("Client using OSCORE to DM");
                        info.useOscore = true;
                        info.masterSecret = getMasterSecret(oscoreInstance);
                        info.senderId = getSenderId(oscoreInstance);
                        info.recipientId = getRecipientId(oscoreInstance);
                        info.aeadAlgorithm = getAeadAlgorithm(oscoreInstance);
                        info.hkdfAlgorithm = getHkdfAlgorithm(oscoreInstance);
                        info.masterSalt = getMasterSalt(oscoreInstance);
                    } else if (info.secureMode == SecurityMode.PSK) {
                        info.pskId = getPskIdentity(security);
                        info.pskKey = getPskKey(security);
                    } else if (info.secureMode == SecurityMode.RPK) {
                        info.publicKey = getPublicKey(security);
                        info.privateKey = getPrivateKey(security);
                        info.serverPublicKey = getServerPublicKey(security);
                    } else if (info.secureMode == SecurityMode.X509) {
                        info.clientCertificate = getClientCertificate(security);
                        info.serverCertificate = getServerCertificate(security);
                        info.privateKey = getPrivateKey(security);
                        info.certificateUsage = getCertificateUsage(security);
                    }
                    // search corresponding device management server
                    for (LwM2mObjectInstance server : servers.getInstances().values()) {
                        if (info.serverId == (Long) server.getResource(SRV_SERVER_ID).getValue()) {
                            info.lifetime = (long) server.getResource(SRV_LIFETIME).getValue();
                            info.binding = BindingMode.parse((String) server.getResource(SRV_BINDING).getValue());

                            infos.deviceManagements.put(info.serverId, info);
                            break;
                        }
                    }
                }
            } catch (URISyntaxException e) {
                LOG.error(String.format("Invalid URI %s", (String) security.getResource(SEC_SERVER_URI).getValue()), e);
            }
        }
        return infos;
    }

    public static DmServerInfo getDMServerInfo(Map<Integer, LwM2mObjectEnabler> objectEnablers, Long shortID) {
        ServersInfo info = getInfo(objectEnablers);
        if (info == null)
            return null;

        return info.deviceManagements.get(shortID);
    }

    public static ServerInfo getBootstrapServerInfo(Map<Integer, LwM2mObjectEnabler> objectEnablers) {
        ServersInfo info = getInfo(objectEnablers);
        if (info == null)
            return null;

        return info.bootstrap;
    }

    public static Long getLifeTime(LwM2mObjectEnabler serverEnabler, int instanceId) {
        ReadResponse response = serverEnabler.read(ServerIdentity.SYSTEM,
                new ReadRequest(SERVER, instanceId, SRV_LIFETIME));
        if (response.isSuccess()) {
            return (Long) ((LwM2mResource) response.getContent()).getValue();
        } else {
            return null;
        }
    }

    public static EnumSet<BindingMode> getServerBindingMode(LwM2mObjectEnabler serverEnabler, int instanceId) {
        ReadResponse response = serverEnabler.read(ServerIdentity.SYSTEM,
                new ReadRequest(SERVER, instanceId, SRV_BINDING));
        if (response.isSuccess()) {
            return BindingMode.parse((String) ((LwM2mResource) response.getContent()).getValue());
        } else {
            return null;
        }
    }

    public static EnumSet<BindingMode> getDeviceSupportedBindingMode(LwM2mObjectEnabler serverEnabler, int instanceId) {
        ReadResponse response = serverEnabler.read(ServerIdentity.SYSTEM,
                new ReadRequest(DEVICE, instanceId, DVC_SUPPORTED_BINDING));
        if (response.isSuccess()) {
            return BindingMode.parse((String) ((LwM2mResource) response.getContent()).getValue());
        } else {
            return null;
        }
    }

    public static Boolean isBootstrapServer(LwM2mObjectEnabler objectEnabler, int instanceId) {
        ReadResponse response = objectEnabler.read(ServerIdentity.SYSTEM,
                new ReadRequest(SECURITY, instanceId, SEC_BOOTSTRAP));
        if (response != null && response.isSuccess()) {
            return (Boolean) ((LwM2mResource) response.getContent()).getValue();
        } else {
            return null;
        }
    }

    public static Long getServerId(LwM2mObjectEnabler objectEnabler, int instanceId) {
        ReadResponse response = null;
        if (objectEnabler.getId() == SERVER) {
            response = objectEnabler.read(ServerIdentity.SYSTEM, new ReadRequest(SERVER, instanceId, SRV_SERVER_ID));
        } else if (objectEnabler.getId() == SECURITY) {
            response = objectEnabler.read(ServerIdentity.SYSTEM, new ReadRequest(SECURITY, instanceId, SEC_SERVER_ID));
        }
        if (response != null && response.isSuccess()) {
            return (Long) ((LwM2mResource) response.getContent()).getValue();
        } else {
            return null;
        }
    }

    public static SecurityMode getSecurityMode(LwM2mObjectInstance securityInstance) {
        return SecurityMode.fromCode((long) securityInstance.getResource(SEC_SECURITY_MODE).getValue());
    }

    public static CertificateUsage getCertificateUsage(LwM2mObjectInstance securityInstance) {
        return CertificateUsage.fromCode((ULong) securityInstance.getResource(SEC_CERTIFICATE_USAGE).getValue());
    }

    public static String getPskIdentity(LwM2mObjectInstance securityInstance) {
        byte[] pubKey = (byte[]) securityInstance.getResource(SEC_PUBKEY_IDENTITY).getValue();
        return new String(pubKey);
    }

    public static byte[] getPskKey(LwM2mObjectInstance securityInstance) {
        return (byte[]) securityInstance.getResource(SEC_SECRET_KEY).getValue();
    }

    private static PublicKey getPublicKey(LwM2mObjectInstance securityInstance) {
        byte[] encodedKey = (byte[]) securityInstance.getResource(SEC_PUBKEY_IDENTITY).getValue();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        String algorithm = "EC";
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            LOG.debug("Failed to instantiate key factory for algorithm " + algorithm, e);
        } catch (InvalidKeySpecException e) {
            LOG.debug("Failed to decode RFC7250 public key with algorithm " + algorithm, e);
        }
        return null;
    }

    private static PrivateKey getPrivateKey(LwM2mObjectInstance securityInstance) {
        byte[] encodedKey = (byte[]) securityInstance.getResource(SEC_SECRET_KEY).getValue();
        try {
            return SecurityUtil.privateKey.decode(encodedKey);
        } catch (IOException | GeneralSecurityException e) {
            LOG.debug("Failed to decode RFC5958 private key", e);
            return null;
        }
    }

    private static PublicKey getServerPublicKey(LwM2mObjectInstance securityInstance) {
        byte[] encodedKey = (byte[]) securityInstance.getResource(SEC_SERVER_PUBKEY).getValue();
        try {
            return SecurityUtil.publicKey.decode(encodedKey);
        } catch (IOException | GeneralSecurityException e) {
            LOG.debug("Failed to decode RFC7250 public key", e);
            return null;
        }
    }

    private static Certificate getServerCertificate(LwM2mObjectInstance securityInstance) {
        byte[] encodedCert = (byte[]) securityInstance.getResource(SEC_SERVER_PUBKEY).getValue();
        try {
            return SecurityUtil.certificate.decode(encodedCert);
        } catch (IOException | GeneralSecurityException e) {
            LOG.debug("Failed to decode X.509 certificate", e);
            return null;
        }
    }

    private static Certificate getClientCertificate(LwM2mObjectInstance securityInstance) {
        byte[] encodedCert = (byte[]) securityInstance.getResource(SEC_PUBKEY_IDENTITY).getValue();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (ByteArrayInputStream in = new ByteArrayInputStream(encodedCert)) {
                return cf.generateCertificate(in);
            }
        } catch (CertificateException | IOException e) {
            LOG.debug("Failed to decode X.509 certificate", e);
            return null;
        }
    }

    public static boolean isBootstrapServer(LwM2mInstanceEnabler instance) {
        ReadResponse response = instance.read(ServerIdentity.SYSTEM, LwM2mId.SEC_BOOTSTRAP);
        if (response == null || response.isFailure()) {
            return false;
        }

        LwM2mResource isBootstrap = (LwM2mResource) response.getContent();
        return (Boolean) isBootstrap.getValue();
    }

    // OSCORE related methods below

    public static byte[] getMasterSecret(LwM2mObjectInstance oscoreInstance) {
        String value = (String) oscoreInstance.getResource(OSCORE_Master_Secret).getValue();
        return Hex.decodeHex(value.toCharArray());
    }

    public static byte[] getSenderId(LwM2mObjectInstance oscoreInstance) {
        String value = (String) oscoreInstance.getResource(OSCORE_Sender_ID).getValue();
        return Hex.decodeHex(value.toCharArray());
    }

    public static byte[] getRecipientId(LwM2mObjectInstance oscoreInstance) {
        String value = (String) oscoreInstance.getResource(OSCORE_Recipient_ID).getValue();
        return Hex.decodeHex(value.toCharArray());
    }

    public static long getAeadAlgorithm(LwM2mObjectInstance oscoreInstance) {
        return (long) oscoreInstance.getResource(OSCORE_AEAD_Algorithm).getValue();
    }

    public static long getHkdfAlgorithm(LwM2mObjectInstance oscoreInstance) {
        return (long) oscoreInstance.getResource(OSCORE_HMAC_Algorithm).getValue();
    }

    public static byte[] getMasterSalt(LwM2mObjectInstance oscoreInstance) {
        String value = (String) oscoreInstance.getResource(OSCORE_Master_Salt).getValue();

        if (value.equals("")) {
            return null;
        } else {
            return Hex.decodeHex(value.toCharArray());
        }
    }
}