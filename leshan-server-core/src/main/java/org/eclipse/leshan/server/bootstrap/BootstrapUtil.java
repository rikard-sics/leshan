/*******************************************************************************
 * Copyright (c) 2019 Sierra Wireless and others.
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
 *     Rikard Höglund (RISE) - additions to support OSCORE
 *     Rikard Höglund (RISE) - additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.server.bootstrap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import org.eclipse.leshan.core.LwM2mId;
import org.eclipse.leshan.core.node.LwM2mMultipleResource;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.LwM2mSingleResource;
import org.eclipse.leshan.core.node.ObjectLink;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.request.BootstrapDeleteRequest;
import org.eclipse.leshan.core.request.BootstrapDownlinkRequest;
import org.eclipse.leshan.core.request.BootstrapWriteRequest;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.response.LwM2mResponse;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig.ACLConfig;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig.EdhocObject;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig.OscoreObject;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig.ServerConfig;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig.ServerSecurity;

public class BootstrapUtil {
    public static LwM2mObjectInstance toSecurityInstance(int instanceId, ServerSecurity securityConfig) {
        Collection<LwM2mResource> resources = new ArrayList<>();

        if (securityConfig.uri != null)
            resources.add(LwM2mSingleResource.newStringResource(0, securityConfig.uri));
        resources.add(LwM2mSingleResource.newBooleanResource(1, securityConfig.bootstrapServer));
        if (securityConfig.securityMode != null)
            resources.add(LwM2mSingleResource.newIntegerResource(2, securityConfig.securityMode.code));
        if (securityConfig.publicKeyOrId != null)
            resources.add(LwM2mSingleResource.newBinaryResource(3, securityConfig.publicKeyOrId));
        if (securityConfig.serverPublicKey != null)
            resources.add(LwM2mSingleResource.newBinaryResource(4, securityConfig.serverPublicKey));
        if (securityConfig.secretKey != null)
            resources.add(LwM2mSingleResource.newBinaryResource(5, securityConfig.secretKey));
        if (securityConfig.smsSecurityMode != null)
            resources.add(LwM2mSingleResource.newIntegerResource(6, securityConfig.smsSecurityMode.code));
        if (securityConfig.smsBindingKeyParam != null)
            resources.add(LwM2mSingleResource.newBinaryResource(7, securityConfig.smsBindingKeyParam));
        if (securityConfig.smsBindingKeySecret != null)
            resources.add(LwM2mSingleResource.newBinaryResource(8, securityConfig.smsBindingKeySecret));
        if (securityConfig.serverSmsNumber != null)
            resources.add(LwM2mSingleResource.newStringResource(9, securityConfig.serverSmsNumber));
        if (securityConfig.serverId != null)
            resources.add(LwM2mSingleResource.newIntegerResource(10, securityConfig.serverId));
        if (securityConfig.clientOldOffTime != null)
            resources.add(LwM2mSingleResource.newIntegerResource(11, securityConfig.clientOldOffTime));
        if (securityConfig.bootstrapServerAccountTimeout != null)
            resources.add(LwM2mSingleResource.newIntegerResource(12, securityConfig.bootstrapServerAccountTimeout));
        if (securityConfig.oscoreSecurityMode != null) {
            // integer value needs to be made into an object link
            ObjectLink oscoreSecurityModeLink = new ObjectLink(LwM2mId.OSCORE, securityConfig.oscoreSecurityMode);
            resources.add(LwM2mSingleResource.newObjectLinkResource(17, oscoreSecurityModeLink));
        }
        return new LwM2mObjectInstance(instanceId, resources);
    }

    public static BootstrapWriteRequest toWriteRequest(int instanceId, ServerSecurity securityConfig,
            ContentFormat contentFormat) {
        LwM2mPath path = new LwM2mPath(LwM2mId.SECURITY, instanceId);
        final LwM2mNode securityInstance = BootstrapUtil.toSecurityInstance(instanceId, securityConfig);
        return new BootstrapWriteRequest(path, securityInstance, contentFormat);
    }

    public static LwM2mObjectInstance toServerInstance(int instanceId, ServerConfig serverConfig) {
        Collection<LwM2mResource> resources = new ArrayList<>();

        resources.add(LwM2mSingleResource.newIntegerResource(0, serverConfig.shortId));
        resources.add(LwM2mSingleResource.newIntegerResource(1, serverConfig.lifetime));
        if (serverConfig.defaultMinPeriod != null)
            resources.add(LwM2mSingleResource.newIntegerResource(2, serverConfig.defaultMinPeriod));
        if (serverConfig.defaultMaxPeriod != null)
            resources.add(LwM2mSingleResource.newIntegerResource(3, serverConfig.defaultMaxPeriod));
        if (serverConfig.disableTimeout != null)
            resources.add(LwM2mSingleResource.newIntegerResource(5, serverConfig.disableTimeout));
        resources.add(LwM2mSingleResource.newBooleanResource(6, serverConfig.notifIfDisabled));
        if (serverConfig.binding != null)
            resources.add(LwM2mSingleResource.newStringResource(7, BindingMode.toString(serverConfig.binding)));

        return new LwM2mObjectInstance(instanceId, resources);
    }

    public static BootstrapWriteRequest toWriteRequest(int instanceId, ServerConfig serverConfig,
            ContentFormat contentFormat) {
        LwM2mPath path = new LwM2mPath(LwM2mId.SERVER, instanceId);
        final LwM2mNode securityInstance = BootstrapUtil.toServerInstance(instanceId, serverConfig);
        return new BootstrapWriteRequest(path, securityInstance, contentFormat);
    }

    public static LwM2mObjectInstance toAclInstance(int instanceId, ACLConfig aclConfig) {
        Collection<LwM2mResource> resources = new ArrayList<>();

        resources.add(LwM2mSingleResource.newIntegerResource(0, aclConfig.objectId));
        resources.add(LwM2mSingleResource.newIntegerResource(1, aclConfig.objectInstanceId));
        if (aclConfig.acls != null)
            resources.add(LwM2mMultipleResource.newIntegerResource(2, aclConfig.acls));
        if (aclConfig.AccessControlOwner != null)
            resources.add(LwM2mSingleResource.newIntegerResource(3, aclConfig.AccessControlOwner));

        return new LwM2mObjectInstance(instanceId, resources);
    }

    public static BootstrapWriteRequest toWriteRequest(int instanceId, ACLConfig aclConfig,
            ContentFormat contentFormat) {
        LwM2mPath path = new LwM2mPath(LwM2mId.ACCESS_CONTROL, instanceId);
        final LwM2mNode securityInstance = BootstrapUtil.toAclInstance(instanceId, aclConfig);
        return new BootstrapWriteRequest(path, securityInstance, contentFormat);
    }

    public static LwM2mObjectInstance toOscoreInstance(int instanceId, OscoreObject oscoreConfig) {
        Collection<LwM2mResource> resources = new ArrayList<>();

        if (oscoreConfig.oscoreMasterSecret != null)
            resources.add(LwM2mSingleResource.newStringResource(0, oscoreConfig.oscoreMasterSecret));
        if (oscoreConfig.oscoreSenderId != null)
            resources.add(LwM2mSingleResource.newStringResource(1, oscoreConfig.oscoreSenderId));
        if (oscoreConfig.oscoreRecipientId != null)
            resources.add(LwM2mSingleResource.newStringResource(2, oscoreConfig.oscoreRecipientId));
        if (oscoreConfig.oscoreAeadAlgorithm != null)
            resources.add(LwM2mSingleResource.newIntegerResource(3, oscoreConfig.oscoreAeadAlgorithm));
        if (oscoreConfig.oscoreHmacAlgorithm != null)
            resources.add(LwM2mSingleResource.newIntegerResource(4, oscoreConfig.oscoreHmacAlgorithm));
        if (oscoreConfig.oscoreMasterSalt != null)
            resources.add(LwM2mSingleResource.newStringResource(5, oscoreConfig.oscoreMasterSalt));

        return new LwM2mObjectInstance(instanceId, resources);
    }

    public static BootstrapWriteRequest toWriteRequest(int instanceId, OscoreObject oscoreConfig,
            ContentFormat contentFormat) {
        LwM2mPath path = new LwM2mPath(LwM2mId.OSCORE, instanceId);
        final LwM2mNode securityInstance = BootstrapUtil.toOscoreInstance(instanceId, oscoreConfig);
        return new BootstrapWriteRequest(path, securityInstance, contentFormat);
    }

    public static LwM2mObjectInstance toEdhocInstance(int instanceId, EdhocObject edhocConfig) {
        Collection<LwM2mResource> resources = new ArrayList<>();

        if (edhocConfig.initiator != null)
            resources.add(LwM2mSingleResource.newBooleanResource(0, edhocConfig.initiator));
        if (edhocConfig.authenticationMethod != null)
            resources.add(LwM2mSingleResource.newUnsignedIntegerResource(1, edhocConfig.authenticationMethod));
        if (edhocConfig.ciphersuite != null)
            resources.add(LwM2mSingleResource.newUnsignedIntegerResource(2, edhocConfig.ciphersuite));
        if (edhocConfig.credentialIdentifier != null)
            resources.add(LwM2mSingleResource.newBinaryResource(3, edhocConfig.credentialIdentifier));
        if (edhocConfig.publicCredential != null)
            resources.add(LwM2mSingleResource.newBinaryResource(4, edhocConfig.publicCredential));
        if (edhocConfig.privateKey != null)
            resources.add(LwM2mSingleResource.newBinaryResource(5, edhocConfig.privateKey));
        if (edhocConfig.serverCredentialIdentifier != null)
            resources.add(LwM2mSingleResource.newBinaryResource(6, edhocConfig.serverCredentialIdentifier));
        if (edhocConfig.serverPublicKey != null)
            resources.add(LwM2mSingleResource.newBinaryResource(7, edhocConfig.serverPublicKey));
        if (edhocConfig.oscoreMasterSecretLength != null)
            resources.add(LwM2mSingleResource.newUnsignedIntegerResource(8, edhocConfig.oscoreMasterSecretLength));
        if (edhocConfig.oscoreMasterSaltLength != null)
            resources.add(LwM2mSingleResource.newUnsignedIntegerResource(9, edhocConfig.oscoreMasterSaltLength));
        if (edhocConfig.edhocOscoreCombined != null)
            resources.add(LwM2mSingleResource.newBooleanResource(10, edhocConfig.edhocOscoreCombined));

        return new LwM2mObjectInstance(instanceId, resources);
    }

    public static BootstrapWriteRequest toWriteRequest(int instanceId, EdhocObject edhocConfig,
            ContentFormat contentFormat) {
        LwM2mPath path = new LwM2mPath(LwM2mId.EDHOC, instanceId);
        final LwM2mNode securityInstance = BootstrapUtil.toEdhocInstance(instanceId, edhocConfig);
        return new BootstrapWriteRequest(path, securityInstance, contentFormat);
    }

    public static List<BootstrapDownlinkRequest<? extends LwM2mResponse>> toRequests(BootstrapConfig bootstrapConfig) {
        return toRequests(bootstrapConfig, ContentFormat.TLV);
    }

    public static List<BootstrapDownlinkRequest<? extends LwM2mResponse>> toRequests(BootstrapConfig bootstrapConfig,
            ContentFormat contentFormat) {
        List<BootstrapDownlinkRequest<? extends LwM2mResponse>> requests = new ArrayList<>();
        // handle delete
        for (String path : bootstrapConfig.toDelete) {
            requests.add(new BootstrapDeleteRequest(path));
        }
        // handle security
        for (Entry<Integer, ServerSecurity> security : bootstrapConfig.security.entrySet()) {
            requests.add(toWriteRequest(security.getKey(), security.getValue(), contentFormat));
        }
        // handle server
        for (Entry<Integer, ServerConfig> server : bootstrapConfig.servers.entrySet()) {
            requests.add(toWriteRequest(server.getKey(), server.getValue(), contentFormat));
        }
        // handle acl
        for (Entry<Integer, ACLConfig> acl : bootstrapConfig.acls.entrySet()) {
            requests.add(toWriteRequest(acl.getKey(), acl.getValue(), contentFormat));
        }
        // handle oscore
        for (Entry<Integer, OscoreObject> oscore : bootstrapConfig.oscore.entrySet()) {
            requests.add(toWriteRequest(oscore.getKey(), oscore.getValue(), contentFormat));
        }
        // handle edhoc
        for (Entry<Integer, EdhocObject> edhoc : bootstrapConfig.edhoc.entrySet()) {
            requests.add(toWriteRequest(edhoc.getKey(), edhoc.getValue(), contentFormat));
        }

        // handle edhoc (for testing TODO RH: Remove)
        EdhocObject edhocTest = new EdhocObject();
        edhocTest.initiator = true;
        edhocTest.authenticationMethod = 0L;
        edhocTest.ciphersuite = 0L;
        edhocTest.credentialIdentifier = new byte[] { (byte) 0x2E };
        edhocTest.publicCredential = new byte[] { (byte) 0x89, (byte) 0x8f, (byte) 0xf7, (byte) 0x9a, (byte) 0x02,
                                (byte) 0x06, (byte) 0x7a, (byte) 0x16, (byte) 0xea, (byte) 0x1e, (byte) 0xcc,
                                (byte) 0xb9, (byte) 0x0f, (byte) 0xa5, (byte) 0x22, (byte) 0x46, (byte) 0xf5,
                                (byte) 0xaa, (byte) 0x4d, (byte) 0xd6, (byte) 0xec, (byte) 0x07, (byte) 0x6b,
                                (byte) 0xba, (byte) 0x02, (byte) 0x59, (byte) 0xd9, (byte) 0x04, (byte) 0xb7,
                                (byte) 0xec, (byte) 0x8b, (byte) 0x0c };
        edhocTest.privateKey = new byte[] { (byte) 0xE9, (byte) 0x4f, (byte) 0xa2, (byte) 0x3d, (byte) 0x06,
                                (byte) 0x06, (byte) 0x7d, (byte) 0x16, (byte) 0xed, (byte) 0x1e, (byte) 0xcc,
                                (byte) 0xb9, (byte) 0x0f, (byte) 0xd5, (byte) 0x66, (byte) 0x46, (byte) 0xf5,
                                (byte) 0xdd, (byte) 0x4d, (byte) 0xd6, (byte) 0xec, (byte) 0x07, (byte) 0x6b,
                                (byte) 0xbd, (byte) 0x06, (byte) 0x59, (byte) 0xd9, (byte) 0x04, (byte) 0xb7,
                                (byte) 0xfc, (byte) 0x2b, (byte) 0x5c };
        edhocTest.serverCredentialIdentifier = new byte[] { (byte) 0x34, (byte) 0xfe, (byte) 0xcd, (byte) 0x22,
                                (byte) 0x28, (byte) 0xb9, (byte) 0x0f, (byte) 0xd5, (byte) 0x66, (byte) 0x46,
                                (byte) 0xf5, (byte) 0x06, (byte) 0x7d, (byte) 0x16, (byte) 0xed, (byte) 0x1e,
                                (byte) 0xcc, (byte) 0xbd, (byte) 0x06, (byte) 0x59, (byte) 0xd9, (byte) 0x04,
                                (byte) 0xb7, (byte) 0xdd, (byte) 0x4d, (byte) 0xd6, (byte) 0xec, (byte) 0x07,
                                (byte) 0x6b, (byte) 0x5f, (byte) 0xe1, (byte) 0xd2 };
        edhocTest.serverPublicKey = new byte[] { (byte) 0xec, (byte) 0x8b, (byte) 0x0c, (byte) 0x9a, (byte) 0x02,
                                (byte) 0x06, (byte) 0x7a, (byte) 0x16, (byte) 0xea, (byte) 0x1e, (byte) 0xcc,
                                (byte) 0xb9, (byte) 0x0f, (byte) 0xa5, (byte) 0x22, (byte) 0x46, (byte) 0xf5,
                                (byte) 0xf5, (byte) 0x06, (byte) 0x7d, (byte) 0x16, (byte) 0xed, (byte) 0x1e,
                                (byte) 0xba, (byte) 0x02, (byte) 0x59, (byte) 0xd9, (byte) 0x04, (byte) 0xb7,
                                (byte) 0xb4, (byte) 0x3a, (byte) 0x44 };
        edhocTest.oscoreMasterSecretLength = 8L;
        edhocTest.oscoreMasterSaltLength = 8L;
        edhocTest.edhocOscoreCombined = true;
        requests.add(toWriteRequest(33, edhocTest, contentFormat));

        return (requests);
    }
}