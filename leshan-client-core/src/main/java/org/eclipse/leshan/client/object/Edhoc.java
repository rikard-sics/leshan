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
 *     Sierra Wireless - initial API and implementation
 *     Rikard Höglund (RISE SICS) - Additions to support OSCORE
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *
 *******************************************************************************/
package org.eclipse.leshan.client.object;

import static org.eclipse.leshan.core.LwM2mId.*;

import java.util.Arrays;
import java.util.List;

import org.eclipse.leshan.client.resource.BaseInstanceEnabler;
import org.eclipse.leshan.client.resource.LwM2mInstanceEnabler;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.model.ResourceModel.Type;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.datatype.ULong;

/**
 * A simple {@link LwM2mInstanceEnabler} for the EDHOC Security (99) object.
 */
public class Edhoc extends BaseInstanceEnabler {

    private static final Logger LOG = LoggerFactory.getLogger(Security.class);

    private final static List<Integer> supportedResources = Arrays.asList(Initiator, Authentication_Method, Ciphersuite,
            Credential_Identifier, Public_Credential, Private_Key, Server_Credential_Identifier, Server_Public_Key,
            Oscore_Master_Secret_Length, Oscore_Master_Salt_Length, Edhoc_Oscore_Combined);

    private boolean initiator;
    private ULong authenticationMethod;
    private ULong ciphersuite;
    private byte[] credentialIdentifier;
    private byte[] publicCredential;
    private byte[] privateKey;
    private byte[] serverCredentialIdentifier;
    private byte[] serverPublicKey;
    private ULong oscoreMasterSecretLength;
    private ULong oscoreMasterSaltLength;
    private boolean edhocOscoreCombined;

    public Edhoc() {

    }

    /**
     * Default constructor.
     */
    public Edhoc(int instanceId, boolean initiator, long authenticationMethod, long ciphersuite,
            byte[] credentialIdentifier,
            byte[] publicCredential, byte[] privateKey, byte[] serverCredentialIdentifier, byte[] serverPublicKey,
            long oscoreMasterSecretLength, long oscoreMasterSaltLength, boolean edhocOscoreCombined) {
        super(instanceId);

        this.initiator = initiator;
        this.authenticationMethod = ULong.valueOf(authenticationMethod);
        this.ciphersuite = ULong.valueOf(ciphersuite);
        this.credentialIdentifier = credentialIdentifier;
        this.publicCredential = publicCredential;
        this.privateKey = privateKey;
        this.serverCredentialIdentifier = serverCredentialIdentifier;
        this.serverPublicKey = serverPublicKey;
        this.oscoreMasterSecretLength = ULong.valueOf(oscoreMasterSecretLength);
        this.oscoreMasterSaltLength = ULong.valueOf(oscoreMasterSaltLength);
        this.edhocOscoreCombined = edhocOscoreCombined;
    }

    @Override
    public WriteResponse write(ServerIdentity identity, int resourceId, LwM2mResource value) {
        LOG.debug("Write on resource {}: {}", resourceId, value);

        // restricted to BS server?

        // TODO RH: Remove debug print
        if (resourceId == Edhoc_Oscore_Combined) {
            System.out.println("Client received EDHOC object from " + identity);
            System.out.println("initiator: " + initiator);
            System.out.println("authenticationMethod: " + authenticationMethod);
            System.out.println("ciphersuite: " + ciphersuite);
            System.out.println("credentialIdentifier: " + Hex.encodeHexString(credentialIdentifier));
            System.out.println("publicCredential: " + Hex.encodeHexString(publicCredential));
            System.out.println("privateKey: " + Hex.encodeHexString(privateKey));
            System.out.println("serverCredentialIdentifier: " + Hex.encodeHexString(serverCredentialIdentifier));
            System.out.println("serverPublicKey: " + Hex.encodeHexString(serverPublicKey));
            System.out.println("oscoreMasterSecretLength: " + oscoreMasterSecretLength);
            System.out.println("oscoreMasterSaltLength: " + oscoreMasterSaltLength);
            System.out.println("edhocOscoreCombined: " + (boolean) value.getValue());
        }

        switch (resourceId) {

        case Initiator:
            if (value.getType() != Type.BOOLEAN) {
                return WriteResponse.badRequest("invalid type");
            }
            initiator = (boolean) value.getValue();
            return WriteResponse.success();

        case Authentication_Method:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            authenticationMethod = (ULong) value.getValue();
            return WriteResponse.success();

        case Ciphersuite:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            ciphersuite = (ULong) value.getValue();
            return WriteResponse.success();

        case Credential_Identifier:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            credentialIdentifier = (byte[]) value.getValue();
            return WriteResponse.success();

        case Public_Credential:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            publicCredential = (byte[]) value.getValue();
            return WriteResponse.success();

        case Private_Key:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            privateKey = (byte[]) value.getValue();
            return WriteResponse.success();

        case Server_Credential_Identifier:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            serverCredentialIdentifier = (byte[]) value.getValue();
            return WriteResponse.success();

        case Server_Public_Key:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            serverPublicKey = (byte[]) value.getValue();
            return WriteResponse.success();

        case Oscore_Master_Secret_Length:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            oscoreMasterSecretLength = (ULong) value.getValue();
            return WriteResponse.success();

        case Oscore_Master_Salt_Length:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            oscoreMasterSaltLength = (ULong) value.getValue();
            return WriteResponse.success();

        case Edhoc_Oscore_Combined:
            if (value.getType() != Type.BOOLEAN) {
                return WriteResponse.badRequest("invalid type");
            }
            edhocOscoreCombined = (boolean) value.getValue();
            return WriteResponse.success();

        default:
            return super.write(identity, resourceId, value);
        }

    }

    @Override
    public ReadResponse read(ServerIdentity identity, int resourceid) {
        LOG.debug("Read on resource {}", resourceid);
        // only accessible for internal read?

        switch (resourceid) {

        case Initiator:
            return ReadResponse.success(resourceid, initiator);

        case Authentication_Method:
            return ReadResponse.success(resourceid, authenticationMethod);

        case Ciphersuite:
            return ReadResponse.success(resourceid, ciphersuite);

        case Credential_Identifier:
            return ReadResponse.success(resourceid, credentialIdentifier);

        case Public_Credential:
            return ReadResponse.success(resourceid, publicCredential);

        case Private_Key:
            return ReadResponse.success(resourceid, privateKey);

        case Server_Credential_Identifier:
            return ReadResponse.success(resourceid, serverCredentialIdentifier);

        case Server_Public_Key:
            return ReadResponse.success(resourceid, serverPublicKey);

        case Oscore_Master_Secret_Length:
            return ReadResponse.success(resourceid, oscoreMasterSecretLength);

        case Oscore_Master_Salt_Length:
            return ReadResponse.success(resourceid, oscoreMasterSaltLength);

        case Edhoc_Oscore_Combined:
            return ReadResponse.success(resourceid, edhocOscoreCombined);

        default:
            return super.read(identity, resourceid);
        }

    }

    @Override
    public List<Integer> getAvailableResourceIds(ObjectModel model) {
        return supportedResources;
    }

}
