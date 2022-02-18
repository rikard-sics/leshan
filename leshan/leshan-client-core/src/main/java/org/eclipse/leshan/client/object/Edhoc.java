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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.AppStatement;
import org.eclipse.californium.edhoc.Constants;
import org.eclipse.californium.edhoc.EdhocClient;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.KissEDP;
import org.eclipse.californium.edhoc.SharedSecretCalculation;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.leshan.client.OscoreHandler;
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

import com.upokecenter.cbor.CBORObject;

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

    public boolean initiator;
    public ULong authenticationMethod;
    public ULong ciphersuite;
    public byte[] credentialIdentifier;
    public byte[] publicCredential;
    public byte[] privateKey;
    public byte[] serverCredentialIdentifier;
    public byte[] serverPublicKey;
    public ULong oscoreMasterSecretLength;
    public ULong oscoreMasterSaltLength;
    public boolean edhocOscoreCombined;

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
    public WriteResponse write(ServerIdentity identity, boolean replace, int resourceId, LwM2mResource value) {
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

		// RH: Run EDHOC now
		// RH: TODO: Do somewhere else instead?
		if (resourceId == Edhoc_Oscore_Combined && !OscoreHandler.getEdhocWithDmDone()) {

			// Utils.printPause("Running EDHOC with Device Manager");
			
			// Install crypto provider
			EdhocClient.installCryptoProvider();

			// Set params
			setupEdhocParameters();

			// Set ciphersuite
			setupSupportedCipherSuites(ciphersuite.intValue());

			// Set cred(s) (Credential Identifier and Server Credential
			// Identifier). Set also my public and private key, and the server's
			// public key
			setupIdentityKeys(credentialIdentifier, serverCredentialIdentifier, privateKey, publicCredential,
					serverPublicKey);

			// Specify the processor of External Authorization Data
			KissEDP edp = new KissEDP();
			String args[] = new String[0];
			HashMapCtxDB db = OscoreHandler.getContextDB();
			// String edhocURI = identity.getUri() + "/.well-known/edhoc";
			String edhocURI = OscoreHandler.getlwServerUri() + "/.well-known/edhoc";
			// String edhocURI = "coap://127.0.0.2" + "/.well-known/edhoc";

			URI uri = null;
			try {
				uri = new URI(edhocURI);
			} catch (URISyntaxException e) {
				System.err.println("Failed to set EDHOC URI for LWM2M Server");
				e.printStackTrace();
			}
			// Prepare the set of information for this EDHOC endpoint

			// Set Authentication Method
			Set<Integer> authMethods = new HashSet<Integer>();
			authMethods.add(authenticationMethod.intValue());
			AppStatement appStatement = new AppStatement(true, authMethods, false, false);
			appStatements.put(edhocURI, appStatement);

			EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCred, cred, keyPair, peerPublicKeys,
					peerCredentials, edhocSessions, usedConnectionIds, supportedCiphersuites, db, edhocURI,
					OSCORE_REPLAY_WINDOW, appStatements, edp);

			// Possibly specify external authorization data for EAD_1, or null
			// if
			// none have to be provided
			// The first element of EAD is always a CBOR integer, followed by
			// one or
			// multiple additional elements
			CBORObject[] ead1 = null;

			System.out.println("Running EDHOC with Device Manager: ");
			EdhocClient.edhocExchangeAsInitiator(args, uri, edhocEndpointInfo, ead1);
			
			OscoreHandler.setEdhocWithDmDone(true);
		} else if (resourceId == Edhoc_Oscore_Combined && OscoreHandler.getEdhocWithDmDone()) {
			Edhoc temp = new Edhoc(100, initiator, authenticationMethod.longValue(), ciphersuite.longValue(),
		            credentialIdentifier,
		            publicCredential, privateKey, serverCredentialIdentifier, serverPublicKey,
		            oscoreMasterSecretLength.longValue(), oscoreMasterSaltLength.longValue(), edhocOscoreCombined);
			OscoreHandler.setAsEdhocObj(temp);
			
		}
		// End run EDHOC

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
            return super.write(identity, replace, resourceId, value);
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

	/* === RH: EDHOC support methods === */

	// RH: Variables for initializing EdhocEndpointInfo
	// Set in setupIdentityKeys() or setupSupportedCipherSuites()
	static OneKey keyPair = null;
	static int credType = Constants.CRED_TYPE_RPK;
	static byte[] cred = null;
	static CBORObject idCred = null;
	static String subjectName = "";
	static Map<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	static Map<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
	static List<Integer> supportedCiphersuites = new ArrayList<Integer>();
	// Other variables needed
	static final int keyCurve = KeyKeys.EC2_P256.AsInt32(); // ECDSA
	static Map<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	static List<Set<Integer>> usedConnectionIds = OscoreHandler.getUsedConnectionIds();
	static String uriLocal = "coap://localhost";
	static final int OSCORE_REPLAY_WINDOW = 32;
	static Map<String, AppStatement> appStatements = new HashMap<String, AppStatement>();
	static KissEDP edp;
	final static int keyFormat = 0; //

	/**
	 * RH: General method for setting up all EDHOC parameters needed to build
	 * the EdhocEndpointInfo
	 */
	private static void setupEdhocParameters() {
		// Set<Integer> authMethods = new HashSet<Integer>();
		// authMethods.add(Constants.EDHOC_AUTH_METHOD_0);
		// AppStatement appStatement = new AppStatement(true, authMethods,
		// false, true);

		// appStatements.put(uriLocal + "/.well-known/edhoc", appStatement);

//		for (int i = 0; i < 4; i++) {
//			// Empty sets of assigned Connection Identifiers; one set for each
//			// possible size in bytes.
//			// The set with index 0 refers to Connection Identifiers with size 1
//			// byte
//			usedConnectionIds.add(new HashSet<Integer>());
//		}

		edp = new KissEDP();
	}

	/**
	 * RH: Imported from the EDHOC code EdhocServer.
	 */
	private static void setupSupportedCipherSuites(int suite) {

		supportedCiphersuites.add(suite);

		// if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
		// supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_2);
		// // supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_3);
		// } else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32() || keyCurve ==
		// KeyKeys.OKP_X25519.AsInt32()) {
		// supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_0);
		// // supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_1);
		// }

	}

	/**
	 * RH: Imported from the EDHOC code EdhocServer.
	 */
	private static void setupIdentityKeys(byte[] idCredKid, byte[] peerKid, byte[] myPrivateKey, byte[] myPublicKey,
			byte[] thePeerPublicKey) {

		String keyPairBase64 = null;
		String peerPublicKeyBase64 = null;
		byte[] privateKeyBinary = null;
		byte[] publicKeyBinary = null;
		byte[] publicKeyBinaryY = null;
		byte[] peerPublicKeyBinary = null;
		byte[] peerPublicKeyBinaryY = null;

		switch (keyFormat) {

		/* For stand-alone testing, as base64 encoding of OneKey objects */
		case 0:
			if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
				// keyPairBase64 =
				// "pgMmAQIgASFYIGdZmgAlZDXB6FGfVVxHrB2LL8JMZag4JgK4ZcZ/+GBUIlgguZsSChh5hecy3n4Op+lZZJ2xXdbsz8DY7qRmLdIVavkjWCDfyRlRix5e7y5M9aMohvqWGgWCbCW2UYo7V5JppHHsRA==";
				// peerPublicKeyBase64 =
				// "pQMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnM=";
			}
			else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
				// keyPairBase64 =
				// "pQMnAQEgBiFYIEPgltbaO4rEBSYv3Lhs09jLtrOdihHUxLdc9pRoR/W9I1ggTriT3VdzE7bLv2mJ3gqW/YIyJ7vDuCac62OZMNO8SP4=";
				// peerPublicKeyBase64 =
				// "pAMnAQEgBiFYIDzQyFH694a7CcXQasH9RcqnmwQAy2FIX97dGGGy+bpS";
			} else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
				// keyPairBase64 =
				// "pQMnAQEgBiFYIGt2OynWjaQY4cE9OhPQrwcrZYNg8lRJ+MwXIYMjeCtrI1gg5TeGQyIjv2d2mulBYLnL7Mxp0cuaHMBlSuuFtmaU808=";
				// peerPublicKeyBase64 =
				// "pAMnAQEgBiFYIKOjK/y+4psOGi9zdnJBqTLThdpEj6Qygg4Voc10NYGS";
			}
			break;
		default:
			System.err.println("ERROR in key format switch!");
			break;
		}

		switch (keyFormat) {
		/* For stand-alone testing, as base64 encoding of OneKey objects */
		case 0:
			// keyPair = new
			// OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyPairBase64)));
			// keyPair = SharedSecretCalculation.buildEcdsa256OneKey(
			// Hex.decodeHex("DFC919518B1E5EEF2E4CF5A32886FA961A05826C25B6518A3B579269A471EC44".toCharArray()),
			// // Priv
			// Hex.decodeHex("67599A00256435C1E8519F555C47AC1D8B2FC24C65A8382602B865C67FF86054".toCharArray()),
			// // X
			// Hex.decodeHex(
			// "B99B120A187985E732DE7E0EA7E959649DB15DD6ECCFC0D8EEA4662DD2156AF9".toCharArray()));
			// // Y

			// ECDSA P256
			if (myPublicKey.length == 64) {
				byte[] keyX = Arrays.copyOfRange(myPublicKey, 0, 32);
				byte[] keyY = Arrays.copyOfRange(myPublicKey, 32, 64);
				keyPair = SharedSecretCalculation.buildEcdsa256OneKey(myPrivateKey, keyX, keyY);
			} else {
				// OKP_Ed25519
				keyPair = SharedSecretCalculation.buildEd25519OneKey(myPrivateKey, myPublicKey);
			}

			break;

		/* Value from the test vectors, as binary serializations */
		case 1:
			// if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			// keyPair =
			// SharedSecretCalculation.buildEcdsa256OneKey(privateKeyBinary,
			// publicKeyBinary,
			// publicKeyBinaryY);
			// } else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			// keyPair =
			// SharedSecretCalculation.buildEd25519OneKey(privateKeyBinary,
			// publicKeyBinary);
			// } else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			// keyPair =
			// SharedSecretCalculation.buildCurve25519OneKey(privateKeyBinary,
			// publicKeyBinary);
			// }
			System.err.println("Bad key settings!");
			break;
		default:
			System.err.println("ERROR in key format switch!");
			break;
		}

		switch (credType) {
		case Constants.CRED_TYPE_RPK:
			// Build the related ID_CRED
			// Use 0x07 as kid for this peer, i.e. the serialized ID_CRED_X
			// is 0xa1, 0x04, 0x41, 0x07
			// byte[] idCredKid = new byte[] { (byte) 0x07 };
			idCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(idCredKid);
			// Build the related CRED
			cred = org.eclipse.californium.edhoc.Util.buildCredRawPublicKey(keyPair, subjectName);
			System.out.println("Adding key");
			break;

		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}

		/* Settings for the other peer */

		// Build the OneKey object for the identity public key of the other
		// peer
		OneKey peerPublicKey = null;

		switch (keyFormat) {
		/* For stand-alone testing, as base64 encoding of OneKey objects */
		case 0:
			// peerPublicKey = new
			// OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(peerPublicKeyBase64)));

			// ECDSA P256
			if (thePeerPublicKey.length == 64) {
				byte[] keyX = Arrays.copyOfRange(thePeerPublicKey, 0, 32);
				byte[] keyY = Arrays.copyOfRange(thePeerPublicKey, 32, 64);
				peerPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, keyX, keyY);
			} else {
				// OKP_Ed25519
				peerPublicKey = SharedSecretCalculation.buildEd25519OneKey(null, thePeerPublicKey);
			}

			break;

		/* Value from the test vectors, as binary serializations */
		case 1:
			// if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			// peerPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
			// peerPublicKeyBinary,
			// peerPublicKeyBinaryY);
			// } else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			// peerPublicKey = SharedSecretCalculation.buildEd25519OneKey(null,
			// peerPublicKeyBinary);
			// } else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			// peerPublicKey =
			// SharedSecretCalculation.buildCurve25519OneKey(null,
			// peerPublicKeyBinary);
			// }
			System.err.println("Bad key settings!");
			break;
		default:
			System.err.println("ERROR in key format switch!");
			break;
		}

		CBORObject peerIdCred = null;
		byte[] peerCred = null;

		switch (credType) {
		case Constants.CRED_TYPE_RPK:
			// Build the related ID_CRED
			// Use 0x24 as kid for the other peer, i.e. the serialized
			// ID_CRED_X is 0xa1, 0x04, 0x41, 0x24
			// byte[] peerKid = new byte[] { (byte) 0x24 };
			CBORObject idCredPeer = org.eclipse.californium.edhoc.Util.buildIdCredKid(peerKid);
			peerPublicKeys.put(idCredPeer, peerPublicKey);
			// Build the related CRED
			peerCred = org.eclipse.californium.edhoc.Util.buildCredRawPublicKey(peerPublicKey, "");
			peerCredentials.put(idCredPeer, CBORObject.FromObject(peerCred));
			System.out.println("Adding peer key");
			break;
		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}
		peerPublicKeys.put(peerIdCred, peerPublicKey);
		peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCred));
	}

}
