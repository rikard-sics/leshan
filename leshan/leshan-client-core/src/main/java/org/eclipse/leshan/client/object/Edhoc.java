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
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.AppProfile;
import org.eclipse.californium.edhoc.ClientEdhocExecutor;
import org.eclipse.californium.edhoc.Constants;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.leshan.client.OscoreHandler;
import org.eclipse.leshan.client.resource.BaseInstanceEnabler;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.model.ResourceModel.Type;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.datatype.ULong;

/**
 * A simple {@link LwM2mInstanceEnabler} for the EDHOC Security (29) object.
 */
public class Edhoc extends BaseInstanceEnabler {

    private static final Logger LOG = LoggerFactory.getLogger(Security.class);

    private final static List<Integer> supportedResources = Arrays.asList(Initiator, Method, Selected_Ciphersuite,
            Client_Key_Identifier, Client_Public_Key, Private_Key, Peer_Public_Key_Identifier, Peer_Public_Key,
			Peer_Edhoc_Coap_Uri_Path, Edhoc_Oscore_Combined_Support);

	public byte[] peerPublicKeyIdentifier;
	public byte[] peerPublicKey;
    public byte[] clientKeyIdentifier;
    public byte[] clientPublicKey;
    public byte[] privateKey;
	public ULong authenticationMethod;
	public boolean initiator;
	public ULong selectedCiphersuite;
	public String peerEdhocCoapUriPath;
    public boolean edhocOscoreCombinedSupport;

    public Edhoc() {

    }

    /**
     * Default constructor.
     */
    public Edhoc(int instanceId, boolean initiator, long authenticationMethod, long selectedCiphersuite,
            byte[] clientKeyIdentifier,
			byte[] clientPublicKey, byte[] privateKey, byte[] peerPublicKeyIdentifier, byte[] peerPublicKey,
			String peerEdhocCoapUriPath, boolean edhocOscoreCombinedSupport) {
        super(instanceId);

        this.initiator = initiator;
        this.authenticationMethod = ULong.valueOf(authenticationMethod);
        this.selectedCiphersuite = ULong.valueOf(selectedCiphersuite);
        this.clientKeyIdentifier = clientKeyIdentifier;
        this.clientPublicKey = clientPublicKey;
        this.privateKey = privateKey;
        this.peerPublicKeyIdentifier = peerPublicKeyIdentifier;
        this.peerPublicKey = peerPublicKey;
		this.peerEdhocCoapUriPath = peerEdhocCoapUriPath;
        this.edhocOscoreCombinedSupport = edhocOscoreCombinedSupport;
    }


    @Override
    public WriteResponse write(ServerIdentity identity, boolean replace, int resourceId, LwM2mResource value) {
        LOG.debug("Write on resource {}: {}", resourceId, value);

        // restricted to BS server?

        // TODO RH: Remove debug print
        if (resourceId == Edhoc_Oscore_Combined_Support) {
            System.out.println("Client received EDHOC object from " + identity);
            System.out.println("initiator: " + initiator);
            System.out.println("authenticationMethod: " + authenticationMethod);
            System.out.println("selectedCiphersuite: " + selectedCiphersuite);
            System.out.println("clientKeyIdentifier: " + Hex.encodeHexString(clientKeyIdentifier));
            System.out.println("clientPublicKey: " + Hex.encodeHexString(clientPublicKey));
            System.out.println("privateKey: " + Hex.encodeHexString(privateKey));
            System.out.println("peerPublicKeyIdentifier: " + Hex.encodeHexString(peerPublicKeyIdentifier));
            System.out.println("peerPublicKey: " + Hex.encodeHexString(peerPublicKey));
			System.out.println("peerEdhocCoapUriPath: " + peerEdhocCoapUriPath);
            System.out.println("edhocOscoreCombinedSupport: " + (boolean) value.getValue());
        }

		// RH: Run EDHOC now
		// RH: TODO: Do somewhere else instead?
		if (resourceId == Edhoc_Oscore_Combined_Support && !OscoreHandler.getEdhocWithDmDone()) {

			// Utils.printPause("Running EDHOC with Device Manager");
			
			// Install crypto provider
			org.eclipse.californium.edhoc.Util.installCryptoProvider();

			// Set params
			setupEdhocParameters();

			// Set selectedCiphersuite
			System.out.println("Suite: " + selectedCiphersuite);
			setupSupportedCipherSuites(selectedCiphersuite.intValue());

			// Set cred(s) (Credential Identifier and Server Credential
			// Identifier). Set also my public and private key, and the server's
			// public key
			setupIdentityKeys(clientKeyIdentifier, peerPublicKeyIdentifier, privateKey, clientPublicKey,
					peerPublicKey);

			// Specify the processor of External Authorization Data
			String args[] = new String[0];
			HashMapCtxDB db = OscoreHandler.getContextDB();
			// String edhocURI = identity.getUri() + "/.well-known/edhoc";
			String edhocURI = OscoreHandler.getlwServerUri() + "/.well-known/edhoc";
			// String edhocURI = "coap://127.0.0.2" + "/.well-known/edhoc";
			System.out.println("Running EDHOC with DM at: " + edhocURI);

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
			AppProfile appStatement = new AppProfile(authMethods, false, true, false);
			appStatements.put(edhocURI, appStatement);

			Set<Integer> supportedEads = new HashSet<Integer>();
			HashMap<Integer, List<CBORObject>> eadProductionInput = null;

			// TODO
			// The asymmetric key pairs of this peer (one per supported curve)
			HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();

			// The identifiers of the authentication credentials of this peer
			HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

			// The authentication credentials of this peer (one per supported curve)
			HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

			// Each element is the ID_CRED_X used for an authentication credential
			// associated to this peer
			Set<CBORObject> ownIdCreds = new HashSet<>();

			// Fill maps
			keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
			keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
			creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
			creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
			idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
			idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());

			// Build an integer
			int method = authenticationMethod.intValue();
			int suite = selectedCiphersuite.intValue();
			// Key Pairs
			HashMap<Integer, OneKey> inner = keyPairs.get(Constants.ECDH_KEY);
			if ((suite == 2 || suite == 3) && (method == 1 || method == 3)) {
			    inner.put(Constants.CURVE_P256, keyPair);
			}
			if ((suite == 0 || suite == 1) && (method == 1 || method == 3)) {
			    inner.put(Constants.CURVE_X25519, keyPair);
			}
			
			inner = keyPairs.get(Constants.SIGNATURE_KEY);
			if ((suite == 2 || suite == 3) && (method == 0 || method == 2)) {
			    inner.put(Constants.CURVE_P256, keyPair);
			}
			if ((suite == 0 || suite == 1) && (method == 0 || method == 2)) {
			    inner.put(Constants.CURVE_Ed25519, keyPair);
			}
			
			// --- Creds ---
			HashMap<Integer, CBORObject> innerC = creds.get(Constants.ECDH_KEY);
			if ((suite == 2 || suite == 3) && (method == 1 || method == 3)) {
			    CBORObject newCred = CBORObject.FromObject(cred);
			    innerC.put(Constants.CURVE_P256, newCred);
			}
			if ((suite == 0 || suite == 1) && (method == 1 || method == 3)) {
			    CBORObject newCred = CBORObject.FromObject(cred);
			    innerC.put(Constants.CURVE_X25519, newCred);
			}
			
			innerC = creds.get(Constants.SIGNATURE_KEY);
			if ((suite == 2 || suite == 3) && (method == 0 || method == 2)) {
			    CBORObject newCred = CBORObject.FromObject(cred);
			    innerC.put(Constants.CURVE_P256, newCred);
			}
			if ((suite == 0 || suite == 1) && (method == 0 || method == 2)) {
			    CBORObject newCred = CBORObject.FromObject(cred);
			    innerC.put(Constants.CURVE_Ed25519, newCred);
			}
			
			// --- ID Creds ---
			HashMap<Integer, CBORObject> innerD = idCreds.get(Constants.ECDH_KEY);
			if ((suite == 2 || suite == 3) && (method == 1 || method == 3)) {
			    innerD.put(Constants.CURVE_P256, idCred);
			}
			if ((suite == 0 || suite == 1) && (method == 1 || method == 3)) {
			    innerD.put(Constants.CURVE_X25519, idCred);
			}
			
			innerD = idCreds.get(Constants.SIGNATURE_KEY);
			if ((suite == 2 || suite == 3) && (method == 0 || method == 2)) {
			    innerD.put(Constants.CURVE_P256, idCred);
			}
			if ((suite == 0 || suite == 1) && (method == 0 || method == 2)) {
			    innerD.put(Constants.CURVE_Ed25519, idCred);
			}
			
			// Complete map
			ownIdCreds.add(idCred);

			EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCreds, creds, keyPairs, peerPublicKeys,
					peerCredentials, edhocSessions, usedConnectionIds, supportedCiphersuites, supportedEads,
					eadProductionInput, Constants.TRUST_MODEL_NO_LEARNING, db, edhocURI, OSCORE_REPLAY_WINDOW, 2048,
					appStatements);


			// Possibly specify external authorization data for EAD_1, or null
			// if
			// none have to be provided
			// The first element of EAD is always a CBOR integer, followed by
			// one or
			// multiple additional elements
			CBORObject[] ead1 = null;

			// Further params
			// CoAP method to use for the application request sent after the
			// EDHOC
			// execution
			Code appRequestCode = Code.GET;
			// CoAP message type to use (CON or NON) for the application request
			// sent after the EDHOC execution
			// CoAP method to use for the application request sent within an
			// EDHOC +
			// OSCORE combined request
			Code combinedRequestAppCode = Code.GET;
			// CoAP message type to use (CON or NON) for the application request
			// sent within an EDHOC + OSCORE combined request
			Type combinedRequestAppType = null;
			// Payload of the application request sent within an EDHOC + OSCORE
			// combined request. It can be null
			byte[] combinedRequestAppPayload = null;

			System.out.println("Running EDHOC with Device Manager: ");
			ClientEdhocExecutor edhocExecutor = new ClientEdhocExecutor();
			List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
			boolean ret = edhocExecutor.startEdhocExchangeAsInitiator(authenticationMethod.intValue(),
					peerSupportedCipherSuites, ownIdCreds, edhocEndpointInfo, false, "", combinedRequestAppCode,
					null, combinedRequestAppPayload);
			System.out.println("EDHOC succeeded: " + ret);
			
			OscoreHandler.setEdhocWithDmDone(true);
		} else if (resourceId == Edhoc_Oscore_Combined_Support && OscoreHandler.getEdhocWithDmDone()) {
			Edhoc temp = new Edhoc(100, initiator, authenticationMethod.longValue(), selectedCiphersuite.longValue(),
		            clientKeyIdentifier,
		            clientPublicKey, privateKey, peerPublicKeyIdentifier, peerPublicKey,
					peerEdhocCoapUriPath, edhocOscoreCombinedSupport);
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

        case Method:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            authenticationMethod = (ULong) value.getValue();
            return WriteResponse.success();

        case Selected_Ciphersuite:
            if (value.getType() != Type.UNSIGNED_INTEGER) {
                return WriteResponse.badRequest("invalid type");
            }
            selectedCiphersuite = (ULong) value.getValue();
            return WriteResponse.success();

        case Client_Key_Identifier:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            clientKeyIdentifier = (byte[]) value.getValue();
            return WriteResponse.success();

        case Client_Public_Key:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            clientPublicKey = (byte[]) value.getValue();
            return WriteResponse.success();

        case Private_Key:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            privateKey = (byte[]) value.getValue();
            return WriteResponse.success();

        case Peer_Public_Key_Identifier:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            peerPublicKeyIdentifier = (byte[]) value.getValue();
            return WriteResponse.success();

        case Peer_Public_Key:
            if (value.getType() != Type.OPAQUE) {
                return WriteResponse.badRequest("invalid type");
            }
            peerPublicKey = (byte[]) value.getValue();
            return WriteResponse.success();

        case Peer_Edhoc_Coap_Uri_Path:
			if (value.getType() != Type.STRING) {
                return WriteResponse.badRequest("invalid type");
            }
			peerEdhocCoapUriPath = (String) value.getValue();
            return WriteResponse.success();

        case Edhoc_Oscore_Combined_Support:
            if (value.getType() != Type.BOOLEAN) {
                return WriteResponse.badRequest("invalid type");
            }
            edhocOscoreCombinedSupport = (boolean) value.getValue();
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

        case Method:
            return ReadResponse.success(resourceid, authenticationMethod);

        case Selected_Ciphersuite:
            return ReadResponse.success(resourceid, selectedCiphersuite);

        case Client_Key_Identifier:
            return ReadResponse.success(resourceid, clientKeyIdentifier);

        case Client_Public_Key:
            return ReadResponse.success(resourceid, clientPublicKey);

        case Private_Key:
            return ReadResponse.success(resourceid, privateKey);

        case Peer_Public_Key_Identifier:
            return ReadResponse.success(resourceid, peerPublicKeyIdentifier);

        case Peer_Public_Key:
            return ReadResponse.success(resourceid, peerPublicKey);

        case Peer_Edhoc_Coap_Uri_Path:
            return ReadResponse.success(resourceid, peerEdhocCoapUriPath);

        case Edhoc_Oscore_Combined_Support:
            return ReadResponse.success(resourceid, edhocOscoreCombinedSupport);

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
	static int credType = Constants.CRED_TYPE_CCS;
	static byte[] cred = null;
	static CBORObject idCred = null;
	static String subjectName = "";
	static HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	static HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
	static List<Integer> supportedCiphersuites = new ArrayList<Integer>();
	// Other variables needed
	static final int keyCurve = KeyKeys.EC2_P256.AsInt32(); // ECDSA
	static HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	static Set<CBORObject> usedConnectionIds = OscoreHandler.getUsedConnectionIds();
	static String uriLocal = "coap://localhost";
	static final int OSCORE_REPLAY_WINDOW = 32;
	static HashMap<String, AppProfile> appStatements = new HashMap<String, AppProfile>();;
	final static int keyFormat = 0; //

	/**
	 * RH: General method for setting up all EDHOC parameters needed to build
	 * the EdhocEndpointInfo
	 */
	private static void setupEdhocParameters() {
		// Set<Integer> authMethods = new HashSet<Integer>();
		// authMethods.add(Constants.EDHOC_AUTH_METHOD_0);
		// AppProfile appStatement = new AppProfile(true, authMethods,
		// false, true);

		// appStatements.put(uriLocal + "/.well-known/edhoc", appStatement);

//		for (int i = 0; i < 4; i++) {
//			// Empty sets of assigned Connection Identifiers; one set for each
//			// possible size in bytes.
//			// The set with index 0 refers to Connection Identifiers with size 1
//			// byte
//			usedConnectionIds.add(new HashSet<Integer>());
//		}

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

		// Build COSE OneKey for client, including public and private keys
		try {
			keyPair = oneKeyFromCcs(myPublicKey, myPrivateKey);
		} catch (CoseException e1) {
			System.err.println("Failed to generate public/private COSE OneKey for client in Edhoc.java");
			e1.printStackTrace();
		}

		switch (credType) {
		case Constants.CRED_TYPE_CCS:
			// Build the related ID_CRED
			// Use 0x07 as kid for this peer, i.e. the serialized ID_CRED_X
			// is 0xa1, 0x04, 0x41, 0x07
			// byte[] idCredKid = new byte[] { (byte) 0x07 };
			idCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(idCredKid);
			// Set the related CRED (full CCS)
			cred = myPublicKey.clone();
			System.out.println("Adding key: " + StringUtil.byteArray2Hex(cred));
			break;

		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}

		/* Settings for the other peer */

		// Build COSE OneKey for server, including public key
		OneKey peerPublicKey = null;
		byte[] peerCred = null;
		CBORObject peerIdCred = null;

		try {
			peerPublicKey = oneKeyFromCcs(thePeerPublicKey);
		} catch (CoseException e1) {
			System.err.println("Failed to generate public COSE OneKey for server in Edhoc.java");
			e1.printStackTrace();
		}

		switch (credType) {
		case Constants.CRED_TYPE_CCS:
			// Build the related ID_CRED
			// Use 0x24 as kid for the other peer, i.e. the serialized
			// ID_CRED_X is 0xa1, 0x04, 0x41, 0x24
			// byte[] peerKid = new byte[] { (byte) 0x24 };
			CBORObject idCredPeer = org.eclipse.californium.edhoc.Util.buildIdCredKid(peerKid);
			peerPublicKeys.put(idCredPeer, peerPublicKey);
			// Build the related CRED
			peerCred = thePeerPublicKey.clone();
			peerCredentials.put(idCredPeer, CBORObject.FromObject(peerCred));
			System.out.println("Adding peer key: " + StringUtil.byteArray2Hex(peerCred));
			break;
		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}
		peerPublicKeys.put(peerIdCred, peerPublicKey);
		peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCred));
	}

	// --- Utility methods ---

	/**
	 * Extracts the innermost COSE_Key map from a CCS and returns it as a COSE
	 * OneKey.
	 *
	 * Assumes CCS layout like: { ..., 8: { 1: { <COSE_Key map> } } }
	 *
	 * @param ccsBytes CBOR-encoded CCS bytes
	 * @param privateKey optional private key bytes to add as COSE label -4 (d)
	 * @return OneKey created from the extracted COSE_Key portion only
	 */
	public static OneKey oneKeyFromCcs(byte[] ccsBytes, byte[] privateKey) throws CoseException {
		if (ccsBytes == null || ccsBytes.length == 0) {
			throw new IllegalArgumentException("ccsBytes is null/empty");
		}

		CBORObject ccs = CBORObject.DecodeFromBytes(ccsBytes);
		if (ccs == null || ccs.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS root is not a CBOR map");
		}

		// CCS claim 8 -> map; inside it key 1 -> COSE_Key map
		CBORObject claim8 = ccs.get(CBORObject.FromObject(8));
		if (claim8 == null || claim8.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS does not contain claim 8 as a map");
		}

		CBORObject coseKeyMap = claim8.get(CBORObject.FromObject(1));
		if (coseKeyMap == null || coseKeyMap.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS claim 8 does not contain key 1 as a COSE_Key map");
		}

		// Work on a copy so to not never mutate the decoded CCS structure
		CBORObject keyMap = CBORObject.DecodeFromBytes(coseKeyMap.EncodeToBytes());

		// If caller provided private key -> inject as -4.
		CBORObject dLabel = CBORObject.FromObject(-4);
		if (privateKey != null && privateKey.length > 0) {
			keyMap.Set(dLabel, CBORObject.FromObject(Arrays.copyOf(privateKey, privateKey.length)));
		}

		return new OneKey(keyMap);
	}

	/**
	 * Convenience overload: public-only OneKey.
	 */
	public static OneKey oneKeyFromCcs(byte[] ccsBytes) throws CoseException {
		return oneKeyFromCcs(ccsBytes, null);
	}

}
