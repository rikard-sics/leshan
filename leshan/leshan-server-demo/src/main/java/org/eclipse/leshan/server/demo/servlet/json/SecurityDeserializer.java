/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
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
 *     Rikard Höglund (RISE SICS) - Additions to support OSCORE
 *     Rikard Höglund (RISE) - Additions to support EDHOC
 *******************************************************************************/
package org.eclipse.leshan.server.demo.servlet.json;

import java.io.IOException;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.AppProfile;
import org.eclipse.californium.edhoc.Constants;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocResource;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.SharedSecretCalculation;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.SecurityUtil;
import org.eclipse.leshan.server.OscoreHandler;
import org.eclipse.leshan.server.EdhocHandler;
import org.eclipse.leshan.server.security.SecurityInfo;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import com.google.gson.GsonBuilder;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class SecurityDeserializer implements JsonDeserializer<SecurityInfo> {

	boolean save = true;

	public SecurityDeserializer(boolean save) {
		this.save = save;
	}

	public SecurityDeserializer() {
		this.save = true;
	}

    @Override
    public SecurityInfo deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {

        if (json == null) {
            return null;
        }

        SecurityInfo info = null;

        if (json.isJsonObject()) {
            JsonObject object = (JsonObject) json;

            String endpoint;
            if (object.has("endpoint")) {
                endpoint = object.get("endpoint").getAsString();
            } else {
                throw new JsonParseException("Missing endpoint");
            }
            
            // Save config
			if (save == true) {
				saveEndpointConfig(object, endpoint);
			}

            JsonObject psk = (JsonObject) object.get("psk");
            JsonObject rpk = (JsonObject) object.get("rpk");
            JsonObject oscore = (JsonObject) object.get("oscore");
			JsonObject edhoc = (JsonObject) object.get("edhoc");
            JsonPrimitive x509 = object.getAsJsonPrimitive("x509");
            if (psk != null) {
                // PSK Deserialization
                String identity;
                if (psk.has("identity")) {
                    identity = psk.get("identity").getAsString();
                } else {
                    throw new JsonParseException("Missing PSK identity");
                }
                byte[] key;
                try {
                    key = Hex.decodeHex(psk.get("key").getAsString().toCharArray());
                } catch (IllegalArgumentException e) {
                    throw new JsonParseException("key parameter must be a valid hex string", e);
                }

                info = SecurityInfo.newPreSharedKeyInfo(endpoint, identity, key);
            } else if (rpk != null) {
                PublicKey key;
                try {
                    if (rpk.has("key")) {
                        byte[] bytekey = Hex.decodeHex(rpk.get("key").getAsString().toCharArray());
                        key = SecurityUtil.publicKey.decode(bytekey);
                    } else {
                        // This is just needed to keep API backward compatibility.
                        // TODO as this is not used anymore by the UI, we should maybe remove it.
                        byte[] x = Hex.decodeHex(rpk.get("x").getAsString().toCharArray());
                        byte[] y = Hex.decodeHex(rpk.get("y").getAsString().toCharArray());
                        String params = rpk.get("params").getAsString();

                        AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
                        algoParameters.init(new ECGenParameterSpec(params));
                        ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

                        KeySpec keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)),
                                parameterSpec);

                        key = KeyFactory.getInstance("EC").generatePublic(keySpec);
                    }
                } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
                    throw new JsonParseException("Invalid security info content", e);
                }
                info = SecurityInfo.newRawPublicKeyInfo(endpoint, key);
            } else if (x509 != null && x509.getAsBoolean()) {
                info = SecurityInfo.newX509CertInfo(endpoint);
            } else if (oscore != null) {
                // OSCORE Deserialization

                // Parse hexadecimal context parameters
                byte[] masterSecret = Hex.decodeHex(oscore.get("masterSecret").getAsString().toCharArray());
                byte[] senderId = Hex.decodeHex(oscore.get("senderId").getAsString().toCharArray());
                byte[] recipientId = Hex.decodeHex(oscore.get("recipientId").getAsString().toCharArray());

                // Check parameters that are allowed to be empty
                byte[] masterSalt = null;
                if (oscore.get("masterSalt") != null) {
                    masterSalt = Hex.decodeHex(oscore.get("masterSalt").getAsString().toCharArray());

                    if (masterSalt.length == 0) {
                        masterSalt = null;
                    }
                }

                // ID Context not supported
                byte[] idContext = null;

                // Parse AEAD Algorithm
                AlgorithmID aeadAlgorithm = null;
                try {
                    String aeadAlgorithmStr = oscore.get("aeadAlgorithm").getAsString();
                    aeadAlgorithm = AlgorithmID.valueOf(aeadAlgorithmStr);
                } catch (IllegalArgumentException e) {
                    throw new JsonParseException("Invalid AEAD algorithm", e);
                }
                if (aeadAlgorithm != AlgorithmID.AES_CCM_16_64_128) {
                    throw new JsonParseException("Unsupported AEAD algorithm");
                }

                // Parse HKDF Algorithm
                AlgorithmID hkdfAlgorithm = null;
                try {
                    String hkdfAlgorithmStr = oscore.get("hkdfAlgorithm").getAsString();
                    hkdfAlgorithm = AlgorithmID.valueOf(hkdfAlgorithmStr);
                } catch (IllegalArgumentException e) {
                    throw new JsonParseException("Invalid HKDF algorithm", e);
                }
                if (hkdfAlgorithm != AlgorithmID.HKDF_HMAC_SHA_256) {
                    throw new JsonParseException("Unsupported HKDF algorithm");
                }

                OSCoreCtx ctx = null;
                // Attempt to generate OSCORE Context from parsed parameters
                // Note that the sender and recipient IDs are inverted here
                try {
                    ctx = new OSCoreCtx(masterSecret, true, aeadAlgorithm, recipientId, senderId, hkdfAlgorithm, 32,
							masterSalt, idContext, 2048);

                    // Support Appendix B.2 functionality
					ctx.setContextRederivationEnabled(true);
                } catch (OSException e) {
                    throw new JsonParseException("Failed to generate OSCORE context", e);
                }

                info = SecurityInfo.newOSCoreInfo(endpoint, ctx);
			} else if (edhoc != null) {
				// EDHOC Deserialization
				Boolean initiator = edhoc.get("initiator").getAsBoolean();
				Long method = edhoc.get("authenticationMethod").getAsLong();
				Long selectedCiphersuite = edhoc.get("selectedCiphersuite").getAsLong();
				byte[] clientKeyIdentifier = Hex
						.decodeHex(edhoc.get("clientKeyIdentifier").getAsString().toCharArray());
				byte[] clientPublicKey = Hex.decodeHex(edhoc.get("clientPublicKey").getAsString().toCharArray());
				byte[] peerPublicKeyIdentifier = Hex
						.decodeHex(edhoc.get("peerPublicKeyIdentifier").getAsString().toCharArray());
				byte[] peerPublicKey = Hex.decodeHex(edhoc.get("peerPublicKey").getAsString().toCharArray());
				String peerEdhocCoapUriPath = edhoc.get("peerEdhocCoapUriPath").getAsString();
				Boolean edhocOscoreCombinedSupport = edhoc.get("edhocOscoreCombinedSupport").getAsBoolean();

				// RH: TODO: Remove debug print
				System.out.println("Configured EDHOC object: ");
				System.out.println("initiator: " + initiator);
				System.out.println("authenticationMethod: " + method);
				System.out.println("selectedCiphersuite: " + selectedCiphersuite);
				System.out.println("clientKeyIdentifier: " + Hex.encodeHexString(clientKeyIdentifier));
				System.out.println("clientPublicKey: " + Hex.encodeHexString(clientPublicKey));
				System.out.println("peerPublicKeyIdentifier: " + Hex.encodeHexString(peerPublicKeyIdentifier));
				System.out.println("peerPublicKey: " + Hex.encodeHexString(peerPublicKey));
				System.out.println("peerEdhocCoapUriPath: " + peerEdhocCoapUriPath);
				System.out.println("edhocOscoreCombinedSupport: " + edhocOscoreCombinedSupport);

				OSCoreCtx ctx = null;
				// Generate a placeholder OSCORE Context
				// RH: TODO: Do this differently?
				try {
					ctx = new OSCoreCtx(Bytes.EMPTY, true, AlgorithmID.AES_CCM_16_64_128, Bytes.EMPTY,
							new byte[] { 0x11, 0x22, 0x33, 0x44 },
							AlgorithmID.HKDF_HMAC_SHA_256, 32, null, null, 2048);
				} catch (OSException e) {
					throw new JsonParseException("Failed to generate placeholder OSCORE context", e);
				}
				info = SecurityInfo.newOSCoreInfo(endpoint, ctx);
				info.setBuiltFromEdhoc(true); // Started from EDHOC

				// Install crypto provider
				org.eclipse.californium.edhoc.Util.installCryptoProvider();

				// Set selectedCiphersuites
				setupSupportedCipherSuites();

				// Set cred(s) (Credential Identifier and Server Credential
				// Identifier). Set also my public and private key, and the
				// client's public key
				setupIdentityKeys(peerPublicKeyIdentifier, clientKeyIdentifier, peerPublicKey, clientPublicKey);

				// NEW
				// Set Authentication Method
				Set<Integer> authMethods = new HashSet<Integer>();
				authMethods.add(0);
				authMethods.add(1);
				authMethods.add(2);
				authMethods.add(3);
				AppProfile appStatement = new AppProfile(authMethods, false, true, false);
				appStatements.put(uriLocal,   appStatement);
				appStatements.put(uriLocal + "/.well-known/edhoc", appStatement);
				appStatements.put("/.well-known/edhoc", appStatement);

				Set<Integer> supportedEads = new HashSet<Integer>();
				HashMap<Integer, List<CBORObject>> eadProductionInput = null;

				// TODO
				// The asymmetric key pairs of this peer (one per supported
				// curve)
				// HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new
				// HashMap<Integer, HashMap<Integer, OneKey>>();

				// The identifiers of the authentication credentials of this
				// peer
				// HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new
				// HashMap<Integer, HashMap<Integer, CBORObject>>();

				// The authentication credentials of this peer (one per
				// supported curve)
				// HashMap<Integer, HashMap<Integer, CBORObject>> creds = new
				// HashMap<Integer, HashMap<Integer, CBORObject>>();

				// Fill maps
				// keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new
				// HashMap<Integer, OneKey>());
				// keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new
				// HashMap<Integer, OneKey>());
				// creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new
				// HashMap<Integer, CBORObject>());
				// creds.put(Integer.valueOf(Constants.ECDH_KEY), new
				// HashMap<Integer, CBORObject>());
				// idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new
				// HashMap<Integer, CBORObject>());
				// idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new
				// HashMap<Integer, CBORObject>());
				
				// Each element is the ID_CRED_X used for an authentication
				// credential
				// associated to this peer
				// Set<CBORObject> ownIdCreds = new HashSet<>();

				// --- Key Pairs ---
				    HashMap<Integer, OneKey> inner = EdhocHandler.keyPairs.get(Constants.ECDH_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 1 || method == 3)) {
					OneKey old = inner.put(Constants.CURVE_P256, keyPair);
					if (old != null && !oneKeysEqual(old, keyPair)) {
					    System.err.println("Warning: Overwriting existing ECDH key pair for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 1 || method == 3)) {
					OneKey old = inner.put(Constants.CURVE_X25519, keyPair);
					if (old != null && !oneKeysEqual(old, keyPair)) {
					    System.err.println("Warning: Overwriting existing ECDH key pair for X25519 with different value");
					}
				    }

				    inner = EdhocHandler.keyPairs.get(Constants.SIGNATURE_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 0 || method == 2)) {
					OneKey old = inner.put(Constants.CURVE_P256, keyPair);
					if (old != null && !oneKeysEqual(old, keyPair)) {
					    System.err.println("Warning: Overwriting existing signature key pair for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 0 || method == 2)) {
					OneKey old = inner.put(Constants.CURVE_Ed25519, keyPair);
					if (old != null && !oneKeysEqual(old, keyPair)) {
					    System.err.println("Warning: Overwriting existing signature key pair for Ed25519 with different value");
					}
				    }

				    // --- Creds ---
				    HashMap<Integer, CBORObject> innerC = EdhocHandler.creds.get(Constants.ECDH_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 1 || method == 3)) {
					CBORObject newCred = CBORObject.FromObject(cred);
					CBORObject old = innerC.put(Constants.CURVE_P256, newCred);
					if (old != null && !cborObjectsEqual(old, newCred)) {
					    System.err.println("Warning: Overwriting existing ECDH credentials for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 1 || method == 3)) {
					CBORObject newCred = CBORObject.FromObject(cred);
					CBORObject old = innerC.put(Constants.CURVE_X25519, newCred);
					if (old != null && !cborObjectsEqual(old, newCred)) {
					    System.err.println("Warning: Overwriting existing ECDH credentials for X25519 with different value");
					}
				    }

				    innerC = EdhocHandler.creds.get(Constants.SIGNATURE_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 0 || method == 2)) {
					CBORObject newCred = CBORObject.FromObject(cred);
					CBORObject old = innerC.put(Constants.CURVE_P256, newCred);
					if (old != null && !cborObjectsEqual(old, newCred)) {
					    System.err.println("Warning: Overwriting existing signature credentials for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 0 || method == 2)) {
					CBORObject newCred = CBORObject.FromObject(cred);
					CBORObject old = innerC.put(Constants.CURVE_Ed25519, newCred);
					if (old != null && !cborObjectsEqual(old, newCred)) {
					    System.err.println("Warning: Overwriting existing signature credentials for Ed25519 with different value");
					}
				    }

				    // --- ID Creds ---
				    HashMap<Integer, CBORObject> innerD = EdhocHandler.idCreds.get(Constants.ECDH_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 1 || method == 3)) {
					CBORObject old = innerD.put(Constants.CURVE_P256, idCred);
					if (old != null && !cborObjectsEqual(old, idCred)) {
					    System.err.println("Warning: Overwriting existing ECDH 'ID Cred' for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 1 || method == 3)) {
					CBORObject old = innerD.put(Constants.CURVE_X25519, idCred);
					if (old != null && !cborObjectsEqual(old, idCred)) {
					    System.err.println("Warning: Overwriting existing ECDH 'ID Cred' for X25519 with different value");
					}
				    }

				    innerD = EdhocHandler.idCreds.get(Constants.SIGNATURE_KEY);
				    if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 0 || method == 2)) {
					CBORObject old = innerD.put(Constants.CURVE_P256, idCred);
					if (old != null && !cborObjectsEqual(old, idCred)) {
					    System.err.println("Warning: Overwriting existing signature 'ID Cred' for P256 with different value");
					}
				    }
				    if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 0 || method == 2)) {
					CBORObject old = innerD.put(Constants.CURVE_Ed25519, idCred);
					if (old != null && !cborObjectsEqual(old, idCred)) {
					    System.err.println("Warning: Overwriting existing signature 'ID Cred' for Ed25519 with different value");
					}
				    }

				// Complete map with own ID creds
				EdhocHandler.ownIdCreds.add(idCred);

				if (EdhocHandler.getEndpointAdded() == false) {
					HashMapCtxDB db = OscoreHandler.getContextDB();

					EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(EdhocHandler.idCreds,
							EdhocHandler.creds, EdhocHandler.keyPairs, EdhocHandler.peerPublicKeys,
							EdhocHandler.peerCredentials, edhocSessions,
							usedConnectionIds, supportedCiphersuites, supportedEads, eadProductionInput,
							Constants.TRUST_MODEL_NO_LEARNING, db, uriLocal, OSCORE_REPLAY_WINDOW, 2048, appStatements);

					System.out.println("*** App profiles ");
					for (String name : edhocEndpointInfo.getAppProfiles().keySet()) {
						String key = name.toString();
						String value = edhocEndpointInfo.getAppProfiles().get(name).toString();
						System.out.println(key + " " + value);
					}

					// Build well-known and EDHOC resource
					// provide an instance of a .well-known/edhoc resource
					CoapResource edhocResource = new EdhocResource("edhoc", edhocEndpointInfo, EdhocHandler.ownIdCreds);
					CoapResource wellKnownResource = new WellKnown();
					wellKnownResource.add(edhocResource);

					// Add resource to the CoapServer
					if (OscoreHandler.getLwServer() != null) {
						OscoreHandler.getLwServer().add(wellKnownResource);
						EdhocHandler.setEndpointAdded(true);
					}
				}

            } else {
                throw new JsonParseException("Invalid security info content");
            }
        }

        return info;
    }

	/* === RH: EDHOC support methods === */

	// RH: Variables for initializing EdhocEndpointInfo
	// Set in setupIdentityKeys() or setupSupportedCipherSuites()
	static OneKey keyPair = null;
	static int credType = Constants.CRED_TYPE_CCS;
	static byte[] cred = null;
	static CBORObject idCred = null;
	static String subjectName = "";
	// static HashMap<CBORObject, OneKey> peerPublicKeys = new
	// HashMap<CBORObject, OneKey>();
	// static HashMap<CBORObject, CBORObject> peerCredentials = new
	// HashMap<CBORObject, CBORObject>();
	static List<Integer> supportedCiphersuites = new ArrayList<Integer>();
	// Other variables needed
	static HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	static Set<CBORObject> usedConnectionIds = new HashSet<CBORObject>();
	static String uriLocal = "coap://localhost";
	static final int OSCORE_REPLAY_WINDOW = 32;
	static HashMap<String, AppProfile> appStatements = new HashMap<String, AppProfile>();

	/**
	 * RH: General method for setting up all EDHOC parameters needed to build
	 * the EdhocEndpointInfo
	 */


	/**
	 * RH: Imported from the EDHOC code EdhocServer.
	 */
	private static void setupSupportedCipherSuites() {

		supportedCiphersuites.add(0);
		supportedCiphersuites.add(1);
		supportedCiphersuites.add(2);
		supportedCiphersuites.add(3);
		supportedCiphersuites.add(4);
		supportedCiphersuites.add(5);
		supportedCiphersuites.add(6);

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
	private static void setupIdentityKeys(byte[] idCredKid, byte[] peerKid, byte[] myPublicPrivateKey,
			byte[] thePeerPublicKey) {

		// Build COSE OneKey for server, including public and private keys
		try {
			keyPair = oneKeyFromCcs(myPublicPrivateKey, true);
		} catch (CoseException e1) {
			System.err.println("Failed to generate public/private COSE OneKey for server in SecurityDeserializer.java");
			e1.printStackTrace();
		}

		switch (credType) {
		case Constants.CRED_TYPE_CCS:
			// Build the related ID_CRED
			// Use 0x07 as kid for this peer, i.e. the serialized ID_CRED_X
			// is 0xa1, 0x04, 0x41, 0x07
			// byte[] idCredKid = new byte[] { (byte) 0x24 };
			System.out.println("This peer ID CRED " + Utils.toHexString(idCredKid));
			idCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(idCredKid);

			// Build the related CRED (first remove private key)
			cred = stripPrivateKeyFromCcs(myPublicPrivateKey).clone();
			System.out.println("Adding key: " + StringUtil.byteArray2Hex(cred));
			break;

		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}

		/* Settings for the other peer */

		// Build COSE OneKey for server, including public key
		OneKey peerPublicKey = null;
		CBORObject peerIdCred = null;
		byte[] peerCred = null;

		try {
			peerPublicKey = oneKeyFromCcs(thePeerPublicKey, false);
		} catch (CoseException e1) {
			System.err.println("Failed to generate public/private COSE OneKey for client in SecurityDeserializer.java");
			e1.printStackTrace();
		}

		switch (credType) {
		case Constants.CRED_TYPE_CCS:
			// Build the related ID_CRED
			// Use 0x24 as kid for the other peer, i.e. the serialized
			// ID_CRED_X is 0xa1, 0x04, 0x41, 0x24
			// byte[] peerKid = new byte[] { (byte) 0x07 };
			System.out.println("Peer ID Cred " + Utils.toHexString(peerKid));
			CBORObject idCredPeer = org.eclipse.californium.edhoc.Util.buildIdCredKid(peerKid);
			EdhocHandler.peerPublicKeys.put(idCredPeer, peerPublicKey);
			// Set the related CRED (full CCS)
			peerCred = thePeerPublicKey.clone();
			EdhocHandler.peerCredentials.put(idCredPeer, CBORObject.FromObject(peerCred));
			System.out.println("Adding peer key: " + StringUtil.byteArray2Hex(peerCred));
			break;
		default:
			System.err.println("ERROR in cred type switch!");
			break;
		}
		EdhocHandler.peerPublicKeys.put(peerIdCred, peerPublicKey);
		EdhocHandler.peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCred));
	}

	/*
	 * Definition of the .well-known Resource
	 */
	static class WellKnown extends CoapResource {

		public WellKnown() {

			// set resource identifier
			super(".well-known");

			// set display name
			getAttributes().setTitle(".well-known");

		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond(".well-known");
		}
	}
	
	
	// --- Utility methods ---
	
	public static boolean oneKeysEqual(OneKey a, OneKey b) {
	    if (a == null || b == null)
	    	return false;
	    
	    try {
		byte[] aBytes = a.AsCBOR().EncodeToBytes();
		byte[] bBytes = b.AsCBOR().EncodeToBytes();
		return Arrays.equals(aBytes, bBytes);
	    } catch (Exception e) {
		return false;
	    }
	}

	public static boolean cborObjectsEqual(CBORObject a, CBORObject b) {
	    if (a == null || b == null)
	    	return false;
	    
	    try {
		byte[] aBytes = a.EncodeToBytes();
		byte[] bBytes = b.EncodeToBytes();
		return Arrays.equals(aBytes, bBytes);
	    } catch (Exception e) {
		return false;
	    }
	}
	
	/**
	 * Extracts the innermost COSE_Key map from a CCS and returns it as a COSE
	 * OneKey. Note that if the CCS returns a private key it will be included in
	 * the constructed OneKey.
	 *
	 * Assumes CCS layout like: { ..., 8: { 1: { <COSE_Key map> } } }
	 *
	 * @param ccsBytes CBOR-encoded CCS bytes
	 * @param requirePrivate if a private key must exist in the CCS
	 * @return OneKey created from the extracted COSE_Key portion only
	 */
	public static OneKey oneKeyFromCcs(byte[] ccsBytes, boolean requirePrivate) throws CoseException {
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

		// Work on a copy so to not never change the decoded CCS structure
		CBORObject keyMap = CBORObject.DecodeFromBytes(coseKeyMap.EncodeToBytes());

		CBORObject dObj = keyMap.get(CBORObject.FromObject(-4));
		if (requirePrivate && dObj == null) {
			throw new IllegalArgumentException("CCS COSE_Key is missing required private key parameter -4");
		}

		if (dObj != null && dObj.getType() != CBORType.ByteString) {
			throw new IllegalArgumentException("CCS COSE_Key private key parameter -4 is not a byte string");
		}

		// Hhandling for keys with curve X25519 (they must be built by a
		// separate method as the OneKey constructor can currently not handle
		// them)
		OneKey keyToReturn = null;

		if (keyMap.ContainsKey(CBORObject.FromObject(-1))
				&& keyMap.get(CBORObject.FromObject(-1)).equals(CBORObject.FromObject(4))) {

			CBORObject xObj = keyMap.get(CBORObject.FromObject(-2));
			if (xObj == null) {
				throw new IllegalArgumentException("X25519 COSE_Key is missing public key parameter -2");
			}
			if (xObj.getType() != CBORType.ByteString) {
				throw new IllegalArgumentException("X25519 COSE_Key public key parameter -2 is not a byte string");
			}

			byte[] publicKeyBytes = xObj.GetByteString();

			// Extract private key parameter (-4) if present in CCS
			byte[] privateKeyBytes = null;
			if (dObj != null) {
				privateKeyBytes = dObj.GetByteString();
			}

			keyToReturn = SharedSecretCalculation.buildCurve25519OneKey(privateKeyBytes, publicKeyBytes);
		} else {
			// Normal handling for non-X25519 keys
			keyToReturn = new OneKey(keyMap);
		}

		return keyToReturn;
	}

	/**
	 * Removes COSE private key parameter (-4, 'd') from the embedded COSE_Key
	 * inside a CCS, while preserving the full CCS structure.
	 *
	 * Assumes CCS layout like: { ..., 8: { 1: { <COSE_Key map possibly
	 * containing -4> } } }
	 *
	 * @param ccsBytes CCS bytes (may contain public+private)
	 * @return CCS bytes with -4 removed from the embedded COSE_Key map
	 */
	public static byte[] stripPrivateKeyFromCcs(byte[] ccsBytes) {
		if (ccsBytes == null || ccsBytes.length == 0) {
			throw new IllegalArgumentException("ccsBytes is null/empty");
		}

		CBORObject ccs = CBORObject.DecodeFromBytes(ccsBytes);
		if (ccs.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS root is not a CBOR map");
		}

		CBORObject claim8 = ccs.get(CBORObject.FromObject(8));
		if (claim8 == null || claim8.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS missing claim 8 map");
		}

		CBORObject coseKeyMap = claim8.get(CBORObject.FromObject(1));
		if (coseKeyMap == null || coseKeyMap.getType() != CBORType.Map) {
			throw new IllegalArgumentException("CCS claim 8/1 is not a COSE_Key map");
		}

		// Remove private key parameter -4 (OKP/EC2/RSA private component label
		// used by COSE)
		coseKeyMap.Remove(CBORObject.FromObject(-4));

		// Re-encode the full CCS with only that field removed
		return ccs.EncodeToBytes();
	}

	private void saveEndpointConfig(JsonObject object, String endpoint) throws JsonParseException {
	    if (endpoint == null || endpoint.trim().isEmpty()) {
	        throw new JsonParseException("Endpoint is empty");
	    }

	    String safeEndpoint = endpoint.replaceAll("[^a-zA-Z0-9._-]", "_");

	    Path directory = Paths.get("data", "endpoints");
	    Path file = directory.resolve(safeEndpoint + ".json");

	    try {
	        Files.createDirectories(directory);

	        try (BufferedWriter writer = Files.newBufferedWriter(
	                file,
	                StandardCharsets.UTF_8,
	                StandardOpenOption.CREATE,
	                StandardOpenOption.TRUNCATE_EXISTING,
	                StandardOpenOption.WRITE
	        )) {
	            new GsonBuilder()
	                    .setPrettyPrinting()
	                    .create()
	                    .toJson(object, writer);
	        }

	    } catch (IOException e) {
	        throw new JsonParseException(
	                "Failed to save endpoint config to " + file.toAbsolutePath(),
	                e
	        );
	    }
	    System.out.println("Saving endpoint config to " + file.toAbsolutePath());
	}
	
}
