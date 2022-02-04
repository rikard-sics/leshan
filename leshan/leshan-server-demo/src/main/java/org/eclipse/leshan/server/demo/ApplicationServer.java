package org.eclipse.leshan.server.demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.AppStatement;
import org.eclipse.californium.edhoc.Constants;
import org.eclipse.californium.edhoc.EdhocClient;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocResource;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.KissEDP;
import org.eclipse.californium.edhoc.SharedSecretCalculation;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreResource;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.server.OscoreHandler;
import org.eclipse.leshan.server.security.SecurityInfo;

import com.google.gson.JsonParseException;
import com.upokecenter.cbor.CBORObject;

public class ApplicationServer {

	public static void main(String[] args) {
		// Application Server EDHOC Configuration (read from file)
//		Boolean initiator = edhoc.get("initiator").getAsBoolean();
//		Long authenticationMethod = edhoc.get("authenticationMethod").getAsLong();
//		Long ciphersuite = edhoc.get("ciphersuite").getAsLong();
//		byte[] credentialIdentifier = Hex
//				.decodeHex(edhoc.get("credentialIdentifier").getAsString().toCharArray());
//		byte[] publicCredential = Hex.decodeHex(edhoc.get("publicCredential").getAsString().toCharArray());
//		byte[] serverCredentialIdentifier = Hex
//				.decodeHex(edhoc.get("serverCredentialIdentifier").getAsString().toCharArray());
//		byte[] serverKey = Hex.decodeHex(edhoc.get("serverPublicKey").getAsString().toCharArray());
//		Long oscoreMasterSecretLength = edhoc.get("oscoreMasterSecretLength").getAsLong();
//		Long oscoreMasterSaltLength = edhoc.get("oscoreMasterSaltLength").getAsLong();
//		Boolean edhocOscoreCombined = edhoc.get("edhocOscoreCombined").getAsBoolean();

		Boolean initiator = false;
		Long authenticationMethod = 0L;
		Long ciphersuite = 2L;
		byte[] credentialIdentifier = hexStringToByteArray("08");
		byte[] publicCredential = hexStringToByteArray("67599A00256435C1E8519F555C47AC1D8B2FC24C65A8382602B865C67FF86054B99B120A187985E732DE7E0EA7E959649DB15DD6ECCFC0D8EEA4662DD2156AF9");
		byte[] serverCredentialIdentifier = hexStringToByteArray("25");
		byte[] serverKey = hexStringToByteArray("D709BFA1CB5C9B52ED7C29300932F8EC997721E16DC777B470EE64C5DE871B2DF5924DD07D48217FF82197A72EE0B72F2A8A9751DF4B7A1E0745190A3C5628805EF242B57557049C268CC6B861D45B71D823A57A8CE7B4B609910D3EB5064273");
		Long oscoreMasterSecretLength = 16L;
		Long oscoreMasterSaltLength = 8L;
		Boolean edhocOscoreCombined = false;

		
		// RH: TODO: Remove debug print
		System.out.println("Configured EDHOC object: ");
		System.out.println("initiator: " + initiator);
		System.out.println("authenticationMethod: " + authenticationMethod);
		System.out.println("ciphersuite: " + ciphersuite);
		System.out.println("credentialIdentifier: " + Hex.encodeHexString(credentialIdentifier));
		System.out.println("publicCredential: " + Hex.encodeHexString(publicCredential));
		System.out.println("serverCredentialIdentifier: " + Hex.encodeHexString(serverCredentialIdentifier));
		System.out.println("serverPublicKey: " + Hex.encodeHexString(serverKey));
		System.out.println("oscoreMasterSecretLength: " + oscoreMasterSecretLength);
		System.out.println("oscoreMasterSaltLength: " + oscoreMasterSaltLength);
		System.out.println("edhocOscoreCombined: " + edhocOscoreCombined);

		OSCoreCtx ctx = null;
		// Generate a placeholder OSCORE Context
		// RH: TODO: Do this differently?
		try {
			ctx = new OSCoreCtx(Bytes.EMPTY, true, AlgorithmID.AES_CCM_16_64_128, Bytes.EMPTY,
					new byte[] { 0x11, 0x22, 0x33, 0x44 },
					AlgorithmID.HKDF_HMAC_SHA_256, 32, null, null);
		} catch (OSException e) {
			throw new JsonParseException("Failed to generate placeholder OSCORE context", e);
		}

		// Install crypto provider
		EdhocClient.installCryptoProvider();

		// Build EDHOC endpoint info
		setupEdhocParameters();

		// Set ciphersuite
		setupSupportedCipherSuites(ciphersuite.intValue());

		// Set cred(s) (Credential Identifier and Server Credential
		// Identifier). Set also my public and private key, and the
		// client's public key
		byte[] serverPrivateKey = Arrays.copyOfRange(serverKey, 0, 32);
		byte[] serverPublicKey = Arrays.copyOfRange(serverKey, 32, serverKey.length);
		setupIdentityKeys(serverCredentialIdentifier, credentialIdentifier, serverPrivateKey, serverPublicKey,
				publicCredential);

		HashMapCtxDB db = OscoreHandler.getContextDB();
		EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCred, cred, keyPair, peerPublicKeys,
				peerCredentials, edhocSessions, usedConnectionIds, supportedCiphersuites, db, uriLocal,
				OSCORE_REPLAY_WINDOW, appStatements, edp);

		// Build well-known and EDHOC resource
		// provide an instance of a .well-known/edhoc resource
		CoapResource edhocResource = new EdhocResource("edhoc", edhocEndpointInfo);
		CoapResource wellKnownResource = new WellKnown();
		wellKnownResource.add(edhocResource);
		
		CoapServer server = new CoapServer(4444);
		server.add(wellKnownResource);
		server.add(new Temp());
		server.add(new TestResource());
		server.start();
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
	static List<Set<Integer>> usedConnectionIds = new ArrayList<Set<Integer>>();
	static String uriLocal = "coap://localhost";
	static final int OSCORE_REPLAY_WINDOW = 32;
	static Map<String, AppStatement> appStatements = new HashMap<String, AppStatement>();
	static KissEDP edp;

	/**
	 * RH: General method for setting up all EDHOC parameters needed to build
	 * the EdhocEndpointInfo
	 */
	private static void setupEdhocParameters() {
		Set<Integer> authMethods = new HashSet<Integer>();
		authMethods.add(Constants.EDHOC_AUTH_METHOD_0);
		AppStatement appStatement = new AppStatement(true, authMethods, false, true);

		appStatements.put(uriLocal + "/.well-known/edhoc", appStatement);

		for (int i = 0; i < 4; i++) {
			// Empty sets of assigned Connection Identifiers; one set for each
			// possible size in bytes.
			// The set with index 0 refers to Connection Identifiers with size 1
			// byte
			usedConnectionIds.add(new HashSet<Integer>());
		}

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

		final int keyFormat = 0; // 0 is for Base64; 1 is for binary encoding

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
				// "pgMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnMjWCDXCb+hy1ybUu18KTAJMvjsmXch4W3Hd7Rw7mTF3ocbLQ==";
				// peerPublicKeyBase64 =
				// "pQMmAQIgASFYIGdZmgAlZDXB6FGfVVxHrB2LL8JMZag4JgK4ZcZ/+GBUIlgguZsSChh5hecy3n4Op+lZZJ2xXdbsz8DY7qRmLdIVavk=";
			}
			else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
				// keyPairBase64 =
				// "pQMnAQEgBiFYIDzQyFH694a7CcXQasH9RcqnmwQAy2FIX97dGGGy+bpSI1gg5aAfgdGCH2/2KFsQH5lXtDc8JUn1a+OkF0zOG6lIWXQ=";
				// peerPublicKeyBase64 =
				// "pAMnAQEgBiFYIEPgltbaO4rEBSYv3Lhs09jLtrOdihHUxLdc9pRoR/W9";
			} else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
				// keyPairBase64 =
				// "pQMnAQEgBiFYIKOjK/y+4psOGi9zdnJBqTLThdpEj6Qygg4Voc10NYGSI1ggn/quL33vMaN9Rp4LKWCXVnaIRSgeeCJlU0Mv/y6zHlQ=";
				// peerPublicKeyBase64 =
				// "pAMnAQEgBiFYIGt2OynWjaQY4cE9OhPQrwcrZYNg8lRJ+MwXIYMjeCtr";
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
			// byte[] idCredKid = new byte[] { (byte) 0x24 };
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
			// peerPublicKey =
			// SharedSecretCalculation.buildEcdsa256OneKey(null,
			// peerPublicKeyBinary,
			// peerPublicKeyBinaryY);
			// } else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			// peerPublicKey =
			// SharedSecretCalculation.buildEd25519OneKey(null,
			// peerPublicKeyBinary);
			// } else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			// peerPublicKey =
			// SharedSecretCalculation.buildCurve25519OneKey(null,
			// peerPublicKeyBinary);
			// }
			System.err.println("ERROR in cred type switch!");
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
			// byte[] peerKid = new byte[] { (byte) 0x07 };
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
	
	/*
	 * Definition of the test Resource
	 */
	static class TestResource extends CoapResource {

		public TestResource() {

			// set resource identifier
			super("test");

			// set display name
			getAttributes().setTitle("test");

		}

		@Override
		public void handleGET(CoapExchange exchange) {

			System.out.println("Received request from Client: " + exchange.getRequestText());
			
			// respond to the request
			Response resp = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
			resp.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			resp.setPayload("Response from AS: Test");
			exchange.respond(resp);
		}
	}
	
	static Random rand = new Random();
	
	/*
	 * Definition of the Temp Resource
	 */
	static class Temp extends OSCoreResource {

		public Temp() {

			// set resource identifier
			super("temp", true);

			// set display name
			getAttributes().setTitle("temp");

		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond(Integer.toString(rand.nextInt(50)));
			
			System.out.println("Received request for temperature reading.");
		}
	}
	
	/**
 	 * @param str the hex string
 	 * @return the byte array
 	 * @str the hexadecimal string to be converted into a byte array
 	 * 
 	 *      Return the byte array representation of the original string
 	 */
 	public static byte[] hexStringToByteArray(final String str) {
 		int len = str.length();
 		byte[] data = new byte[len / 2];

 		// Big-endian
 		for (int i = 0; i < len; i += 2) {
 			data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
 			data[i / 2] = (byte) (data[i / 2] & 0xFF);
 		}

 		// Little-endian
 		/*
 		 * for (int i = 0; i < len; i += 2) { data[i / 2] = (byte)
 		 * ((Character.digit(str.charAt(len - 2 - i), 16) << 4) +
 		 * Character.digit(str.charAt(len - 1 - i), 16)); data[i / 2] = (byte)
 		 * (data[i / 2] & 0xFF); }
 		 */

 		return data;

 	}
	
}
