package org.eclipse.leshan.client;

/**
 * Class to manage client credentials indicated on the command line.
 * 
 *
 */
public final class ClientCredentialManager {

	private static byte[] clientKeyIdentifier;
	private static byte[] clientPublicKey;
	private static byte[] privateKey;

	private ClientCredentialManager() {
	}

	public static byte[] getClientKeyIdentifier() {
		return clientKeyIdentifier.clone();
	}

	public static void setClientKeyIdentifier(byte[] inputClientKeyIdentifier) {
		if (inputClientKeyIdentifier == null) {
			throw new IllegalArgumentException("Input ClientKeyIdentifier is null");
		}
		clientKeyIdentifier = inputClientKeyIdentifier.clone();
	}

	public static byte[] getClientPublicKey() {
		return clientPublicKey.clone();
	}

	public static void setClientPublicKey(byte[] inputClientPublicKey) {
		if (inputClientPublicKey == null) {
			throw new IllegalArgumentException("Input ClientPublicKey is null");
		}
		clientPublicKey = inputClientPublicKey.clone();
	}

	public static byte[] getPrivateKey() {
		return privateKey.clone();
	}

	public static void setPrivateKey(byte[] inputPrivateKey) {
		if (inputPrivateKey == null) {
			throw new IllegalArgumentException("Input PrivateKey is null");
		}
		privateKey = inputPrivateKey.clone();
	}
}