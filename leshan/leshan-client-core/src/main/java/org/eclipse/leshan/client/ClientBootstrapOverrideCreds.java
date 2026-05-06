package org.eclipse.leshan.client;

/**
 * Class to manage override client EDHOC credentials indicated on the command
 * line. Note that this class only handles the credentials meant to override
 * what is received from the BS.
 * 
 *
 */
public final class ClientBootstrapOverrideCreds {

	private static byte[] clientKeyIdentifier;
	private static byte[] clientPublicKey;
	private static byte[] privateKey;

	private ClientBootstrapOverrideCreds() {
	}

	public static byte[] getClientKeyIdentifier() {
		if (clientKeyIdentifier != null) {
			return clientKeyIdentifier.clone();
		} else {
			return null;
		}
	}

	public static void setClientKeyIdentifier(byte[] inputClientKeyIdentifier) {
		if (inputClientKeyIdentifier == null) {
			throw new IllegalArgumentException("Input ClientKeyIdentifier is null");
		}
		clientKeyIdentifier = inputClientKeyIdentifier.clone();
	}

	public static byte[] getClientPublicKey() {
		if (clientPublicKey != null) {
			return clientPublicKey.clone();
		} else {
			return null;
		}
	}

	public static void setClientPublicKey(byte[] inputClientPublicKey) {
		if (inputClientPublicKey == null) {
			throw new IllegalArgumentException("Input ClientPublicKey is null");
		}
		clientPublicKey = inputClientPublicKey.clone();
	}

	public static byte[] getPrivateKey() {
		if (privateKey != null) {
			return privateKey.clone();
		} else {
			return null;
		}
	}

	public static void setPrivateKey(byte[] inputPrivateKey) {
		if (inputPrivateKey == null) {
			throw new IllegalArgumentException("Input PrivateKey is null");
		}
		privateKey = inputPrivateKey.clone();
	}
}