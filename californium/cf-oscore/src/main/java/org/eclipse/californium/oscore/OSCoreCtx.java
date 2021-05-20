/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.EncryptCommon;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.CCMBlockCipher;

/**
 * 
 * Represents the Security Context and its parameters. At initiation derives the
 * keys and IVs. Also maintains replay window.
 *
 */
public class OSCoreCtx {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSCoreCtx.class);

	private static final byte ZERO = 0;
	private static final byte ONE = 1;

	private AlgorithmID common_alg;
	private byte[] common_master_secret;
	private byte[] common_master_salt;
	private byte[] common_iv;
	private byte[] context_id;

	private byte[] sender_id;
	private byte[] sender_key;
	private int sender_seq;

	private byte[] recipient_id;
	private byte[] recipient_key;
	private int recipient_seq;
	private int recipient_replay_window_size;
	private int recipient_replay_window;

	private AlgorithmID kdf;

	private int rollback_recipient_seq = -1;
	private int rollback_recipient_replay = -1;
	private byte[] rollback_last_block_tag = null;

	private byte[] last_block_tag = null;
	private int seqMax = Integer.MAX_VALUE;

	private int id_length;
	private int iv_length;
	private int key_length;

	private Code CoAPCode = null;

	/**
	 * Include the context id in messages generated using this context. This is
	 * generally optional and can be controlled by the application.
	 *
	 * Default value is false.
	 */
	private boolean includeContextId;

	/**
	 * Generate a new partial IV for outgoing Response messages. If this
	 * variable is false the same nonce from the original request will be used.
	 * Otherwise a new partial IV will be generated by the sender and included
	 * in the Response. This affects the calculation of the nonce.
	 *
	 * See https://tools.ietf.org/html/rfc8613#section-5.2
	 *
	 * This variable will control the behaviour when sending Response messages
	 * with this context. Note that Observe notifications will always include a
	 * new partial IV.
	 *
	 * Default value is false.
	 */
	private boolean responsesIncludePartialIV;
	
	/**
	 * Indicates if this client/server shall support the context re-derivation
	 * procedure.
	 * 
	 * See https://tools.ietf.org/html/rfc8613#appendix-B.2
	 */
	private boolean contextRederivationEnabled;

	/**
	 * When using outer block-wise with OSCORE a proxy can maliciously inject
	 * block fragments. To protect against this a message with size exceeding
	 * this parameter should never be sent without inner block-wise. Likewise
	 * when receiving a message using outer block-wise it should be discarded if
	 * the cumulated size exceeds this parameter.
	 * 
	 * See https://tools.ietf.org/html/rfc8613#section-4.1.3.4.2
	 */
	private int maxUnfragmentedSize;

	/**
	 * URI this Context is associated with if any.
	 *
	 * That is what URI it is associated and stored under in the HashMapCtxDB.
	 */
	private String uri;

	/**
	 * String versions of the context ID, sender ID and recipient ID.
	 *
	 * These are set when the context is created (rather than for every message)
	 * to be used later when adding information about the messages to the
	 * EndpointContext on sending or receiving a message.
	 */
	private final String contextIdString;
	private final String senderIdString;
	private final String recipientIdString;

	/**
	 * Key that is used during the context re-derivation process.
	 */
	private byte[] contextRederivationKey;

	/**
	 * Makes it possible to override the Context ID to include in messages.
	 * Typically this would be the Context ID this context was generated with
	 * but that is not the case for the context re-derivation procedure.
	 */
	private byte[] overrideContextId;

	/**
	 * Indicate which phase the context re-derivation procedure is in,
	 */
	private ContextRederivation.PHASE contextRederivationPhase;

	/**
	 * Constructor. Generates the context from the base parameters with the
	 * minimal input.
	 * 
	 * @param master_secret the master secret
	 * @param client is this originally the client's context
	 * @throws OSException if the default KDF is not supported
	 */
	public OSCoreCtx(byte[] master_secret, boolean client) throws OSException {
		this(master_secret, client, null, null, null, null, null, null, null);
	}

	/**
	 * Constructor. Generates the context from the base parameters.
	 * 
	 * @param master_secret the master secret
	 * @param alg the encryption algorithm as defined in COSE
	 * @param client is this originally the client's context
	 * @param sender_id the sender id or null for default
	 * @param recipient_id the recipient id or null for default
	 * @param kdf the COSE algorithm abbreviation of the kdf or null for the
	 *            default
	 * @param replay_size the replay window size or null for the default
	 * @param master_salt the optional master salt, can be null
	 * @param contextId the context id, can be null
	 *
	 * @throws OSException if the KDF is not supported
	 */
	public OSCoreCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id, byte[] recipient_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId) throws OSException {

		if (alg == null) {
			this.common_alg = AlgorithmID.AES_CCM_16_64_128;
		} else {
			this.common_alg = alg;
		}

		setLengths();

		this.sender_seq = 0;
		this.recipient_seq = -1;

		if (master_secret != null) {
			this.common_master_secret = master_secret.clone();
		} else {
			LOGGER.error("Input master secret is null");
			throw new NullPointerException("Input master secret is null");
		}
		if (sender_id == null || sender_id.length > this.id_length) {
			this.sender_id = createByteArray(client ? ZERO : ONE);
		} else {
			this.sender_id = sender_id.clone();
		}

		if (recipient_id == null || recipient_id.length > this.id_length) {
			this.recipient_id = createByteArray(client ? ONE : ZERO);
		} else {
			this.recipient_id = recipient_id.clone();
		}

		if (kdf == null) {
			this.kdf = AlgorithmID.HKDF_HMAC_SHA_256;
		} else {
			this.kdf = kdf;
		}

		if (replay_size == null) {
			this.recipient_replay_window_size = 32;
		} else {
			this.recipient_replay_window_size = replay_size.intValue();
		}
		this.recipient_replay_window = 0;

		if (master_salt == null) {
			// Default value. Automatically initialized with 0-es.
			this.common_master_salt = new byte[this.kdf.getKeySize() / Byte.SIZE];
		} else {
			this.common_master_salt = master_salt.clone();
		}

		if (contextId != null) {
			this.context_id = contextId.clone();
		} else {
			this.context_id = null;
		}

		// Set default values for these flags
		//They can be set by the application using their setters
		includeContextId = false;
		responsesIncludePartialIV = false;
		contextRederivationEnabled = false;

		//Set string versions of sender ID, recipient ID and Context ID
		contextIdString = toHex(this.context_id);
		senderIdString = toHex(this.sender_id);
		recipientIdString = toHex(this.recipient_id);

		//Initialize the URI associated with the context
		//It will be overwritten if this context is added to a HashMapCtxDB
		uri = "";

		overrideContextId = null;
		contextRederivationPhase = ContextRederivation.PHASE.INACTIVE;

		// Set default value of MAX_UNFRAGMENTED_SIZE
		maxUnfragmentedSize = NetworkConfig.getStandard().getInt(Keys.MAX_RESOURCE_BODY_SIZE);

		//Set digest value depending on HKDF
		String digest = null;
		switch (this.kdf) {
		case HKDF_HMAC_SHA_256:
			digest = "SHA256";
			break;
		case HKDF_HMAC_SHA_512:
			digest = "SHA512";
			break;
		case HKDF_HMAC_AES_128:
		case HKDF_HMAC_AES_256:
		default:
			LOGGER.error("Requested HKDF algorithm is not supported: " + this.kdf.toString());
			throw new OSException("HKDF algorithm not supported");
		}

		// Derive sender_key
		CBORObject info = CBORObject.NewArray();
		info.Add(this.sender_id);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(this.key_length);

		try {
			this.sender_key = deriveKey(this.common_master_secret, this.common_master_salt, this.key_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

		// Derive recipient_key
		info = CBORObject.NewArray();
		info.Add(this.recipient_id);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(this.key_length);

		try {
			this.recipient_key = deriveKey(this.common_master_secret, this.common_master_salt, this.key_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

		// Derive common_iv
		info = CBORObject.NewArray();
		info.Add(Bytes.EMPTY);
		info.Add(this.context_id);
		info.Add(this.common_alg.AsCBOR());
		info.Add(CBORObject.FromObject("IV"));
		info.Add(this.iv_length);

		try {
			this.common_iv = deriveKey(this.common_master_secret, this.common_master_salt, this.iv_length, digest,
					info.EncodeToBytes());
		} catch (CoseException e) {
			LOGGER.error(e.getMessage());
			throw new OSException(e.getMessage());
		}

		// Initialize cipher object
		initializeCipher(common_alg);

	}

	/**
	 * Overrides hasCode to provide a functional implementation for this class.
	 */
	@Override
	public int hashCode() {
		return 31 * Arrays.hashCode(sender_id) + Arrays.hashCode(recipient_id);
	}

	/**
	 * Overrides equals to provide a functional implementation for this class.
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof OSCoreCtx)) {
			return false;
		}
		OSCoreCtx other = (OSCoreCtx) o;

		return Arrays.equals(other.sender_id, sender_id) && Arrays.equals(other.recipient_id, recipient_id);
	}

	/**
	 * @return the sender key
	 */
	public byte[] getSenderKey() {
		return sender_key;
	}

	/**
	 * @return the recipient key
	 */
	public byte[] getRecipientKey() {
		return recipient_key;
	}

	/**
	 * @return the encryption algorithm
	 */
	public AlgorithmID getAlg() {
		return this.common_alg;
	}

	/**
	 * @return the sender sequence number
	 */
	public synchronized int getSenderSeq() {
		return sender_seq;
	}

	/**
	 * @return the receiver sequence number
	 */
	public synchronized int getReceiverSeq() {
		return recipient_seq;
	}

	/**
	 * @return the tag of the last block processed with this context
	 */
	public byte[] getLastBlockTag() {
		return last_block_tag;
	}

	/**
	 * @return the sender's identifier
	 */
	public byte[] getSenderId() {
		return sender_id;
	}

	/**
	 * @return the repipient's identifier
	 */
	public byte[] getRecipientId() {
		return recipient_id;
	}

	/**
	 * @return the common_iv
	 */
	public byte[] getCommonIV() {
		return common_iv;
	}

	/**
	 * @return the set length of IV:s
	 */
	public int getIVLength() {
		return iv_length;
	}

	/**
	 * @return size of recipient replay window
	 */
	public int getRecipientReplaySize() {
		return recipient_replay_window_size;
	}

	/**
	 * @return recipient replay window
	 */
	public int getRecipientReplayWindow() {
		return recipient_replay_window;
	}

	public byte[] getMasterSecret() {
		return common_master_secret;
	}

	public byte[] getSalt() {
		return common_master_salt;
	}

	public AlgorithmID getKdf() {
		return kdf;
	}
	
	/**
	 * Enables getting the ID Context
	 * 
	 * @return Byte array with ID Context
	 */
	public byte[] getIdContext() {
		return context_id;
	}

	/**
	 * Enables getting the ID Context to put in an outgoing message.
	 *
	 * Typically this will be the Context ID this context was generated with but
	 * it may be different when performing the context re-derivation procedure.
	 * 
	 * @return Byte array with ID Context
	 */
	public byte[] getMessageIdContext() {
		if (overrideContextId != null) {
			return overrideContextId;
		} else {
			return context_id;
		}
	}

	/**
	 * Get the flag controlling whether or not to include the Context ID in
	 * messages generated using this context.
	 *
	 * @return the includeContextId
	 */
	public boolean getIncludeContextId() {
		return includeContextId;
	}

	/**
	 * Set the flag controlling whether or not to include the Context ID in
	 * messages generated using this context.
	 * 
	 * Note that this flag should never be set to true in a context without a Context ID set.
	 *
	 * @param includeContextId the includeContextId to set
	 *
	 * @throws IllegalStateException if a Context ID has not been set for this context
	 */
	public void setIncludeContextId(boolean includeContextId) {
		if (context_id == null && overrideContextId == null) {
			LOGGER.error("Context ID cannot be included for a context without one set.");
			throw new IllegalStateException("Context ID cannot be included for a context without one set.");
		}
		
		// If Context ID is not to be included clear the overriding Context ID
		// possibly set to be included in messages
		if (!includeContextId) {
			this.overrideContextId = null;
		}

		this.includeContextId = includeContextId;
	}

	/**
	 * Indicate as a parameter exactly what Context ID should be included.
	 * Normally that would be the Context ID this context was generated with but
	 * that is not the case for the context re-derivation procedure.
	 * 
	 * @param overrideContextId the Context ID to include in messages
	 */
	public void setIncludeContextId(byte[] overrideContextId) {
		this.overrideContextId = overrideContextId.clone();
		this.setIncludeContextId(true);
	}

	/**
	 * Get the flag controlling whether or not to generate a new partial IV for
	 * outgoing Response messages using this context.
	 * 
	 * @return the responsesIncludePartialIV
	 */
	public boolean getResponsesIncludePartialIV() {
		return responsesIncludePartialIV;
	}

	/**
	 * Set the flag controlling whether or not to generate a new partial IV for
	 * outgoing Response messages using this context.
	 * 
	 * @param responsesIncludePartialIV the responsesIncludePartialIV to set
	 */
	public void setResponsesIncludePartialIV(boolean responsesIncludePartialIV) {
		this.responsesIncludePartialIV = responsesIncludePartialIV;
	}

	/**
	 * Get the flag controlling whether or not this context supports the context
	 * re-derivation procedure.
	 * 
	 * @return the contextRederivationEnabled
	 */
	public boolean getContextRederivationEnabled() {
		return contextRederivationEnabled;
	}

	/**
	 * Set the flag controlling whether or not this context supports the context
	 * re-derivation procedure.
	 * 
	 * @param contextRederivationEnabled the contextRederivationEnabled to set
	 */
	public void setContextRederivationEnabled(boolean contextRederivationEnabled) {
		this.contextRederivationEnabled = contextRederivationEnabled;
	}

	/**
	 * Gets the current value of the MAX_UNFRAGMENTED_SIZE parameter. It is used
	 * to prevent malicious behaviour by a proxy when using block-wise.
	 * 
	 * @return the current value of MAX_UNFRAGMENTED_SIZE
	 */
	public int getMaxUnfragmentedSize() {
		return maxUnfragmentedSize;
	}

	/**
	 * Sets the current value of the MAX_UNFRAGMENTED_SIZE parameter. It is used
	 * to prevent malicious behaviour by a proxy when using block-wise.
	 * 
	 * @param maxUnfragmentedSize the desired value of MAX_UNFRAGMENTED_SIZE
	 */
	public void setMaxUnfragmentedSize(int maxUnfragmentedSize) {
		this.maxUnfragmentedSize = maxUnfragmentedSize;
	}

	/**
	 * Get a string representation of the context ID. (A string showing the
	 * hexadecimal bytes.)
	 *
	 * @return the contextIdString
	 */
	public String getContextIdString() {
		return contextIdString;
	}

	/**
	 * Get a string representation of the sender ID. (A string showing the
	 * hexadecimal bytes.)
	 *
	 * @return the senderIdString
	 */
	public String getSenderIdString() {
		return senderIdString;
	}

	/**
	 * Get a string representation of the recipient ID. (A string showing the
	 * hexadecimal bytes.)
	 *
	 * @return the recipientIdString
	 */
	public String getRecipientIdString() {
		return recipientIdString;
	}

    public int rollbackRecipientSeq() {
		return rollback_recipient_seq;
	}

	public int rollbackRecipientReplay() {
		return rollback_recipient_replay;
	}

	/**
	 * @param seq the sender sequence number to set
	 */
	public synchronized void setSenderSeq(int seq) {
		sender_seq = seq;
	}

	/**
	 * @param seq the recipient sequence number to set
	 */
	public synchronized void setReceiverSeq(int seq) {
		recipient_seq = seq;
	}

	/**
	 * Save the tag of the last processed block
	 * 
	 * @param tag the tag
	 */
	public void setLastBlockTag(byte[] tag) {
		last_block_tag = tag.clone();
	}

	/**
	 * Enables setting the sender key
	 * 
	 * @param senderKey the sender key to set
	 */
	public void setSenderKey(byte[] senderKey) {
		this.sender_key = senderKey.clone();
	}
	
	/**
	 * Enables setting the recipient key
	 * 
	 * @param recipientKey the recipient key to set
	 */
	public void setRecipientKey(byte[] recipientKey) {
		this.recipient_key = recipientKey.clone();
	}
	
	/**
	 * Set the maximum sequence number.
	 * 
	 * @param seqMax the maximum sequence number.
	 */
	public void setSeqMax(int seqMax) {
		this.seqMax = seqMax;
	}

	/**
	 * Sets the valid lengths, in bytes, of constrained variables(ids, IVs and
	 * keys).
	 * 
	 * @throws RuntimeException if not this.common_alg has been initiated
	 */
	private void setLengths() {
		if (common_alg != null) {

			iv_length = EncryptCommon.ivLength(common_alg);
			if (iv_length > 0) {
				id_length = iv_length - 6; // RFC section 5.2
				key_length = common_alg.getKeySize() / 8;

			} else {
				LOGGER.error("Unable to set lengths, since algorithm");
				throw new RuntimeException("Unable to set lengths, since algorithm");
			}

		} else {
			LOGGER.error("Common_alg has not yet been initiated.");
			throw new RuntimeException("Common_alg has not yet been initiated.");
		}
	}

	/**
	 * @return the URI this context is associated with if any.
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Sets the URI this context is associated with.
	 * (The URI it is saved under in the HashMapCtxDB.)
	 *
	 * This will be set when added to the HashMapCtxDB.
	 *
	 * @param uri the URI this OSCORE context is associated with
	 */
	protected void setUri(String uri) {
		this.uri = uri;
	}

	/**
	 * Get the context re-derivation key.
	 * 
	 * @return the context re-derivation key
	 */
	protected byte[] getContextRederivationKey() {
		return contextRederivationKey;
	}

	/**
	 * Sets the context re-derivation key.
	 * 
	 * @param contextRederivationKey the context re-derivation key to set
	 */
	protected void setContextRederivationKey(byte[] contextRederivationKey) {
		this.contextRederivationKey = contextRederivationKey;
	}

	/**
	 * Check the phase of the context re-derivation process.
	 * 
	 * @return the contextRederivationOngoing
	 */
	public ContextRederivation.PHASE getContextRederivationPhase() {
		return contextRederivationPhase;
	}

	/**
	 * Set the phase of the context re-derivation process.
	 * 
	 * @param contextRederivationPhase the contextRederivationPhase to set
	 */
	public void setContextRederivationPhase(ContextRederivation.PHASE contextRederivationPhase) {
		this.contextRederivationPhase = contextRederivationPhase;
	}

	/**
	 * Increase the sender's sequence number by one
	 *
	 * @throws OSException if the sequence number wraps
	 */
	public synchronized void increaseSenderSeq() throws OSException {
		if (sender_seq >= seqMax) {
			LOGGER.error("Sequence number wrapped, get a new OSCore context");
			throw new OSException("Sequence number wrapped");
		}
		sender_seq++;
	}

	/**
	 * Checks and sets the sequence number for incoming messages.
	 * 
	 * @param seq the incoming sequence number
	 * 
	 * @throws OSException if the sequence number wraps or if for a replay
	 */
	public synchronized void checkIncomingSeq(int seq) throws OSException {
		if (seq >= seqMax) {
			LOGGER.error("Sequence number wrapped, get new OSCore context");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		}
		rollback_recipient_seq = recipient_seq;
		rollback_recipient_replay = recipient_replay_window;
		if (seq > recipient_seq) {
			// Update the replay window
			int shift = seq - recipient_seq;
			recipient_replay_window = recipient_replay_window << shift;
			recipient_seq = seq;
		} else if (seq == recipient_seq) {
			LOGGER.error("Sequence number is replay");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		} else { // seq < recipient_seq
			if (seq + recipient_replay_window_size < recipient_seq) {
				LOGGER.error("Message too old");
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			}
			// seq+replay_window_size > recipient_seq
			int shift = this.recipient_seq - seq;
			int pattern = 1 << shift;
			int verifier = recipient_replay_window & pattern;
			verifier = verifier >> shift;
			if (verifier == 1) {
				throw new OSException(ErrorDescriptions.REPLAY_DETECT);
			}
			recipient_replay_window = recipient_replay_window | pattern;
		}
	}

	/**
	 * Rolls back the latest recipient sequence number update if any
	 */
	public synchronized void rollBack() {
		if (rollback_recipient_replay != -1) {
			recipient_replay_window = rollback_recipient_replay;
			rollback_recipient_replay = -1;
		}
		if (rollback_recipient_seq != -1) {
			recipient_seq = rollback_recipient_seq;
			rollback_recipient_seq = -1;
		}
		if (this.rollback_last_block_tag != null) {
			this.last_block_tag = this.rollback_last_block_tag;
			this.rollback_last_block_tag = null;
		}
	}

	protected static byte[] deriveKey(byte[] secret, byte[] salt, int cbitKey, String digest, byte[] rgbContext)
			throws CoseException {

		final String HMAC_ALG_NAME = "Hmac" + digest;

		try {
			Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
			int hashLen = hmac.getMacLength();

			// Perform extract
			hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
			byte[] rgbExtract = hmac.doFinal(secret);

			// Perform expand
			hmac.init(new SecretKeySpec(rgbExtract, HMAC_ALG_NAME));
			int c = ((cbitKey + 7) / 8 + hashLen - 1) / hashLen;
			byte[] rgbOut = new byte[cbitKey];
			byte[] T = new byte[hashLen * c];
			byte[] last = new byte[0];
			for (int i = 0; i < c; i++) {
				hmac.reset();
				hmac.update(last);
				hmac.update(rgbContext);
				hmac.update((byte) (i + 1));
				last = hmac.doFinal();
				System.arraycopy(last, 0, T, i * hashLen, hashLen);
			}
			System.arraycopy(T, 0, rgbOut, 0, cbitKey);
			return rgbOut;
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Derivation failure", ex);
		}
	}

	/**
	 * Converts a byte array to a hexadecimal string representation.
	 *
	 * @param bytes the byte array to convert
	 * @return the string representation
	 */
	private String toHex(byte[] bytes) {
		if(bytes == null || bytes.length == 0) {
			return "";
		} else {
			return StringUtil.byteArray2Hex(bytes);
		}
	}

	/**
	 * Returns this CoAPCode
	 */
	public Code getCoAPCode() {
		return CoAPCode;
	}

	/**
	 * Sets this CoAPCode to CoAPCode
	 * 
	 * @param coapCode coap code.
	 */
	public void setCoAPCode(Code coapCode) {
		if (coapCode != null) {
			this.CoAPCode = coapCode;
		}
	}

	/**
	 * Initializes the cipher object by calling CCMBlockCipher.encrypt with
	 * dummy data. Doing this at creation of the OSCORE context reduces the
	 * latency for the first request since it would otherwise happen then.
	 * 
	 * @param alg the encryption algorithm used
	 */
	private void initializeCipher(AlgorithmID alg) {
		switch (alg) {
		case AES_CCM_16_64_128:
		case AES_CCM_16_128_128:
		case AES_CCM_64_64_128:
		case AES_CCM_64_128_128:

			byte[] key = { (byte) 0xEB, (byte) 0xDE, (byte) 0xBC, (byte) 0x51, (byte) 0xF1, (byte) 0x03,
					(byte) 0x79, (byte) 0x14, (byte) 0x14, (byte) 0x4F, (byte) 0xC3, (byte) 0xAC, (byte) 0x40,
					(byte) 0x14, (byte) 0xD2, (byte) 0x4C };
			byte[] nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			try {
				CCMBlockCipher.encrypt(new SecretKeySpec(key, "AES"), nonce, Bytes.EMPTY,
						Bytes.EMPTY, 0);
			} catch (GeneralSecurityException e) {
				LOGGER.error("Failed to initialize cipher.");
				throw new RuntimeException("Failed to initialize cipher.");
			}

			break;

		default:
			break;
		}
	}

	/**
	 * Create byte array from values.
	 * 
	 * @param values bytes for byte array
	 * @return initialized byte array
	 */
	private static byte[] createByteArray(byte... values) {
		return values;
	}
}
