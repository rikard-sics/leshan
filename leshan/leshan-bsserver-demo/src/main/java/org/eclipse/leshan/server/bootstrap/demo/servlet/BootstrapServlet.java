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
 *******************************************************************************/

package org.eclipse.leshan.server.bootstrap.demo.servlet;

import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.AppProfile;
import org.eclipse.californium.edhoc.Constants;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocResource;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.SharedSecretCalculation;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.server.EdhocHandler;
import org.eclipse.leshan.server.OscoreHandler;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig;
import org.eclipse.leshan.server.bootstrap.EditableBootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.InvalidConfigurationException;
import org.eclipse.leshan.server.bootstrap.demo.json.BindingModeTypeAdapter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Servlet for REST API in charge of adding bootstrap information to the bootstrap server.
 */
public class BootstrapServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static class SignedByteUnsignedByteAdapter implements JsonSerializer<Byte>, JsonDeserializer<Byte> {

        @Override
        public Byte deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            return json.getAsByte();
        }

        @Override
        public JsonElement serialize(Byte src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive((int) src & 0xff);
        }
    }

    private final EditableBootstrapConfigStore bsStore;

    private final Gson gson;

    public BootstrapServlet(EditableBootstrapConfigStore bsStore) {
        this.bsStore = bsStore;

        this.gson = new GsonBuilder()//
                .registerTypeAdapter(new TypeToken<EnumSet<BindingMode>>() {
                }.getType(), new BindingModeTypeAdapter()) //
                .registerTypeHierarchyAdapter(Byte.class, new SignedByteUnsignedByteAdapter()).create();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getPathInfo() != null) {
            sendError(resp, HttpServletResponse.SC_NOT_FOUND, "bad URL");
            return;
        }

        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        resp.getOutputStream().write(gson.toJson(bsStore.getAll()).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getPathInfo() == null) {
            // we need the endpoint in the URL
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "endpoint name should be specified in the URL");
            return;
        }

        String[] path = StringUtils.split(req.getPathInfo(), '/');

        // endPoint
        if (path.length != 1) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
                    "endpoint name should be specified in the URL, nothing more");
            return;
        }

        String endpoint = path[0];

        try {
            BootstrapConfig cfg = gson.fromJson(new InputStreamReader(req.getInputStream()), BootstrapConfig.class);

            if (cfg == null) {
                sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "no content");
            } else {
                bsStore.add(endpoint, cfg);
                configureEdhocIfNeeded(cfg);
                resp.setStatus(HttpServletResponse.SC_OK);
            }
        } catch (JsonSyntaxException | InvalidConfigurationException e) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getPathInfo() == null) {
            // we need the endpoint in the URL
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "endpoint name should be specified in the URL");
            return;
        }

        String[] path = StringUtils.split(req.getPathInfo(), '/');

        // endPoint
        if (path.length != 1) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
                    "endpoint name should be specified in the URL, nothing more");
            return;
        }

        String endpoint = path[0];

        if (bsStore.remove(endpoint) != null) {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            sendError(resp, HttpServletResponse.SC_NOT_FOUND, "no config for " + endpoint);
        }
    }

    private void sendError(HttpServletResponse resp, int statusCode, String errorMessage) throws IOException {
        resp.setStatus(statusCode);
        resp.setContentType("text/plain; charset=UTF-8");
        if (errorMessage != null)
            resp.getOutputStream().write(errorMessage.getBytes(StandardCharsets.UTF_8));
    }

    // --- EDHOC setup ---

    private static final HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<>();
    private static final Set<CBORObject> usedConnectionIds = new HashSet<>();
    private static final List<Integer> supportedCiphersuites = new ArrayList<>();
    private static final String URI_LOCAL = "coap://localhost";
    private static final int OSCORE_REPLAY_WINDOW = 32;

    private void configureEdhocIfNeeded(BootstrapConfig cfg) {
        BootstrapConfig.EdhocObject bsEdhoc = null;
        for (BootstrapConfig.ServerSecurity sec : cfg.security.values()) {
            if (sec.bootstrapServer && sec.oscoreSecurityMode != null) {
                BootstrapConfig.EdhocObject candidate = cfg.edhoc.get(sec.oscoreSecurityMode);
                if (candidate != null) {
                    bsEdhoc = candidate;
                    break;
                }
            }
        }
        if (bsEdhoc == null) return;

        EdhocHandler.init();
        org.eclipse.californium.edhoc.Util.installCryptoProvider();

        if (supportedCiphersuites.isEmpty())
            for (int i = 0; i <= 6; i++) supportedCiphersuites.add(i);

        try {
            setupBsIdentityKeys(bsEdhoc.peerPublicKeyIdentifier, bsEdhoc.clientKeyIdentifier,
                    bsEdhoc.peerPublicKey, bsEdhoc.clientPublicKey,
                    bsEdhoc.authenticationMethod.intValue(), bsEdhoc.selectedCiphersuite.intValue());
        } catch (Exception e) {
            System.err.println("Failed to set up BS EDHOC credentials: " + e.getMessage());
            return;
        }

        CBORObject idCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(bsEdhoc.peerPublicKeyIdentifier);
        EdhocHandler.ownIdCreds.add(idCred);

        if (!EdhocHandler.getEndpointAdded() && OscoreHandler.getLwServer() != null) {
            Set<Integer> authMethods = new HashSet<>(Arrays.asList(0, 1, 2, 3));
            AppProfile appStatement = new AppProfile(authMethods, false, true, false);
            HashMap<String, AppProfile> appStatements = new HashMap<>();
            appStatements.put(URI_LOCAL, appStatement);
            appStatements.put(URI_LOCAL + "/.well-known/edhoc", appStatement);
            appStatements.put("/.well-known/edhoc", appStatement);

            HashMapCtxDB db = OscoreHandler.getContextDB();
            EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(
                    EdhocHandler.idCreds, EdhocHandler.creds, EdhocHandler.keyPairs,
                    EdhocHandler.peerPublicKeys, EdhocHandler.peerCredentials, edhocSessions,
                    usedConnectionIds, supportedCiphersuites, new HashSet<>(), null,
                    Constants.TRUST_MODEL_NO_LEARNING, db, URI_LOCAL, OSCORE_REPLAY_WINDOW, 2048, appStatements);

            CoapResource edhocResource = new EdhocResource("edhoc", edhocEndpointInfo, EdhocHandler.ownIdCreds);
            CoapResource wellKnownResource = new WellKnownResource();
            wellKnownResource.add(edhocResource);
            OscoreHandler.getLwServer().add(wellKnownResource);
            EdhocHandler.setEndpointAdded(true);
        }
    }

    private static void setupBsIdentityKeys(byte[] myKid, byte[] peerKid,
            byte[] myCcs, byte[] peerCcs, int method, int selectedCiphersuite) throws CoseException {
        OneKey keyPair = oneKeyFromCcs(myCcs, true);
        CBORObject idCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(myKid);
        CBORObject cred = CBORObject.FromObject(stripPrivateKeyFromCcs(myCcs));

        HashMap<Integer, OneKey> kpEcdh = EdhocHandler.keyPairs.get(Constants.ECDH_KEY);
        HashMap<Integer, OneKey> kpSig  = EdhocHandler.keyPairs.get(Constants.SIGNATURE_KEY);
        HashMap<Integer, CBORObject> crEcdh = EdhocHandler.creds.get(Constants.ECDH_KEY);
        HashMap<Integer, CBORObject> crSig  = EdhocHandler.creds.get(Constants.SIGNATURE_KEY);
        HashMap<Integer, CBORObject> idEcdh = EdhocHandler.idCreds.get(Constants.ECDH_KEY);
        HashMap<Integer, CBORObject> idSig  = EdhocHandler.idCreds.get(Constants.SIGNATURE_KEY);

        if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 1 || method == 3)) {
            kpEcdh.put(Constants.CURVE_P256, keyPair);
            crEcdh.put(Constants.CURVE_P256, cred);
            idEcdh.put(Constants.CURVE_P256, idCred);
        }
        if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 1 || method == 3)) {
            kpEcdh.put(Constants.CURVE_X25519, keyPair);
            crEcdh.put(Constants.CURVE_X25519, cred);
            idEcdh.put(Constants.CURVE_X25519, idCred);
        }
        if ((selectedCiphersuite == 2 || selectedCiphersuite == 3) && (method == 0 || method == 2)) {
            kpSig.put(Constants.CURVE_P256, keyPair);
            crSig.put(Constants.CURVE_P256, cred);
            idSig.put(Constants.CURVE_P256, idCred);
        }
        if ((selectedCiphersuite == 0 || selectedCiphersuite == 1) && (method == 0 || method == 2)) {
            kpSig.put(Constants.CURVE_Ed25519, keyPair);
            crSig.put(Constants.CURVE_Ed25519, cred);
            idSig.put(Constants.CURVE_Ed25519, idCred);
        }

        OneKey peerPublicKey = oneKeyFromCcs(peerCcs, false);
        CBORObject peerIdCred = org.eclipse.californium.edhoc.Util.buildIdCredKid(peerKid);
        EdhocHandler.peerPublicKeys.put(peerIdCred, peerPublicKey);
        EdhocHandler.peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCcs));
    }

    private static OneKey oneKeyFromCcs(byte[] ccsBytes, boolean requirePrivate) throws CoseException {
        CBORObject ccs = CBORObject.DecodeFromBytes(ccsBytes);
        if (ccs == null || ccs.getType() != CBORType.Map)
            throw new IllegalArgumentException("CCS root is not a CBOR map");
        CBORObject claim8 = ccs.get(CBORObject.FromObject(8));
        if (claim8 == null || claim8.getType() != CBORType.Map)
            throw new IllegalArgumentException("CCS does not contain claim 8 as a map");
        CBORObject coseKeyMap = claim8.get(CBORObject.FromObject(1));
        if (coseKeyMap == null || coseKeyMap.getType() != CBORType.Map)
            throw new IllegalArgumentException("CCS claim 8 does not contain key 1 as a COSE_Key map");
        CBORObject keyMap = CBORObject.DecodeFromBytes(coseKeyMap.EncodeToBytes());
        CBORObject dObj = keyMap.get(CBORObject.FromObject(-4));
        if (requirePrivate && dObj == null)
            throw new IllegalArgumentException("CCS COSE_Key is missing required private key parameter -4");
        if (keyMap.ContainsKey(CBORObject.FromObject(-1))
                && keyMap.get(CBORObject.FromObject(-1)).equals(CBORObject.FromObject(4))) {
            byte[] pub = keyMap.get(CBORObject.FromObject(-2)).GetByteString();
            byte[] priv = dObj != null ? dObj.GetByteString() : null;
            return SharedSecretCalculation.buildCurve25519OneKey(priv, pub);
        }
        return new OneKey(keyMap);
    }

    private static byte[] stripPrivateKeyFromCcs(byte[] ccsBytes) {
        CBORObject ccs = CBORObject.DecodeFromBytes(ccsBytes);
        CBORObject coseKeyMap = ccs.get(CBORObject.FromObject(8)).get(CBORObject.FromObject(1));
        coseKeyMap.Remove(CBORObject.FromObject(-4));
        return ccs.EncodeToBytes();
    }

    private static class WellKnownResource extends CoapResource {
        WellKnownResource() { super(".well-known"); }
        @Override public void handleGET(CoapExchange exchange) { exchange.respond(".well-known"); }
    }
}