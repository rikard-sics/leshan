/*******************************************************************************
 * Copyright (c) 2022 Sierra Wireless and others.
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
package org.eclipse.leshan.transport.californium.server.endpoint;

import static org.eclipse.leshan.transport.californium.ResponseCodeUtil.toLwM2mResponseCode;

import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.leshan.core.ResponseCode;
import org.eclipse.leshan.core.node.TimestampedLwM2mNode;
import org.eclipse.leshan.core.node.TimestampedLwM2mNodes;
import org.eclipse.leshan.core.node.codec.CodecException;
import org.eclipse.leshan.core.observation.CompositeObservation;
import org.eclipse.leshan.core.observation.Observation;
import org.eclipse.leshan.core.observation.SingleObservation;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.request.DownlinkDeviceManagementRequest;
import org.eclipse.leshan.core.request.exception.InvalidResponseException;
import org.eclipse.leshan.core.response.AbstractLwM2mResponse;
import org.eclipse.leshan.core.response.LwM2mResponse;
import org.eclipse.leshan.core.response.ObserveCompositeResponse;
import org.eclipse.leshan.core.response.ObserveResponse;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.server.endpoint.ServerEndpointToolbox;
import org.eclipse.leshan.server.profile.ClientProfile;
import org.eclipse.leshan.server.request.UplinkDeviceManagementRequestReceiver;
import org.eclipse.leshan.transport.californium.identity.IdentityHandler;
import org.eclipse.leshan.transport.californium.identity.IdentityHandlerProvider;
import org.eclipse.leshan.transport.californium.server.registration.RegisterResource;
import org.eclipse.leshan.transport.californium.server.request.CoapRequestBuilder;
import org.eclipse.leshan.transport.californium.server.request.LwM2mResponseBuilder;
import org.eclipse.leshan.transport.californium.server.send.SendResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerCoapMessageTranslator {

    private final Logger LOG = LoggerFactory.getLogger(ServerCoapMessageTranslator.class);

    public Request createCoapRequest(ClientProfile clientProfile,
            DownlinkDeviceManagementRequest<? extends LwM2mResponse> lwm2mRequest, ServerEndpointToolbox toolbox,
            IdentityHandler identityHandler) {
        CoapRequestBuilder builder = new CoapRequestBuilder(clientProfile.getTransportData(),
                clientProfile.getRootPath(), clientProfile.getRegistrationId(), clientProfile.getEndpoint(),
                clientProfile.getModel(), toolbox.getEncoder(), clientProfile.canInitiateConnection(), null,
                identityHandler);
        lwm2mRequest.accept(builder);
        return builder.getRequest();
    }

    public <T extends LwM2mResponse> T createLwM2mResponse(ClientProfile clientProfile,
            DownlinkDeviceManagementRequest<T> lwm2mRequest, Request coapRequest, Response coapResponse,
            ServerEndpointToolbox toolbox) {

        LwM2mResponseBuilder<T> builder = new LwM2mResponseBuilder<T>(coapRequest, coapResponse,
                clientProfile.getEndpoint(), clientProfile.getRootPath(), clientProfile.getModel(),
                clientProfile.getRegistration().getEndpointUri(), toolbox.getDecoder(), toolbox.getLinkParser());
        lwm2mRequest.accept(builder);
        return builder.getResponse();
    }

    public List<Resource> createResources(UplinkDeviceManagementRequestReceiver receiver, ServerEndpointToolbox toolbox,
            IdentityHandlerProvider identityHandlerProvider) {
        return Arrays.asList( //
                (Resource) new RegisterResource(receiver, toolbox.getLinkParser(), identityHandlerProvider,
                        toolbox.getUriHandler()), //
                (Resource) new SendResource(receiver, toolbox.getDecoder(), toolbox.getProfileProvider(),
                        identityHandlerProvider, toolbox.getUriHandler()));
    }

    public AbstractLwM2mResponse createObserveResponse(Observation observation, Response coapResponse,
            ServerEndpointToolbox toolbox, ClientProfile profile) {
        // get content format
        ContentFormat contentFormat = null;
        if (coapResponse.getOptions().hasContentFormat()) {
            contentFormat = ContentFormat.fromCode(coapResponse.getOptions().getContentFormat());
        }
        // TODO should we check that content format is the same than observation

        // decode response
        try {
            ResponseCode responseCode = toLwM2mResponseCode(coapResponse.getCode());

            if (observation instanceof SingleObservation) {
                SingleObservation singleObservation = (SingleObservation) observation;

                if (responseCode.isError()) {
                    return new ObserveResponse(responseCode, null, null, null, null, coapResponse.getPayloadString(),
                            coapResponse);
                } else {
                    List<TimestampedLwM2mNode> timestampedNodes = toolbox.getDecoder().decodeTimestampedData(
                            coapResponse.getPayload(), contentFormat, profile.getRootPath(),
                            singleObservation.getPath(), profile.getModel());

                    // create lwm2m response
                    if (timestampedNodes.size() == 1 && !timestampedNodes.get(0).isTimestamped()) {
                        return new ObserveResponse(responseCode, timestampedNodes.get(0).getNode(), null, null,
                                singleObservation, null, coapResponse);
                    } else {
                        return new ObserveResponse(responseCode, null, null, timestampedNodes, singleObservation, null,
                                coapResponse);
                    }
                }
            } else if (observation instanceof CompositeObservation) {

                CompositeObservation compositeObservation = (CompositeObservation) observation;

                if (responseCode.isError()) {
                    return new ObserveCompositeResponse(responseCode, null, null, null, null,
                            coapResponse.getPayloadString(), coapResponse);
                } else {
                    TimestampedLwM2mNodes timestampedNodes = toolbox.getDecoder().decodeTimestampedNodes(
                            coapResponse.getPayload(), contentFormat, profile.getRootPath(),
                            compositeObservation.getPaths(), profile.getModel());

                    if (timestampedNodes.getTimestamps().size() == 1
                            && timestampedNodes.getTimestamps().iterator().next() == null) {

                        return new ObserveCompositeResponse(responseCode, timestampedNodes.getMostRecentNodes(), null,
                                null, compositeObservation, null, coapResponse);
                    } else {
                        return new ObserveCompositeResponse(responseCode, null, null, timestampedNodes,
                                compositeObservation, null, coapResponse);
                    }
                }
            }
            throw new IllegalStateException(
                    "observation must be a CompositeObservation or a SingleObservation but was " + observation == null
                            ? null
                            : observation.getClass().getSimpleName());
        } catch (CodecException e) {
            if (LOG.isDebugEnabled()) {
                byte[] payload = coapResponse.getPayload() == null ? new byte[0] : coapResponse.getPayload();
                LOG.debug(String.format("Unable to decode notification payload [%s] of observation [%s] ",
                        Hex.encodeHexString(payload), observation), e);
            }
            throw new InvalidResponseException(e, "Unable to decode notification payload  of observation [%s] ",
                    observation);
        }
    }
}
