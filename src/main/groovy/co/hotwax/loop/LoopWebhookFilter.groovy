/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package co.hotwax.loop

import groovy.transform.CompileStatic
import org.moqui.entity.EntityCondition
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.moqui.impl.context.ContextJavaUtil
import org.moqui.impl.context.ExecutionContextFactoryImpl
import org.moqui.impl.context.ExecutionContextImpl
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.apache.commons.io.IOUtils

import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@CompileStatic
class LoopWebhookFilter implements Filter {

    protected static final Logger logger = LoggerFactory.getLogger(LoopWebhookFilter.class)
    protected FilterConfig filterConfig = null

    LoopWebhookFilter() { super() }

    @Override
    void init(FilterConfig filterConfig) {
        this.filterConfig = filterConfig
    }

    @Override
    void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        if (!(req instanceof HttpServletRequest) || !(resp instanceof HttpServletResponse)) {
            chain.doFilter(req, resp); return
        }

        HttpServletRequest request = (HttpServletRequest) req
        HttpServletResponse response = (HttpServletResponse) resp

        ServletContext servletContext = req.getServletContext()

        ExecutionContextFactoryImpl ecfi = (ExecutionContextFactoryImpl) servletContext.getAttribute("executionContextFactory")
        // check for and cleanly handle when executionContextFactory is not in place in ServletContext attr
        if (ecfi == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "System is initializing, try again soon.")
            return
        }

        try {
            // Verify the incoming webhook request
            verifyIncomingWebhook(request, response, ecfi.getEci())
            chain.doFilter(req, resp)
        } catch(Throwable t) {
            logger.error("Error occurred in Loop Webhook verification", t)
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in Loop webhook verification: ${t.toString()}")
        }
    }

    @Override
    void destroy() {
        // Your implementa tion here }
    }

    void verifyIncomingWebhook(HttpServletRequest request, HttpServletResponse response, ExecutionContextImpl ec) {
        String hmac = request.getHeader("X-Loop-Signature")
        String requestBody = IOUtils.toString(request.getReader());
        String url = request.getRequestURL().toString()
        String webhookPartyId = null;

        if (requestBody.length() == 0) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "The Request Body is empty for Loop webhook")
            return
        }
        if (url) {
            String[] urlParts = url.split("/");
            webhookPartyId = urlParts[urlParts.length - 1];
        }


        Map<String, String> payloadMap = ContextJavaUtil.jacksonMapper.readValue(requestBody, Map.class)
        String webhookTrigger = payloadMap.get("trigger");

        request.setAttribute("payload", ContextJavaUtil.jacksonMapper.readValue(requestBody, Map.class))

        EntityValue systemMessageRemote = null;
        EntityValue systemMessageRemoteWebhook = ec.entityFacade.find("co.hotwax.netsuite.party.PartySystemMessageRemote")
                .condition("partyId", webhookPartyId).condition("systemMessageTypeId", "LoopWebhook").useCache(true).disableAuthz().one();
        if (systemMessageRemoteWebhook) {
            systemMessageRemote = ec.entityFacade.find("moqui.service.message.SystemMessageRemote")
                    .condition("systemMessageRemoteId", systemMessageRemoteWebhook.systemMessageRemoteId).useCache(true).disableAuthz().one();
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The webhook ${webhookTrigger} is not configured for Loop")
            return
        }

        // Call service to verify Hmac
        Map result = ec.serviceFacade.sync().name("co.hotwax.loop.webhook.LoopWebhookServices.verify#Hmac")
                .parameters([message:requestBody, hmac:hmac, sharedSecret:systemMessageRemote.sendSharedSecret])
                .disableAuthz().call()

        // If the hmac matched with the calculatedHmac, break the loop and return
        if (result.isValidWebhook) {
            EntityValue systemMessageRemoteSFTP = ec.entityFacade.find("co.hotwax.netsuite.party.PartySystemMessageRemote")
                    .condition("partyId", webhookPartyId).condition("systemMessageTypeId", "LoopSFTP").useCache(true).disableAuthz().one();
            if (systemMessageRemoteSFTP) {
                request.setAttribute("systemMessageRemoteId", systemMessageRemoteSFTP.systemMessageRemoteId)
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The SFTP ${webhookTrigger} is not configured for Loop")
                return
            }
            request.setAttribute("webhookTrigger", webhookTrigger)
            request.setAttribute("webhookPartyId", webhookPartyId);
            return;
        }
        logger.warn("The webhook ${webhookTrigger} HMAC header did not match with the computed HMAC for Loop")
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "HMAC verification failed for Loop for webhook ${webhookTrigger}")
    }
}