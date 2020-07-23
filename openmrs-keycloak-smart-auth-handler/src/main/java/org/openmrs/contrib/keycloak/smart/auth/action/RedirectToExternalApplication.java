/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.action;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.openmrs.contrib.keycloak.smart.auth.token.ExternalApplicationNotificationActionToken;
import org.openmrs.contrib.keycloak.smart.auth.token.ExternalApplicationNotificationActionTokenHandler;

/**
 *
 * @author hmlnarik
 */
@Slf4j
public class RedirectToExternalApplication implements RequiredActionProvider, RequiredActionFactory {

    public static final String ID = "redirect-to-external-application";

    public static final String DEFAULT_APPLICATION_ID = "application-id";

    private String externalApplicationUrl = "http://localhost:8080/?token={TOKEN}";

    private String applicationId = DEFAULT_APPLICATION_ID;

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
        final AuthenticationSessionModel authSession = context.getAuthenticationSession();
        final String clientId = authSession.getClient().getClientId();

        // Create a token used to return back to the current authentication flow
        String token = new ExternalApplicationNotificationActionToken(
          context.getUser().getId(),
          absoluteExpirationInSecs,
          clientId,
          applicationId
        ).serialize(
          context.getSession(),
          context.getRealm(),
          context.getUriInfo()
        );

        // This URL will be used by the application to submit the action token above to return back to the flow
        String submitActionTokenUrl;
        submitActionTokenUrl = Urls
          .actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId())
          .queryParam(ExternalApplicationNotificationActionTokenHandler.QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
          .build(context.getRealm().getName(), "{APP_TOKEN}")
          .toString();

        try {
            Response challenge = Response
              .status(Status.FOUND)
              .header("Location", externalApplicationUrl.replace("{TOKEN}", URLEncoder.encode(submitActionTokenUrl, "UTF-8")))
              .build();

            context.challenge(challenge);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }


    @Override
    public void processAction(RequiredActionContext context) {
        requiredActionChallenge(context);
    }


    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Redirect to external application";
    }

    @Override
    public String getId() {
        return ID;
    }
}
