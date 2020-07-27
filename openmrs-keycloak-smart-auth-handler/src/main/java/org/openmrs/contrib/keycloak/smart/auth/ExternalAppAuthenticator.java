/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth;

import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Objects;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.jboss.logging.Logger;
import org.openmrs.contrib.keycloak.smart.auth.token.ExternalApplicationNotificationActionToken;
import org.openmrs.contrib.keycloak.smart.auth.token.ExternalApplicationNotificationActionTokenHandler;

import static org.openmrs.contrib.keycloak.smart.auth.token.ExternalApplicationNotificationActionTokenHandler.QUERY_PARAM_APP_TOKEN;

/**
 *
 * @author hmlnarik
 */
public class ExternalAppAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(ExternalAppAuthenticator.class);

    public static final String DEFAULT_EXTERNAL_APP_URL = "http://127.0.0.1:8080/action-token-responder-example/external-action.jsp?token={TOKEN}";

    public static final String DEFAULT_APPLICATION_ID = "application-id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String externalApplicationUrl = null;
        String applicationId = null;
        if (context.getAuthenticatorConfig() != null) {
            externalApplicationUrl = context.getAuthenticatorConfig().getConfig().get(ExternalAppAuthenticatorFactory.CONFIG_EXTERNAL_APP_URL);
            applicationId = context.getAuthenticatorConfig().getConfig().get(ExternalAppAuthenticatorFactory.CONFIG_APPLICATION_ID);
        }
        if (externalApplicationUrl == null) {
            externalApplicationUrl = DEFAULT_EXTERNAL_APP_URL;
        }

        if (applicationId == null) {
            applicationId = DEFAULT_APPLICATION_ID;
        }

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
          .queryParam(Constants.EXECUTION, context.getExecution().getId())
          .queryParam(QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
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
    public void action(AuthenticationFlowContext context) {
        final AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (! Objects.equals(authSession.getAuthNote(ExternalApplicationNotificationActionTokenHandler.INITIATED_BY_ACTION_TOKEN_EXT_APP), "true")) {
            authenticate(context);
            return;
        }

        authSession.removeAuthNote(ExternalApplicationNotificationActionTokenHandler.INITIATED_BY_ACTION_TOKEN_EXT_APP);

        // Update user according to the claims in the application token
        String appTokenString = context.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);
        UserModel user = authSession.getAuthenticatedUser();
        String applicationId = null;
        if (context.getAuthenticatorConfig() != null) {
            applicationId = context.getAuthenticatorConfig().getConfig().get(ExternalAppAuthenticatorFactory.CONFIG_APPLICATION_ID);
        }
        if (applicationId == null) {
            applicationId = DEFAULT_APPLICATION_ID;
        }

        try {
            JsonWebToken appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
            final String appId = applicationId;
            appToken.getOtherClaims()
              .forEach((key, value) -> user.setAttribute(appId + "." + key, Collections.singletonList(String.valueOf(value))));
        } catch (VerificationException ex) {
            logger.error("Error handling action token", ex);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
                    .setError(Messages.INVALID_PARAMETER)
                    .createErrorPage(Status.INTERNAL_SERVER_ERROR));
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
