/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.provider;

import org.keycloak.Config.Scope;
import org.keycloak.TokenVerifier;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.authentication.actiontoken.*;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.events.*;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.io.IOException;
import java.util.Collections;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;

/**
 * Action token handler for verification of e-mail address.
 * @author hmlnarik
 */
public class ExternalApplicationNotificationActionTokenHandler extends AbstractActionTokenHander<ExternalApplicationNotificationActionToken> {

    public static final String QUERY_PARAM_APP_TOKEN = "app-token";

    private SecretKeySpec hmacSecretKeySpec = null;

    public ExternalApplicationNotificationActionTokenHandler() {
        super(
          ExternalApplicationNotificationActionToken.TOKEN_TYPE,
          ExternalApplicationNotificationActionToken.class,
          Messages.INVALID_REQUEST,
          EventType.EXECUTE_ACTION_TOKEN,
          Errors.INVALID_REQUEST
        );
    }

    private boolean isApplicationTokenValid(
      ExternalApplicationNotificationActionToken token,
      ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext
    ) throws VerificationException {
        String appTokenString = tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

        TokenVerifier.create(appTokenString, JsonWebToken.class)
          .secretKey(hmacSecretKeySpec)
          .verify();

        return true;
    }

    @Override
    public Predicate<? super ExternalApplicationNotificationActionToken>[] getVerifiers(ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext) {
        return TokenUtils.predicates(
          // Check that the app token is set in query parameters
          t -> tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN) != null,

          // Validate correctness of the app token
          t -> isApplicationTokenValid(t, tokenContext)
        );
    }

    private static final Logger LOG = Logger.getLogger(ExternalApplicationNotificationActionTokenHandler.class);

    @Override
    public String getAuthenticationSessionIdFromToken(ExternalApplicationNotificationActionToken token, ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext,
      AuthenticationSessionModel currentAuthSession) {
        // always join current authentication session
        final String id = currentAuthSession == null
          ? null
          : AuthenticationSessionCompoundId.fromAuthSession(currentAuthSession).getEncodedId();

        LOG.infof("Returning %s", id);

        return id;
    }

    @Override
    public Response handleToken(ExternalApplicationNotificationActionToken token, ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        EventBuilder event = tokenContext.getEvent();

        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();

        // Update user according to the claims in the application token
        String appTokenString = tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);
        try {
            JsonWebToken appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
            appToken.getOtherClaims()
              .forEach((key, value) -> user.setAttribute(token.getApplicationId() + "." + key, Collections.singletonList(String.valueOf(value))));
        } catch (VerificationException ex) {
            return tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setError(Messages.INVALID_PARAMETER)
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
        }

        event.success();

        user.removeRequiredAction(RedirectToExternalApplication.ID);
        authSession.removeRequiredAction(RedirectToExternalApplication.ID);

        // User updated. Now if authentication is not in progress (e.g. opened in a new browser window), just show an info that account has been updated
        if (tokenContext.isAuthenticationSessionFresh()) {
            AuthenticationSessionManager asm = new AuthenticationSessionManager(tokenContext.getSession());
            asm.removeAuthenticationSession(tokenContext.getRealm(), authSession, true);
            return tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setSuccess(Messages.ACCOUNT_UPDATED)
                    .createInfoPage();
        }

        // Otherwise continue with next required action (if any)
        String nextAction = AuthenticationManager.nextRequiredAction(tokenContext.getSession(), authSession, tokenContext.getClientConnection(), tokenContext.getRequest(), tokenContext.getUriInfo(), event);
        return AuthenticationManager.redirectToRequiredActions(tokenContext.getSession(), tokenContext.getRealm(), authSession, tokenContext.getUriInfo(), nextAction);
    }

    @Override
    public void init(Scope config) {
        final String secret = config.get("hmacSecret", null);

        if (secret == null) {
            throw new RuntimeException("You have to configure HMAC secret");
        }

        try {
            this.hmacSecretKeySpec = new SecretKeySpec(Base64.decode(secret), "HmacSHA256");
        } catch (IOException ex) {
            throw new RuntimeException("Cannot decode HMAC secret from string", ex);
        }
    }
}
