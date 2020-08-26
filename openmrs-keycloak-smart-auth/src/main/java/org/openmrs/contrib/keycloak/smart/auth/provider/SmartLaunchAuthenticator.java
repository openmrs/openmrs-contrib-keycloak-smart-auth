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

import org.apache.commons.lang3.StringUtils;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.MacSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartPatientSelectionActionToken;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartUserNameToken;

import static org.keycloak.OAuth2Constants.JWT;

public class SmartLaunchAuthenticator implements Authenticator {

	public static final String QUERY_PARAM_APP_TOKEN = "app-token";

	public static final String SMART_PATIENT_SELECTION = "smart-patient-selection";

	public static final String SMART_NOTE_PREFIX = "smart-oidc-note.";

	public static final String DEFAULT_PATIENT_SELECTION_APP_URL = "http://localhost:8080/openmrs/smartonfhir/findPatient.page?app=smart.search&token={TOKEN}";

	public static final String DEFAULT_EXTERNAL_SMART_LAUNCH_SECRET_KEY = "";

	private static final Logger logger = Logger.getLogger(SmartLaunchAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		String patientSelectionUrl = null;
		if (context.getAuthenticatorConfig() != null) {
			patientSelectionUrl = context.getAuthenticatorConfig().getConfig()
					.get(SmartLaunchAuthenticatorFactory.CONFIG_SMART_PATIENT_SELECTION_URL);
		}

		if (patientSelectionUrl == null) {
			patientSelectionUrl = DEFAULT_PATIENT_SELECTION_APP_URL;
		}

		int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
		int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		final String clientId = authSession.getClient().getClientId();

		// Create a token used to return back to the current authentication flow
		SmartPatientSelectionActionToken externalToken = new SmartPatientSelectionActionToken(
				context.getUser().getId(),
				absoluteExpirationInSecs,
				AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId()
		);

		try {
			externalToken
					.setNote("user", buildUserNameToken(context, absoluteExpirationInSecs, clientId, patientSelectionUrl));
		}
		catch (IOException e) {
			throw new AuthenticationFlowException("Could not create user token", e, AuthenticationFlowError.INTERNAL_ERROR);
		}

		String token = externalToken.serialize(
				context.getSession(),
				context.getRealm(),
				context.getUriInfo()
		);

		// This URL will be used by the application to submit the action token above to return back to the flow
		String submitActionTokenUrl = Urls
				.actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId())
				.queryParam(Constants.EXECUTION, context.getExecution().getId())
				.queryParam(QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
				.build(context.getRealm().getName(), "{APP_TOKEN}")
				.toString();

		try {
			Response challenge = Response
					.status(Status.FOUND)
					.header("Location",
							patientSelectionUrl.replace("{TOKEN}",
									URLEncoder.encode(submitActionTokenUrl, StandardCharsets.UTF_8.name())))
					.build();
			context.challenge(challenge);
		}
		catch (UnsupportedEncodingException e) {
			throw new AuthenticationFlowException("Could not decode token", e, AuthenticationFlowError.INTERNAL_ERROR);
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (!Objects.equals(authSession.getAuthNote(SMART_PATIENT_SELECTION), "true")) {
			authenticate(context);
			return;
		}

		authSession.removeAuthNote(SMART_PATIENT_SELECTION);

		String appTokenString = context.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

		if (StringUtils.isBlank(appTokenString)) {
			// try again
			authenticate(context);
			return;
		}

		JsonWebToken appToken;
		try {
			validateAppToken(context, appTokenString);
			appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
		}
		catch (IOException | VerificationException e) {
			logger.error("Error handling action token", e);
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError(Messages.INVALID_PARAMETER)
					.createErrorPage(Status.INTERNAL_SERVER_ERROR));
			return;
		}

		appToken.getOtherClaims()
				.forEach((key, value) -> {
					if (value instanceof String) {
						authSession.setUserSessionNote(SMART_NOTE_PREFIX + key, (String) value);
					}
				});

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

	private String buildUserNameToken(AuthenticationFlowContext context, int absoluteExpirationInSecs, String clientId,
			String patientSelectionUrl) throws IOException {
		// here we create a token indicating the user pre-authenticated with Keycloak
		// this enables us to "login" as the user temporarily to select the appropriate patient
		SmartUserNameToken userToken = new SmartUserNameToken(
				context.getUser().getUsername(),
				absoluteExpirationInSecs,
				clientId
		);

		String issuer = Urls.realmIssuer(context.getUriInfo().getBaseUri(), context.getRealm().getName());
		userToken.issuer(issuer);

		URL usernameAudienceUrl;
		try {
			usernameAudienceUrl = new URL(patientSelectionUrl);
		}
		catch (MalformedURLException e) {
			throw new AuthenticationFlowException("Could not parse external URL " + patientSelectionUrl, e,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		StringBuilder sb = new StringBuilder(usernameAudienceUrl.getProtocol()).append("://")
				.append(usernameAudienceUrl.getHost());
		if (usernameAudienceUrl.getPort() != usernameAudienceUrl.getDefaultPort()) {
			sb.append(":").append(usernameAudienceUrl.getPort());
		}
		userToken.audience(sb.toString());

		// sign the token with a shared secret so it can be verified by the client
		KeyWrapper key = new KeyWrapper();
		key.setAlgorithm(Algorithm.HS256);
		key.setSecretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()));
		SignatureSignerContext signer = new MacSignatureSignerContext(key);

		return new JWSBuilder().type(JWT).jsonContent(userToken).sign(signer);
	}

	private void validateAppToken(AuthenticationFlowContext context, String appTokenString)
			throws VerificationException, IOException {
		TokenVerifier.create(appTokenString, JsonWebToken.class)
				.secretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()))
				.verify();
	}

	private SecretKeySpec getSecretKey(AuthenticatorConfigModel authenticatorConfig, String realmName) throws IOException {
		String secretKey = null;

		if (authenticatorConfig != null) {
			secretKey = authenticatorConfig.getConfig()
					.get(SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY);
		}

		if (StringUtils.isBlank(secretKey)) {
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		return new SecretKeySpec(Base64.decode(secretKey), JavaAlgorithm.HS256);
	}
}
