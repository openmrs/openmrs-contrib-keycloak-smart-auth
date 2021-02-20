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
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartLaunchAccessActionToken;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartUserNameToken;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.keycloak.OAuth2Constants.JWT;

public class SmartLaunchAccessAuthenticator implements Authenticator {

	public static final String QUERY_PARAM_APP_TOKEN = "app-token";

	public static final String SMART_ACCESS = "smart-access";

	public static final String DEFAULT_PATIENT_ACCESS_URL = "http://localhost:8080/openmrs/ws/rest/v1/smartonfhir/accessConfirmation?token={TOKEN}";

	public static final String DEFAULT_EXTERNAL_SMART_LAUNCH_SECRET_KEY = "";

	@Override
	public void authenticate(AuthenticationFlowContext context) {

		final String launch = context.getAuthenticationSession()
				.getClientNote(SmartLaunchAuthenticator.LAUNCH_CLIENT_REQUEST_PARAM);
		final String scope = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);

		if (launch != null && scope != null) {

			context.getAuthenticationSession().setClientNote(SmartLaunchAuthenticator.SMART_PATIENT_PARAMS, launch);

			String accessEndUrl = null;
			if (context.getAuthenticatorConfig() != null) {
				accessEndUrl = context.getAuthenticatorConfig().getConfig()
						.get(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_URL);
			}

			if (accessEndUrl == null) {
				accessEndUrl = DEFAULT_PATIENT_ACCESS_URL;
			}

			int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
			int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
			final AuthenticationSessionModel authSession = context.getAuthenticationSession();
			final String clientId = authSession.getClient().getClientId();

			SmartLaunchAccessActionToken externalToken = new SmartLaunchAccessActionToken(
					context.getSession().users().getUserByUsername("admin", context.getRealm()).getId(),
					absoluteExpirationInSecs,
					AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId()
			);

			try {
				externalToken
						.setNote("user", buildUserNameToken(context, absoluteExpirationInSecs, clientId,
								accessEndUrl));
			}
			catch (IOException e) {
				throw new AuthenticationFlowException("Could not create access token", e,
						AuthenticationFlowError.INTERNAL_ERROR);
			}

			String token = externalToken.serialize(
					context.getSession(),
					context.getRealm(),
					context.getUriInfo()
			);

			String SubmitActionTokenUrl = Urls
					.actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId())
					.queryParam(Constants.EXECUTION, context.getExecution().getId())
					.queryParam(QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
					.build(context.getRealm().getName(), "{APP_TOKEN}")
					.toString();

			try {
				Response challenge = Response
						.status(Response.Status.FOUND)
						.header("Location",
								accessEndUrl.replace("{TOKEN}",
										URLEncoder.encode(SubmitActionTokenUrl, StandardCharsets.UTF_8.name())))
						.build();
				context.challenge(challenge);
			}
			catch (UnsupportedEncodingException e) {
				throw new AuthenticationFlowException("Could not decode token", e, AuthenticationFlowError.INTERNAL_ERROR);
			}

			return;
		}

		context.attempted();
	}

	@Override
	public void action(AuthenticationFlowContext context) {

		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (!Objects.equals(authSession.getAuthNote(SMART_ACCESS), "true")) {
			authenticate(context);
			return;
		}

		authSession.removeAuthNote(SMART_ACCESS);

		String appTokenString = context.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

		if (StringUtils.isBlank(appTokenString)) {
			authenticate(context);
			return;
		}

		JsonWebToken appToken;
		try {
			validateAppToken(context, appTokenString);
			appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
		}
		catch (IOException | VerificationException e) {
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError(Messages.INVALID_PARAMETER)
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		String username = appToken.getSubject();
		UserModel user = context.getSession().users().getUserByUsername(username, context.getRealm());
		context.getAuthenticationSession().setAuthenticatedUser(user);

		context.success();
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

	}

	@Override
	public void close() {

	}

	private String buildUserNameToken(AuthenticationFlowContext context, int absoluteExpirationInSecs, String clientId,
			String accessUrl) throws IOException {

		SmartUserNameToken userToken = new SmartUserNameToken(
				absoluteExpirationInSecs,
				clientId
		);

		String issuer = Urls.realmIssuer(context.getUriInfo().getBaseUri(), context.getRealm().getName());
		userToken.issuer(issuer);

		URL usernameAudienceUrl;
		try {
			usernameAudienceUrl = new URL(accessUrl);
		}
		catch (MalformedURLException e) {
			throw new AuthenticationFlowException("Could not parse external URL " + accessUrl, e,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		StringBuilder sb = new StringBuilder(usernameAudienceUrl.getProtocol()).append("://")
				.append(usernameAudienceUrl.getHost());
		if (usernameAudienceUrl.getPort() != usernameAudienceUrl.getDefaultPort()) {
			sb.append(":").append(usernameAudienceUrl.getPort());
		}
		userToken.audience(sb.toString());

		KeyWrapper key = new KeyWrapper();
		key.setAlgorithm(Algorithm.HS256);
		key.setSecretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getName()));
		SignatureSignerContext signer = new MacSignatureSignerContext(key);

		return new JWSBuilder().type(JWT).jsonContent(userToken).sign(signer);
	}

	private SecretKeySpec getSecretKey(AuthenticatorConfigModel authenticatorConfig, String realmName) throws
			IOException {
		String secretKey = null;
		if (authenticatorConfig != null) {
			secretKey = authenticatorConfig.getConfig()
					.get(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY);
		}

		if (StringUtils.isBlank(secretKey)) {
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		return new SecretKeySpec(Base64.decode(secretKey), JavaAlgorithm.HS256);
	}

	private void validateAppToken(AuthenticationFlowContext context, String appTokenString)
			throws VerificationException, IOException {
		TokenVerifier.create(appTokenString, JsonWebToken.class)
				.secretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()))
				.verify();
	}
}
