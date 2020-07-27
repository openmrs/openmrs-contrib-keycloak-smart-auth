/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.token;

import javax.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.keycloak.models.ActionTokenValueModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;

/**
 * Representation of a token that represents a time-limited verify e-mail action.
 *
 * @author hmlnarik
 */
public class ExternalApplicationNotificationActionToken extends JsonWebToken implements ActionTokenValueModel {

	public static final String JSON_FIELD_AUTHENTICATION_SESSION_ID = "asid";

	public static final String JSON_FIELD_ACTION_VERIFICATION_NONCE = "nonce";

	public static final String TOKEN_TYPE = "external-app-notification";

	private static final String JSON_FIELD_APP_ID = "app-id";

	@JsonProperty(value = JSON_FIELD_ACTION_VERIFICATION_NONCE, required = true)
	@Getter
	private final UUID actionVerificationNonce;

	@JsonProperty(value = JSON_FIELD_APP_ID)
	private String applicationId;

	public ExternalApplicationNotificationActionToken(String userId, int absoluteExpirationInSecs,
			String authenticationSessionId, String applicationId) {
		this.subject = userId;
		this.type = TOKEN_TYPE;
		this.exp = (long) absoluteExpirationInSecs;
		this.applicationId = applicationId;
		this.actionVerificationNonce = UUID.randomUUID();
		setCompoundAuthenticationSessionId(authenticationSessionId);
	}

	public String getApplicationId() {
		return applicationId;
	}

	@SuppressWarnings("unused")
	public void setApplicationId(String applicationId) {
		this.applicationId = applicationId;
	}

	@Override
	public Map<String, String> getNotes() {
		Map<String, String> res = new HashMap<>();
		if (getCompoundAuthenticationSessionId() != null) {
			res.put(JSON_FIELD_AUTHENTICATION_SESSION_ID, getCompoundAuthenticationSessionId());
		}
		return res;
	}

	@Override
	public String getNote(String name) {
		Object res = getOtherClaims().get(name);
		return res instanceof String ? (String) res : null;
	}

	@JsonProperty(value = JSON_FIELD_AUTHENTICATION_SESSION_ID)
	public String getCompoundAuthenticationSessionId() {
		return (String) getOtherClaims().get(JSON_FIELD_AUTHENTICATION_SESSION_ID);
	}

	@JsonProperty(value = JSON_FIELD_AUTHENTICATION_SESSION_ID)
	@SuppressWarnings("unused")
	public final void setCompoundAuthenticationSessionId(String authenticationSessionId) {
		setOtherClaims(JSON_FIELD_AUTHENTICATION_SESSION_ID, authenticationSessionId);
	}

	/**
	 * Updates the following fields and serializes this token into a signed JWT. The list of updated fields follows:
	 * <ul>
	 * <li>{@code id}: random nonce</li>
	 * <li>{@code issuedAt}: Current time</li>
	 * <li>{@code issuer}: URI of the given realm</li>
	 * <li>{@code audience}: URI of the given realm (same as issuer)</li>
	 * </ul>
	 *
	 * @param session
	 * @param realm
	 * @param uri
	 * @return
	 */
	public String serialize(KeycloakSession session, RealmModel realm, UriInfo uri) {
		String issuerUri = getIssuer(realm, uri);
		this.issuedNow().id(getActionVerificationNonce().toString()).issuer(issuerUri).audience(issuerUri);
		return session.tokens().encode(this);
	}

	private static String getIssuer(RealmModel realm, UriInfo uri) {
		return Urls.realmIssuer(uri.getBaseUri(), realm.getName());
	}
}
