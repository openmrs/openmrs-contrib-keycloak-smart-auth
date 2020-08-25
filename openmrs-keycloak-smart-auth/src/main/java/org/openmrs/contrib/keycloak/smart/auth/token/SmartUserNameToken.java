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

import org.keycloak.authentication.actiontoken.DefaultActionToken;
import org.keycloak.representations.JsonWebToken;

public class SmartUserNameToken extends JsonWebToken {

	public static final String TOKEN_TYPE = "smart-username-token";

	// required to deserialize correctly
	@SuppressWarnings("unused")
	private SmartUserNameToken() {
		super();
	}

	public SmartUserNameToken(String userName, long absoluteExpirationInSecs, String authenticationSessionId) {
		this.subject = userName;
		this.type = TOKEN_TYPE;
		this.exp = absoluteExpirationInSecs;
		this.otherClaims.put(DefaultActionToken.JSON_FIELD_AUTHENTICATION_SESSION_ID, authenticationSessionId);
	}
}
