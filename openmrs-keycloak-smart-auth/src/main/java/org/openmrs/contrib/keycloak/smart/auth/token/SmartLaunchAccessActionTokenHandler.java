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

import static org.keycloak.services.resources.LoginActionsService.AUTHENTICATE_PATH;

import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.services.messages.Messages;
import org.openmrs.contrib.keycloak.smart.auth.provider.SmartLaunchAccessAuthenticator;

import javax.ws.rs.core.Response;

public class SmartLaunchAccessActionTokenHandler extends AbstractActionTokenHander<SmartLaunchAccessActionToken> {

	public SmartLaunchAccessActionTokenHandler() {
		super(
				SmartLaunchAccessActionToken.TOKEN_TYPE,
				SmartLaunchAccessActionToken.class,
				Messages.INVALID_REQUEST,
				EventType.EXECUTE_ACTION_TOKEN,
				Errors.INVALID_REQUEST
		);
	}

	@Override
	public Response handleToken(SmartLaunchAccessActionToken token,
			ActionTokenContext<SmartLaunchAccessActionToken> tokenContext) {
		tokenContext.getAuthenticationSession().setAuthNote(SmartLaunchAccessAuthenticator.SMART_ACCESS, "true");
		return tokenContext.processFlow(true, AUTHENTICATE_PATH, tokenContext.getRealm().getBrowserFlow(), null,
				new AuthenticationProcessor());
	}
}
