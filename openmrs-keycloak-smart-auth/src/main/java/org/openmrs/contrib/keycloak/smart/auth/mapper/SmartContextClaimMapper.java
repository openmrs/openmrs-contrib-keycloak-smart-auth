/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.mapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

public class SmartContextClaimMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenResponseMapper {

	public static final String PROVIDER_ID = "smart-context-claim-mapper";

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

	static {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
		property.setName(ProtocolMapperUtils.USER_SESSION_NOTE);
		property.setLabel(ProtocolMapperUtils.USER_SESSION_MODEL_NOTE_LABEL);
		property.setHelpText(ProtocolMapperUtils.USER_SESSION_MODEL_NOTE_HELP_TEXT);
		property.setType(ProviderConfigProperty.STRING_TYPE);
		CONFIG_PROPERTIES.add(property);
		OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, UserSessionNoteMapper.class);
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayCategory() {
		return "Token response mapper";
	}

	@Override
	public String getDisplayType() {
		return "SMART Context Claim";
	}

	@Override
	public String getHelpText() {
		return "Maps a user session note to a SMART context claim";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	@Override
	public AccessTokenResponse transformAccessTokenResponse(AccessTokenResponse token, ProtocolMapperModel mappingModel,
			KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
		setClaim(token, mappingModel, userSession, session, clientSessionCtx);
		return token;
	}

	@Override
	protected void setClaim(AccessTokenResponse token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		String noteName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_SESSION_NOTE);
		String noteValue = userSession.getNote(noteName);
		if (noteValue == null) {
			return;
		}

		Object attributeValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, noteValue);

		if (attributeValue == null) {
			return;
		}

		String protocolClaim = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
		if (protocolClaim == null) {
			return;
		}

		List<String> split = OIDCAttributeMapperHelper.splitClaimPath(protocolClaim);

		final int length = split.size();
		int i = 0;
		Map<String, Object> jsonObject = token.getOtherClaims();
		for (String component : split) {
			i++;
			if (i == length) {
				jsonObject.put(component, attributeValue);
			} else {
				@SuppressWarnings("unchecked")
				Map<String, Object> nested = (Map<String, Object>) jsonObject.get(component);

				if (nested == null) {
					nested = new HashMap<>();
					jsonObject.put(component, nested);
				}

				jsonObject = nested;
			}
		}
	}
}
