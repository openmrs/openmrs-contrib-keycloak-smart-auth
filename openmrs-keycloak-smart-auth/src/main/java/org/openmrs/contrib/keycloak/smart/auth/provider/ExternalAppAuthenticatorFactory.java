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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

/**
 * @author hmlnarik
 */
public class ExternalAppAuthenticatorFactory implements AuthenticatorFactory {

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED
	};

	public static final String CONFIG_APPLICATION_ID = "application-id";

	public static final String CONFIG_EXTERNAL_APP_URL = "external-application-url";

	public static final String CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY = "external-smart-launch-secret-key";

	public static final String ID = "external-application-authenticator";

	@Override
	public String getDisplayType() {
		return "External Application Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return null;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "External Application Authenticator";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		ProviderConfigProperty rep1 = new ProviderConfigProperty(CONFIG_APPLICATION_ID, "Application ID",
				"Application ID sent in the token",
				STRING_TYPE, ExternalAppAuthenticator.DEFAULT_APPLICATION_ID);

		ProviderConfigProperty rep2 = new ProviderConfigProperty(CONFIG_EXTERNAL_APP_URL, "External Application URL",
				"URL of the application to redirect to. It has to contain token position marked with \"{TOKEN}\" (without quotes).",
				STRING_TYPE, ExternalAppAuthenticator.DEFAULT_EXTERNAL_APP_URL);

		ProviderConfigProperty rep3 = new ProviderConfigProperty(CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY,
				"External SMART Launch Secret Key",
				"HmacSHA256 secret key for smart launch external application.",
				STRING_TYPE, ExternalAppAuthenticator.DEFAULT_EXTERNAL_SMART_LAUNCH_SECRET_KEY);

		return Arrays.asList(rep1, rep2, rep3);
	}

	@Override
	public Authenticator create(KeycloakSession keycloakSession) {
		return new ExternalAppAuthenticator();
	}

	@Override
	public void init(Config.Scope scope) {
	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return ID;
	}
}
