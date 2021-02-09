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

import static org.keycloak.provider.ProviderConfigProperty.PASSWORD;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class SmartLaunchAccessAuthenticatorFactory implements AuthenticatorFactory {

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.DISABLED
	};

	public static final String CONFIG_SMART_LAUNCH_ACCESS_URL = "smart-launch-access-url";

	public static final String CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY = "smart-launch-access-secret-key";

	public static final String ID = "smart-access-authenticator";

	public static final SmartLaunchAccessAuthenticator SINGLETON = new SmartLaunchAccessAuthenticator();

	@Override
	public String getDisplayType() {
		return "Smart Access Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return "Smart Access";
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
		return "Smart Access Authenticator";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {

		ProviderConfigProperty patientSelectionUrl = new ProviderConfigProperty(CONFIG_SMART_LAUNCH_ACCESS_URL,
				"Access Endpoint URL",
				"URL of the endpoint to redirect to.",
				STRING_TYPE, SmartLaunchAccessAuthenticator.DEFAULT_PATIENT_ACCESS_URL);

		ProviderConfigProperty smartLaunchKey = new ProviderConfigProperty(CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY,
				"SMART Launch Access Secret Key",
				"HmacSHA256 secret key for smart launch external application.",
				PASSWORD, SmartLaunchAccessAuthenticator.DEFAULT_EXTERNAL_SMART_LAUNCH_SECRET_KEY);

		return Arrays.asList(patientSelectionUrl, smartLaunchKey);
	}

	@Override
	public Authenticator create(KeycloakSession keycloakSession) {
		return SINGLETON;
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
