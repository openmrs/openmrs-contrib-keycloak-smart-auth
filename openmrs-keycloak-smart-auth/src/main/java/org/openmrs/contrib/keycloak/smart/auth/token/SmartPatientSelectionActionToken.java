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

/**
 * An action token used to authenticate to a patient selection application to complete the SMART launch sequence where
 * a patient is required.
 */
public class SmartPatientSelectionActionToken extends DefaultActionToken {

    public static final String TOKEN_TYPE = "smart-patient-selection";

    // required to deserialize correctly
    @SuppressWarnings("unused")
    private SmartPatientSelectionActionToken() {
        super();
    }

    public SmartPatientSelectionActionToken(String userId, int absoluteExpirationInSecs, String authenticationSessionId) {
        super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null, authenticationSessionId);
    }
}
