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

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/**
 * Representation of a token that represents a time-limited verify e-mail action.
 *
 * @author hmlnarik
 */
public class ExternalApplicationNotificationActionToken extends DefaultActionToken {

    public static final String TOKEN_TYPE = "external-app-notification";

    private static final String JSON_FIELD_APP_ID = "app-id";

    @JsonProperty(value = JSON_FIELD_APP_ID)
    private String applicationId;

    public ExternalApplicationNotificationActionToken(String userId, int absoluteExpirationInSecs, String authenticationSessionId, String applicationId) {
        super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null, authenticationSessionId);
        this.applicationId = applicationId;
    }

    private ExternalApplicationNotificationActionToken() {
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }
}
