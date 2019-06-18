/**
 * Copyright 2016-2019 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.nukleus.oauth.internal;

import org.reaktivity.nukleus.Configuration;

public class OAuthConfiguration extends Configuration
{
    public static final PropertyDef<String> AUTH_JWT_KEYS;

    private static final ConfigurationDef AUTH_JWT_CONFIG;
    private static final BooleanPropertyDef EXPIRE_IN_FLIGHT_REQUESTS;

    static
    {
        // TODO: rename scope to "nukleus.auth_jwt"
        final ConfigurationDef config = new ConfigurationDef("oauth");
        AUTH_JWT_KEYS = config.property("keys", "keys.jwk");
        AUTH_JWT_CONFIG = config;
        EXPIRE_IN_FLIGHT_REQUESTS = config.property("expire.in.flight.requests", true);
    }

    public OAuthConfiguration(
        Configuration config)
    {
        super(AUTH_JWT_CONFIG, config);
    }

    public String keyFileName()
    {
        return AUTH_JWT_KEYS.get(this);
    }

    public boolean expireInFlightRequests()
    {
        return EXPIRE_IN_FLIGHT_REQUESTS.getAsBoolean(this);
    }
}
