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
    public static final String KEYS_NAME = "nukleus.oauth.keys";
    public static final String AUTO_DISCOVER_REALMS_NAME = "nukleus.oauth.auto.discover.realms";
    public static final String CHALLENGE_DELTA_CLAIM_NAMESPACE_NAME = "nukleus.oauth.namespace";
    public static final String CHALLENGE_DELTA_CLAIM_NAME_NAME = "nukleus.oauth.name";

    static final ConfigurationDef OAUTH_CONFIG;
    static final BooleanPropertyDef EXPIRE_IN_FLIGHT_REQUESTS;
    static final PropertyDef<String> KEYS;
    static final BooleanPropertyDef AUTO_DISCOVER_REALMS;
    static final PropertyDef<String> CHALLENGE_DELTA_CLAIM_NAMESPACE;
    static final PropertyDef<String> CHALLENGE_DELTA_CLAIM_NAME;

    static
    {
        final ConfigurationDef config = new ConfigurationDef("nukleus.oauth");
        KEYS = config.property("keys", "keys.jwk");
        EXPIRE_IN_FLIGHT_REQUESTS = config.property("expire.in.flight.requests", true);
        AUTO_DISCOVER_REALMS = config.property("auto.discover.realms", false);
        CHALLENGE_DELTA_CLAIM_NAMESPACE = config.property("namespace", "https://reaktivity.org/");
        CHALLENGE_DELTA_CLAIM_NAME = config.property("name", "challenge_response_delta");
        OAUTH_CONFIG = config;
    }

    public OAuthConfiguration(
        Configuration config)
    {
        super(OAUTH_CONFIG, config);
    }

    public String keyFileName()
    {
        return KEYS.get(this);
    }

    public boolean expireInFlightRequests()
    {
        return EXPIRE_IN_FLIGHT_REQUESTS.getAsBoolean(this);
    }

    public boolean autoDiscoverRealms()
    {
        return AUTO_DISCOVER_REALMS.getAsBoolean(this);
    }

    public String getChallengeDeltaClaimNamespace()
    {
        return CHALLENGE_DELTA_CLAIM_NAMESPACE.get(this);
    }

    public String getChallengeDeltaClaimName()
    {
        return CHALLENGE_DELTA_CLAIM_NAME.get(this);
    }
}
