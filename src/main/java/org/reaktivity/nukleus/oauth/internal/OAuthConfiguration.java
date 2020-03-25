/**
 * Copyright 2016-2020 The Reaktivity Project
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
    public static final String CLAIM_NAMESPACE_NAME = "nukleus.oauth.claim.namespace";
    public static final String CLAIM_NAME_CHALLENGE_TIMEOUT_NAME = "nukleus.oauth.claim.name.challenge.timeout";

    static final ConfigurationDef OAUTH_CONFIG;
    static final BooleanPropertyDef EXPIRE_IN_FLIGHT_REQUESTS;
    static final PropertyDef<String> KEYS;
    static final BooleanPropertyDef AUTO_DISCOVER_REALMS;
    static final PropertyDef<String> CLAIM_NAMESPACE;
    static final PropertyDef<String> CLAIM_NAME_CHALLENGE_TIMEOUT;

    static
    {
        final ConfigurationDef config = new ConfigurationDef("nukleus.oauth");
        KEYS = config.property("keys", "keys.jwk");
        EXPIRE_IN_FLIGHT_REQUESTS = config.property("expire.in.flight.requests", true);
        AUTO_DISCOVER_REALMS = config.property("auto.discover.realms", false);
        CLAIM_NAMESPACE = config.property("claim.namespace", "https://reaktivity.org");
        CLAIM_NAME_CHALLENGE_TIMEOUT = config.property("claim.name.challenge.timeout",
                "challenge_timeout");
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

    public String getClaimNamespace()
    {
        return CLAIM_NAMESPACE.get(this);
    }

    public String getClaimNameChallengeTimeout()
    {
        return CLAIM_NAME_CHALLENGE_TIMEOUT.get(this);
    }

    public String getCanonicalClaimNamespace()
    {
        final String namespace = getClaimNamespace();
        return namespace.endsWith("/") ? namespace : String.format("%s/", namespace);
    }
}
