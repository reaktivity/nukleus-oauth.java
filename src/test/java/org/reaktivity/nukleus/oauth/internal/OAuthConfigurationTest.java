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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.AUTO_DISCOVER_REALMS;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.AUTO_DISCOVER_REALMS_NAME;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.CHALLENGE_DELTA_CLAIM_NAME;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAMESPACE;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAMESPACE_NAME;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAME_NAME;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.KEYS;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.KEYS_NAME;

public class OAuthConfigurationTest
{

    @Test
    public void shouldMatchKeysConfigName()
    {
        assertEquals(KEYS_NAME, KEYS.name());
    }

    @Test
    public void shouldMatchAutoDiscoverRealmsConfigName()
    {
        assertEquals(AUTO_DISCOVER_REALMS_NAME, AUTO_DISCOVER_REALMS.name());
    }

    @Test
    public void shouldMatchChallengeResponseDeltaNamespaceConfigName()
    {
        assertEquals(CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAMESPACE_NAME, CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAMESPACE.name());
    }

    @Test
    public void shouldMatchChallengeResponseDeltaNameConfigName()
    {
        assertEquals(CHALLENGE_RESPONSE_TIMEOUT_CLAIM_NAME_NAME, CHALLENGE_DELTA_CLAIM_NAME.name());
    }

}
