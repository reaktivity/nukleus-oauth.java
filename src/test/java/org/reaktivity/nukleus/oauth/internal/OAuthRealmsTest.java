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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.reaktivity.specification.nukleus.oauth.internal.OAuthJwtKeys.RFC7515_ES256;
import static org.reaktivity.specification.nukleus.oauth.internal.OAuthJwtKeys.RFC7515_RS256;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Test;

public class OAuthRealmsTest
{
    @Test
    public void shouldAddUpToMaximumRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotAddTooManyRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
        realms.add("one realm too many");
    }

    @Test
    public void shouldResolveKnownRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.add("RS256");
        realms.add("ES256");

        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", "test issuer");
        String payload = claims.toJson();

        final JsonWebSignature signature1 = new JsonWebSignature();
        signature1.setPayload(payload);
        signature1.setKey(RFC7515_RS256.getPrivate());
        signature1.setKeyIdHeaderValue("RS256");
        signature1.setAlgorithmHeaderValue("RS256");
        signature1.sign();
        signature1.setKey(RFC7515_RS256.getPublic());

        final JsonWebSignature signature2 = new JsonWebSignature();
        signature2.setPayload(payload);
        signature2.setKey(RFC7515_ES256.getPrivate());
        signature2.setKeyIdHeaderValue("ES256");
        signature2.setAlgorithmHeaderValue("ES256");
        signature2.sign();
        signature2.setKey(RFC7515_ES256.getPublic());

        assertEquals(0x0001_000000000000L, realms.lookup(signature1));
        assertEquals(0x0002_000000000000L, realms.lookup(signature2));
    }

    @Test
    public void shouldNotResolveUnknownRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        final JsonWebSignature signature = new JsonWebSignature();
        assertEquals(0L, realms.lookup(signature));
    }

    @Test
    public void shouldUnresolveAllKnownRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
        for (int i=0; i < Short.SIZE; i++)
        {
            final JsonWebSignature signature = new JsonWebSignature();
            signature.setPayload("{}");
            signature.setKey(RFC7515_RS256.getPrivate());
            signature.setKeyIdHeaderValue("realm" + i);
            signature.setAlgorithmHeaderValue("RS256");
            signature.sign();
            signature.setKey(RFC7515_RS256.getPublic());

            assertTrue(realms.unresolve(realms.lookup(signature)));
        }
    }

    @Test
    public void shouldNotUnresolveUnknownRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.add("realm one");
        assertFalse(realms.unresolve(0x0002_000000000000L));
    }

    @Test
    public void shouldNotUnresolveInvalidRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.add("realm one");
        realms.add("realm two");
        assertFalse(realms.unresolve(0x0003_000000000000L));
    }
}
