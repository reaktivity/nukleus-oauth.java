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

import java.security.KeyPair;

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
            realms.resolve("realm" + i);
        }
    }

    @Test
    public void shouldNotAddTooManyRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.resolve("realm" + i);
        }
        assertEquals(0L, realms.resolve("one realm too many"));
    }

    @Test
    public void shouldResolveKnownRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one");
        realms.resolve("realm two");

        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", "test issuer");
        String payload = claims.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm two", "ES256", payload, RFC7515_ES256);

        assertEquals(0x0001_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0002_000000000000L, realms.lookup(signatureTwo));
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
        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", "test issuer");
        String payload = claims.toJson();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.resolve("realm" + i);
        }
        for (int i=0; i < Short.SIZE; i++)
        {
            final JsonWebSignature signature = newSignedSignature("realm"+i, "RS256", payload, RFC7515_RS256);
            assertTrue(realms.unresolve(realms.lookup(signature)));
        }
    }

    @Test
    public void shouldNotUnresolveUnknownRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one");
        assertFalse(realms.unresolve(0x0002_000000000000L));
    }

    @Test
    public void shouldNotUnresolveInvalidRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one");
        realms.resolve("realm two");
        assertFalse(realms.unresolve(0x0003_000000000000L));
    }

    private JsonWebSignature newSignedSignature(
            String kid, String alg, String payload, KeyPair pair) throws Exception
    {
        final JsonWebSignature signature = new JsonWebSignature();
        signature.setPayload(payload);
        signature.setKey(pair.getPrivate());
        signature.setKeyIdHeaderValue(kid);
        signature.setAlgorithmHeaderValue(alg);
        signature.sign();
        signature.setKey(pair.getPublic());
        return signature;
    }
}
