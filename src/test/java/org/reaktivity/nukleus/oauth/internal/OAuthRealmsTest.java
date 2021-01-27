/**
 * Copyright 2016-2021 The Reaktivity Project
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
import java.util.Arrays;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Test;

public class OAuthRealmsTest
{
    @Test
    public void shouldAddUpToMaximumRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i = 0; i < Short.SIZE; i++)
        {
            realms.resolve("realm" + i);
        }
    }

    @Test
    public void shouldNotAddTooManyRealms() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        for (int i = 0; i < Short.SIZE; i++)
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
        String payload = claims.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm two", "ES256", payload, RFC7515_ES256);

        assertEquals(0x0001_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0002_000000000000L, realms.lookup(signatureTwo));
    }

    @Test
    public void shouldResolveKnownRealmWithUnspecifiedIssuerAndAudience() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one");
        realms.resolve("realm two");

        JwtClaims claims1 = new JwtClaims();
        claims1.setClaim("iss", "test issuer1");
        claims1.setClaim("aud", "testAudience1");
        String payload1 = claims1.toJson();

        JwtClaims claims2 = new JwtClaims();
        claims2.setClaim("iss", "test issuer2");
        claims2.setClaim("aud", "testAudience2");
        String payload2 = claims1.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload1, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm two", "ES256", payload2, RFC7515_ES256);

        assertEquals(0x0001_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0002_000000000000L, realms.lookup(signatureTwo));
    }

    @Test
    public void shouldFailResolveKnownRealmWithTokenWithUnspecifiedIssuerAndAudience() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer1", "testAudience1", null);
        realms.resolve("realm two", "test issuer2", "testAudience2", null);

        JwtClaims claims = new JwtClaims();
        String emptyPayload = claims.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", emptyPayload, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm two", "ES256", emptyPayload, RFC7515_ES256);

        assertEquals(0x0000_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0000_000000000000L, realms.lookup(signatureTwo));
    }

    @Test
    public void shouldResolveKnownRealmWithDifferentKidAndDifferentClaims() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer1", "testAudience1", null);
        realms.resolve("realm two", "test issuer2", "testAudience2", null);

        JwtClaims claims1 = new JwtClaims();
        claims1.setClaim("iss", "test issuer1");
        claims1.setClaim("aud", "testAudience1");
        String payload1 = claims1.toJson();

        JwtClaims claims2 = new JwtClaims();
        claims2.setClaim("iss", "test issuer2");
        claims2.setClaim("aud", "testAudience2");
        String payload2 = claims2.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload1, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm two", "ES256", payload2, RFC7515_ES256);

        assertEquals(0x0001_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0002_000000000000L, realms.lookup(signatureTwo));
    }

    @Test
    public void shouldResolveKnownRealmWithIssuerAndMultipleAudiences() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer1", "testAudience1", null);

        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", "test issuer1");
        claims.setClaim("aud", Arrays.asList("testAudience1", "testAudience2"));

        final JsonWebSignature signature = newSignedSignature("realm one", "RS256", claims.toJson(), RFC7515_RS256);

        assertEquals(0x0001_000000000000L, realms.lookup(signature));
    }

    @Test
    public void shouldResolveKnownRealmWithSameKidButDifferentClaims() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer1", "testAudience1", null);
        realms.resolve("realm one", "test issuer2", "testAudience2", null);

        JwtClaims claims1 = new JwtClaims();
        claims1.setClaim("iss", "test issuer1");
        claims1.setClaim("aud", "testAudience1");
        String payload1 = claims1.toJson();

        JwtClaims claims2 = new JwtClaims();
        claims2.setClaim("iss", "test issuer2");
        claims2.setClaim("aud", "testAudience2");
        String payload2 = claims2.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload1, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm one", "RS256", payload2, RFC7515_RS256);

        assertEquals(0x0001_000000000000L, realms.lookup(signatureOne));
        assertEquals(0x0002_000000000000L, realms.lookup(signatureTwo));
    }

    @Test
    public void shouldUnresolveKnownRealmWithSameKidButDifferentClaims() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer1", "testAudience1", null);
        realms.resolve("realm one", "test issuer2", "testAudience2", null);

        JwtClaims claims1 = new JwtClaims();
        claims1.setClaim("iss", "test issuer1");
        claims1.setClaim("aud", "testAudience1");
        String payload1 = claims1.toJson();

        JwtClaims claims2 = new JwtClaims();
        claims2.setClaim("iss", "test issuer2");
        claims2.setClaim("aud", "testAudience2");
        String payload2 = claims2.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload1, RFC7515_RS256);
        final JsonWebSignature signatureTwo = newSignedSignature("realm one", "RS256", payload2, RFC7515_RS256);

        assertTrue(realms.unresolve(realms.lookup(signatureOne)));
        assertTrue(realms.unresolve(realms.lookup(signatureTwo)));
    }

    @Test
    public void shouldFailTooManyUnresolves() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        realms.resolve("realm one", "test issuer", "testAudience", null);

        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", "test issuer");
        claims.setClaim("aud", "testAudience");
        String payload = claims.toJson();

        final JsonWebSignature signatureOne = newSignedSignature("realm one", "RS256", payload, RFC7515_RS256);

        assertTrue(realms.unresolve(realms.lookup(signatureOne)));
        assertFalse(realms.unresolve(realms.lookup(signatureOne)));
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
        String payload = claims.toJson();
        for (int i = 0; i < Short.SIZE; i++)
        {
            realms.resolve("realm" + i);
        }
        for (int i = 0; i < Short.SIZE; i++)
        {
            final JsonWebSignature signature = newSignedSignature("realm" + i, "RS256", payload, RFC7515_RS256);
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
