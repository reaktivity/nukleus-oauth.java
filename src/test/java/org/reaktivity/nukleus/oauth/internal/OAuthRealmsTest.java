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

import org.junit.Test;

public class OAuthRealmsTest
{
    private static final String[] EMPTY_STRING_ARRAY = new String[0];

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
        realms.add("realm one");
        realms.add("realm two");
//        final JsonWebSignature signature1 = new JsonWebSignature();
//        signature1.setKeyIdHeaderValue("realm one");
//        signature1.setAlgorithmHeaderValue("RS256");
//        final JsonWebKey key1 = realms.supplyKey("realm one");
//        signature1.setKey(key1.getKey());
//        signature1.sign();
//        signature1.setPayload("");
//        System.out.println(String.format("sig1: %s", signature1));
//        final JsonWebSignature signature2 = new JsonWebSignature();
//        signature2.setKeyIdHeaderValue("realm two");
//        signature2.setAlgorithmHeaderValue("RS256");
//        final JsonWebKey key2 = realms.supplyKey("realm two");
//        signature2.setKey(key2.getKey());
//        signature2.sign();
//        signature2.setPayload("");
//        assertEquals(0x0001_000000000000L, realms.lookup(signature1));
//        assertEquals(0x0002_000000000000L, realms.lookup(signature2));
        assertEquals(0x0001_000000000000L, realms.lookup("realm one", EMPTY_STRING_ARRAY));
        assertEquals(0x0002_000000000000L, realms.lookup("realm two", EMPTY_STRING_ARRAY));
    }

    @Test
    public void shouldNotResolveUnknownRealm() throws Exception
    {
        OAuthRealms realms = new OAuthRealms();
        assertEquals(0L, realms.lookup("realm one", EMPTY_STRING_ARRAY));
//        JsonWebSignature signature = new JsonWebSignature();
//        signature.setKeyIdHeaderValue("realm one");
//        signature.setPayload("");
//        assertEquals(0L, realms.lookup(signature));
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
//            JsonWebSignature signature = new JsonWebSignature();
//            signature.setKeyIdHeaderValue(String.format("realm%d", i));
//            signature.sign();
//            assertTrue(realms.unresolve(realms.lookup(signature)));
            assertTrue(realms.unresolve(realms.lookup("realm"+i, EMPTY_STRING_ARRAY)));
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
