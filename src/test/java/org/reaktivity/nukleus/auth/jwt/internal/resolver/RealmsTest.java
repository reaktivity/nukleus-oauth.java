/**
 * Copyright 2016-2017 The Reaktivity Project
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
package org.reaktivity.nukleus.auth.jwt.internal.resolver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class RealmsTest
{

    @Test
    public void shouldAddUpToMaximumRealms() throws Exception
    {
        Realms realms = new Realms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotAddTooManyRealms() throws Exception
    {
        Realms realms = new Realms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
        realms.add("one realm too many");
    }

    @Test
    public void shouldResolveKnownRealms() throws Exception
    {
        Realms realms = new Realms();
        realms.add("realm one");
        realms.add("realm two");
        assertEquals(0x0001_000000000000L, realms.resolve("realm one"));
        assertEquals(0x0002_000000000000L, realms.resolve("realm two"));
    }

    @Test
    public void shouldNotResolveUnknownRealm() throws Exception
    {
        Realms realms = new Realms();
        assertEquals(0L, realms.resolve("realm one"));
    }

    @Test
    public void shouldUnresolveKnownRealms() throws Exception
    {
        Realms realms = new Realms();
        for (int i=0; i < Short.SIZE; i++)
        {
            realms.add("realm" + i);
        }
        for (int i=0; i < Short.SIZE; i++)
        {
            assertTrue(realms.unresolve(realms.resolve("realm" + i)));

        }
    }

    @Test
    public void shouldNotUnresolveUnknownRealm() throws Exception
    {
        Realms realms = new Realms();
        realms.add("realm one");
        assertFalse(realms.unresolve(0x0002_000000000000L));
    }

    @Test
    public void shouldNotUnresolveInvalidRealm() throws Exception
    {
        Realms realms = new Realms();
        realms.add("realm one");
        realms.add("realm two");
        assertFalse(realms.unresolve(0x0003_000000000000L));
    }

}
