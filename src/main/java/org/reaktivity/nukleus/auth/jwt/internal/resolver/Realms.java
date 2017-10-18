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

import java.util.HashMap;
import java.util.Map;

public class Realms
{
    private static final Long NO_AUTHORIZATION = 0L;

    // To optimize authorization checks we use a single distinct bit per realm
    private static final int MAX_REALMS = Short.SIZE;

    private static final long SCOPE_MASK = 0xFFFF_000000000000L;

    private final Map<String, Long> realmsIdsByName = new HashMap<>(MAX_REALMS);

    private int nextRealmBitShift = 48;

    public void add(String realm)
    {
        if (realmsIdsByName.size() == MAX_REALMS)
        {
            throw new IllegalStateException("Too many realms");
        }
        realmsIdsByName.put(realm, 1L << nextRealmBitShift++);
    }

    public long resolve(
        String realm)
    {
        return realmsIdsByName.getOrDefault(realm, NO_AUTHORIZATION);
    }

    public boolean unresolve(long authorization)
    {
        long scope = authorization & SCOPE_MASK;
        boolean result;
        if (Long.bitCount(scope) > 1)
        {
            result = false;
        }
        else
        {
            result = realmsIdsByName.entrySet().removeIf(e -> (e.getValue() == scope));
        }
        return result;
    }
}
