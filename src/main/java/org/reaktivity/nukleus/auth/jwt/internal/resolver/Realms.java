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
    private static final int MAX_SCOPES = Short.SIZE;
    private static final int MAX_ROLES = Long.SIZE - MAX_SCOPES;
    private static final long SCOPE_MASK = 0xFFFF_FFFF_FFFF_FFFFL << MAX_ROLES;

    private final Map<Object, Long> scopesByRealm = new HashMap<>();
    private final String[] realmsByScope = new String[MAX_SCOPES];
    private short nextScopeIndex = 0;

    public void add(String realm)
    {
        if (nextScopeIndex == Short.SIZE)
        {
            throw new IllegalStateException("Too many realms");
        }
        realmsByScope[nextScopeIndex] = realm;
        scopesByRealm.put(realm, 1L << (nextScopeIndex + MAX_ROLES));
        nextScopeIndex++;
    }

    public long resolve(
        String realm)
    {
        return scopesByRealm.getOrDefault(realm, NO_AUTHORIZATION);
    }

    public boolean unresolve(long authorization)
    {
        if (Long.bitCount(authorization & SCOPE_MASK) > 1)
        {
            return false;
        }
        int index = Short.SIZE - Long.numberOfLeadingZeros(authorization) - 1;
        String realm = realmsByScope[index];
        if (realm != null)
        {
            realmsByScope[index] = null;
            scopesByRealm.remove(realm);
        }
        return realm != null;
    }
}
