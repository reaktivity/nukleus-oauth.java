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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.unmodifiableMap;
import static org.agrona.LangUtil.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.reaktivity.nukleus.internal.CopyOnWriteHashMap;

public class OAuthRealms
{
    public static final String[] EMPTY_STRING_ARRAY = new String[0];

    private static final String SCOPES_CLAIM = "scopes";
    private static final Long NO_AUTHORIZATION = 0L;

    // To optimize authorization checks we use a single distinct bit per realm
    private static final int MAX_REALMS = Short.SIZE;

    private static final long SCOPE_MASK = 0xFFFF_000000000000L;

    private final Map<String, OAuthRealm> realmsIdsByName = new CopyOnWriteHashMap<>();

    private int nextRealmBitShift = 48;

    private final Map<String, JsonWebKey> keysByKid;

    public OAuthRealms()
    {
        this(Collections.emptyMap());
    }

    public OAuthRealms(
        Path keyFile)
    {
        this(parseKeyMap(keyFile));
    }

    public OAuthRealms(
        String keysAsJwkSet)
    {
        this(toKeyMap(keysAsJwkSet));
    }

    private OAuthRealms(
        Map<String, JsonWebKey> keysByKid)
    {
        // TODO: move kid authorization from startup to on first RESOLVE. Possibly would need to change the stream scripts
        //       to change expectedAuthorization from 0x0001_000000000000L to 0 as realms wouldnt be added UNLESS RESOLVE
        //       is called.  If realms arent assigned on startup by the config file, then no realm should exist until
        //       RESOLVE is called.
        //       The test DOES pass if changing expectedAuthorization from 0x0001_000000000000L -> 0x0000_000000000000L
//        keysByKid.forEach((k, v) -> add(v.getKeyId()));
        this.keysByKid = keysByKid;
//        System.out.println(this.keysByKid);
    }

    public void add(
        String realm)
    {
        if (realmsIdsByName.size() == MAX_REALMS)
        {
            throw new IllegalStateException("Too many realms");
        }
        realmsIdsByName.put(realm, new OAuthRealm(1L << nextRealmBitShift++));
    }

    public long resolve(
        String realm,
        String[] scopes)
    {
        // If realm doesn't exist, add it to realms
        if(!realmsIdsByName.containsKey(realm))
        {
            add(realm);
        }
        final OAuthRealm realmObject = realmsIdsByName.get(realm);
        if(realmObject == null)
        {
            return NO_AUTHORIZATION;
        }
        long realmBit = realmObject.realmBit;
        // if not already there, add the scope to the map, assign each scope a bit
        // which determines which low bit will be flipped if that scope is present
        for (int i = 0; i < scopes.length; i++)
        {
            final String scope = scopes[i];
            // check if scope's bit has been set and if scope can be added
            if(!realmObject.scopeBitAssigned(scope) && !realmObject.supplyScopeBit(scope))
            {
                throw new IllegalStateException("Too many scopes");
            }
            final long bit = realmObject.getScopeBit(scope);
            realmBit |= bit;
        }
        return realmBit;
    }

    public long lookup(
        JsonWebSignature verified)
    {
        final String realmName = verified.getKeyIdHeaderValue();
        try
        {
            final JwtClaims claims = JwtClaims.parse(verified.getPayload());
            final Object scopeClaim = claims.getClaimValue(SCOPES_CLAIM);
            final String[] roleNames = scopeClaim != null ?
                    splitScopes(scopeClaim.toString())
                    : EMPTY_STRING_ARRAY;
            final OAuthRealm realm = realmsIdsByName.get(realmName);
            if(realm == null)
            {
                return NO_AUTHORIZATION;
            }
            long authorizationBits = realm.realmBit;
            for (int i = 0; i < roleNames.length; i++)
            {
                final String scope = roleNames[i];
                final long bit = realm.getScopeBit(scope);
                authorizationBits |= bit;
            }
            return authorizationBits;
        }
        catch (JoseException | InvalidJwtException e)
        {
            // TODO: diagnostics?
            return NO_AUTHORIZATION;
        }
    }

    public boolean unresolve(
        long authorization)
    {
        long scope = authorization & SCOPE_MASK;
        boolean result;
        if (Long.bitCount(scope) > 1)
        {
            result = false;
        }
        else
        {
            result = realmsIdsByName.entrySet().removeIf(e -> (e.getValue().realmBit == scope));
        }
        return result;
    }

    public JsonWebKey supplyKey(
        String kid)
    {
        return keysByKid.get(kid);
    }

    private String[] splitScopes(
            String scopes)
    {
        return scopes.split("\\s+");
    }

    private static Map<String, JsonWebKey> parseKeyMap(
        Path keyFile)
    {
        Map<String, JsonWebKey> keysByKid = Collections.emptyMap();

        if (Files.exists(keyFile))
        {
            try
            {
                byte[] rawKeys = Files.readAllBytes(keyFile);
                String keysAsJwkSet = new String(rawKeys, UTF_8);
                keysByKid = toKeyMap(keysAsJwkSet);
            }
            catch (IOException ex)
            {
                rethrowUnchecked(ex);
            }
        }

        return keysByKid;
    }

    private static Map<String, JsonWebKey> toKeyMap(
        String keysAsJwkSet)
    {
        Map<String, JsonWebKey> keysByKid = Collections.emptyMap();

        try
        {
            JsonWebKeySet keys = new JsonWebKeySet(keysAsJwkSet);
            keysByKid = new LinkedHashMap<>();
            for (JsonWebKey key : keys.getJsonWebKeys())
            {
               String kid = key.getKeyId();
               if (kid == null)
               {
                   throw new IllegalArgumentException("Key without kid");
               }

               if (key.getAlgorithm() == null)
               {
                   throw new IllegalArgumentException("Key without alg");
               }

               final JsonWebKey existingKey = keysByKid.putIfAbsent(kid, key);
               if (existingKey != null)
               {
                   throw new IllegalArgumentException("Key with duplicate kid");
               }
            }
            keysByKid = unmodifiableMap(keysByKid);
        }
        catch (JoseException ex)
        {
            rethrowUnchecked(ex);
        }

        return keysByKid;
    }

    private final class OAuthRealm
    {
        private static final int MAX_SCOPES = 48;

        private final Map<String, Long> scopeBitsByName = new CopyOnWriteHashMap<>();

        private long realmBit;
        private long nextScopeBitShift;

        private OAuthRealm(
            long realmBit)
        {
            this.realmBit = realmBit;
        }

        private boolean scopeBitAssigned(
            String scope)
        {
            return scopeBitsByName.containsKey(scope);
        }

        private boolean supplyScopeBit(
            String scope)
        {
            // return true if not reach scope cap and scope bit >= 0
            return scopeBitsByName.size() < MAX_SCOPES &&
                   scopeBitsByName.computeIfAbsent(scope, s -> 1L << nextScopeBitShift++) >= 0;
        }

        private long getScopeBit(
            String scope)
        {
            return scopeBitsByName.getOrDefault(scope, 0L);
        }
    }
}
