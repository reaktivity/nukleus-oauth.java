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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.reaktivity.nukleus.internal.CopyOnWriteHashMap;

public class OAuthRealms
{
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    private static final String SCOPE_CLAIM = "scope";
    private static final String ISSUER_CLAIM = "iss";
    private static final String AUDIENCE_CLAIM = "aud";
    private static final Long NO_AUTHORIZATION = 0L;

    // To optimize authorization checks we use a single distinct bit per realm and per scope
    private static final int MAX_REALMS = Short.SIZE;

    private static final long REALM_MASK = 0xFFFF_000000000000L;

    private final Map<String, OAuthRealm> realmsIdsByName = new CopyOnWriteHashMap<>();

    private int nextRealmBit = 0;

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
        this.keysByKid = keysByKid;
    }

    public long resolve(
        String realmName,
        String[] scopeNames,
        String issuerName,
        String audienceName)
    {
        long authorization = NO_AUTHORIZATION;
        if(nextRealmBit < MAX_REALMS)
        {
            final OAuthRealm realm = realmsIdsByName.computeIfAbsent(realmName, OAuthRealm::new);
            authorization = realm.resolve(scopeNames, issuerName, audienceName);
        }
        return authorization;
    }

    public long resolve(
        String realmName)
    {
        return resolve(realmName, EMPTY_STRING_ARRAY, "", "");
    }

    public long lookup(
        JsonWebSignature verified)
    {
        final OAuthRealm realm = realmsIdsByName.get(verified.getKeyIdHeaderValue());
        long authorization = NO_AUTHORIZATION;
        if (realm != null)
        {
            try
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                final Object issuerClaim = claims.getClaimValue(ISSUER_CLAIM);
                final Object audienceClaim = claims.getClaimValue(AUDIENCE_CLAIM);
                final String issuerName = issuerClaim != null ? issuerClaim.toString() : "";
                final String audienceName = audienceClaim != null ? audienceClaim.toString() : "";
                final Object scopeClaim = claims.getClaimValue(SCOPE_CLAIM);
                final String[] scopeNames = scopeClaim != null ?
                        scopeClaim.toString().split("\\s+")
                        : EMPTY_STRING_ARRAY;
                authorization = realm.lookup(scopeNames, issuerName, audienceName);
            }
            catch (JoseException | InvalidJwtException e)
            {
                // TODO: diagnostics?
            }
        }
        return authorization;
    }

    public boolean unresolve(
        long authorization)
    {
        final long realmId = authorization & REALM_MASK;
        return Long.bitCount(realmId) <= 1 && tryRemoveRealmInfoById(realmId);
    }

    public JsonWebKey supplyKey(
        String kid)
    {
        return keysByKid.get(kid);
    }

    private boolean tryRemoveRealmInfoById(
        long realmId)
    {
        boolean removed = false;
        for (OAuthRealm realm: realmsIdsByName.values())
        {
            removed = realm.tryRemoveInfoById(realmId);
            if(removed)
            {
                break;
            }
        }
        return removed;
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

        private final List<OAuthRealmInfo> realmInfoVariations = new LinkedList<>();

        private final String realmName;

        private long nextScopeBit;

        private OAuthRealm(
            String realmName)
        {
            assert nextRealmBit < MAX_REALMS;
            this.realmName = realmName;
        }

        private long resolve(
            String[] scopeNames,
            String issuerName,
            String audienceName)
        {
            long authorization = NO_AUTHORIZATION;
            if (nextScopeBit + scopeNames.length < MAX_SCOPES)
            {
                final OAuthRealmInfo realmInfo = computeInfoIfAbsent(issuerName, audienceName);
                authorization = realmInfo.realmId;
                for (int i = 0; i < scopeNames.length; i++)
                {
                    authorization |= realmInfo.computeScopeBitsIfAbsent(scopeNames[i], this::assignScopeBit);
                }
            }
            return authorization;
        }

        private long lookup(
            String[] scopeNames,
            String issuerName,
            String audienceName)
        {
            final OAuthRealmInfo info = getInfoByFilter(issuerName, audienceName);
            long authorization = NO_AUTHORIZATION;
            if(info != null)
            {
                authorization = info.realmId;
                for (int i = 0; i < scopeNames.length; i++)
                {
                    authorization |= info.getOrDefault(scopeNames[i], 0L);
                }
            }
            return authorization;
        }

        private OAuthRealmInfo computeInfoIfAbsent(
            String issuerName,
            String audienceName)
        {
            assert nextRealmBit < MAX_REALMS;
            OAuthRealmInfo info = getInfoByFilter(issuerName, audienceName);
            if(info == null)
            {
                info = new OAuthRealmInfo(1L << nextRealmBit++ << MAX_SCOPES, issuerName, audienceName);
                realmInfoVariations.add(info);
            }
            return info;
        }

        private OAuthRealmInfo getInfoByFilter(
            String issuerName,
            String audienceName)
        {
            OAuthRealmInfo result = null;
            for(int i = 0; i < realmInfoVariations.size(); i++)
            {
                final OAuthRealmInfo realmInfo = realmInfoVariations.get(i);
                if(realmInfo.containsClaims(issuerName, audienceName))
                {
                    result = realmInfo;
                    break;
                }
            }
            return result;
        }

        private boolean tryRemoveInfoById(
            long realmId)
        {
            return realmInfoVariations.removeIf(r -> r.realmId == realmId);
        }

        private long assignScopeBit(
            String scopeName)
        {
            assert nextScopeBit < MAX_SCOPES;
            return 1L << nextScopeBit++;
        }

        @Override
        public String toString()
        {
            return String.format("Realm name: \"%s\",\tRealm info: %s\n",
                    realmName, realmInfoVariations);
        }
    }

    private final class OAuthRealmInfo
    {

        private final long realmId;
        private final Claims requiredClaims;
        private final Map<String, Long> scopeBitsByName = new CopyOnWriteHashMap<>();

        private OAuthRealmInfo(
            long realmId,
            String issuerName,
            String audienceName)
        {
            this.realmId = realmId;
            this.requiredClaims = new Claims(issuerName, audienceName);
        }

        private long getOrDefault(
            String scopeName,
            long defaultValue)
        {
            return scopeBitsByName.getOrDefault(scopeName, defaultValue);
        }

        private long computeScopeBitsIfAbsent(
            String scopeName,
            Function<String, Long> mappingFunction)
        {
            return scopeBitsByName.computeIfAbsent(scopeName, mappingFunction);
        }

        private boolean containsClaims(
            String issuerName,
            String audienceName)
        {
            return requiredClaims.containsClaims(issuerName, audienceName);
        }

        @Override
        public String toString()
        {
            return String.format("Info: realm id=%d, claims=%s, scope bits=%s",
                    realmId, requiredClaims, this.scopeBitsByName);
        }

        private final class Claims
        {
            final String issuerName;
            final String audienceName;

            private Claims(
                String issuerName,
                String audienceName)
            {
                this.issuerName = issuerName;
                this.audienceName = audienceName;
            }

            private boolean containsClaims(
                String issuerName,
                String audienceName)
            {
                return this.issuerName.equals(issuerName) && this.audienceName.equals(audienceName);
            }

            @Override
            public String toString()
            {
                return String.format("[issuer=\"%s\", audience=\"%s\"]", issuerName, audienceName);
            }
        }
    }
}
