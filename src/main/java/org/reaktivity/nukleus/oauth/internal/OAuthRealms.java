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
import java.util.*;

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

//    private final Map<String, OAuthRealm> realmsIdsByName = new CopyOnWriteHashMap<>();
    private final Map<String, List<OAuthRealm>> realmsIdsByName = new CopyOnWriteHashMap<>();

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

//    public long resolve(
//        String realmName,
//        String[] scopeNames)
//    {
//        long authorization = NO_AUTHORIZATION;
//        if(nextRealmBit < MAX_REALMS)
//        {
//            final OAuthRealm realm = realmsIdsByName.computeIfAbsent(realmName, OAuthRealm::new);
//            authorization = realm.resolve(scopeNames);
//        }
//        return authorization;
//    }

    public long resolve(
        String realmName,
        String[] scopeNames,
        String issuerName,
        String audienceName)
    {
        long authorization = NO_AUTHORIZATION;
        if(nextRealmBit < MAX_REALMS)
        {
//            final OAuthRealm realm = realmsIdsByName.computeIfAbsent(realmName, r -> new OAuthRealm(realmName, issuerName, audienceName));
            // TODO: if kid doesn't exist, make new list for it. else, get the list of that realm
            final List<OAuthRealm> realms = realmsIdsByName.computeIfAbsent(realmName, r -> new LinkedList<>());
            final OAuthRealm realm = getNewRealmIfAbsent(realmName, realms, issuerName, audienceName);
            System.out.println("realm: " + realm);
            authorization = realm.resolve(scopeNames);
            realmsIdsByName.get(realmName).add(realm);
        }
        return authorization;
    }

    public long resolve(
        String realmName)
    {
        return resolve(realmName, EMPTY_STRING_ARRAY, "", "");
    }

    // TODO: spec scripts mostly have "iss": "test issuer" claims. either add claims to the common script they use, or get rid of
    //       to specifically test the use of iss and aud claims
    public long lookup(
        JsonWebSignature verified)
    {

        final List<OAuthRealm> realms = realmsIdsByName.get(verified.getKeyIdHeaderValue());

//        final OAuthRealm realm = realmsIdsByName.get(verified.getKeyIdHeaderValue());
        long authorization = NO_AUTHORIZATION;
        if(!realms.isEmpty())
        {
            try
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                final Object issuerClaim = claims.getClaimValue(ISSUER_CLAIM);
                final Object audienceClaim = claims.getClaimValue(AUDIENCE_CLAIM);
                final String issuerName = issuerClaim != null ? issuerClaim.toString() : "";
                final String audienceName = audienceClaim != null ? audienceClaim.toString() : "";
                final OAuthRealm realm = getRealmByFilter(realms, issuerName, audienceName);
                System.out.println("iss : " + issuerName + "\taud: " + audienceName);
                System.out.println("lookup - realm: " + realm);

                final Object scopeClaim = claims.getClaimValue(SCOPE_CLAIM);
                final String[] scopeNames = scopeClaim != null ?
                        scopeClaim.toString().split("\\s+")
                        : EMPTY_STRING_ARRAY;
                if (realm != null)
                {
                    authorization = realm.lookup(scopeNames);
                }
            }
            catch (JoseException | InvalidJwtException e)
            {
                // TODO: diagnostics?
            }
        }
        return authorization;
    }

//    public long lookup(
//        JsonWebSignature verified)
//    {
//        final OAuthRealm realm = realmsIdsByName.get(verified.getKeyIdHeaderValue());
//        long authorization = NO_AUTHORIZATION;
//        if(realm != null)
//        {
//            try
//            {
//                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
//                final Object scopeClaim = claims.getClaimValue(SCOPE_CLAIM);
//                final String[] scopeNames = scopeClaim != null ?
//                        scopeClaim.toString().split("\\s+")
//                        : EMPTY_STRING_ARRAY;
//                authorization = realm.lookup(scopeNames);
//            }
//            catch (JoseException | InvalidJwtException e)
//            {
//                // TODO: diagnostics?
//            }
//        }
//        return authorization;
//    }

    public boolean unresolve(
        long authorization)
    {
        final long realmId = authorization & REALM_MASK;
//        return Long.bitCount(realmId) <= 1 && realmsIdsByName.entrySet().removeIf(e -> e.getValue().realmId == realmId);
        boolean removed = false;
        if(Long.bitCount(realmId) <= 1)
        {
            for (List<OAuthRealm> realms:
                 realmsIdsByName.values())
            {
                removed = realms.removeIf(r -> r.realmId == realmId);
            }
        }
        return removed;
    }

    public JsonWebKey supplyKey(
        String kid)
    {
        return keysByKid.get(kid);
    }

    private OAuthRealm getNewRealmIfAbsent(
        String realmName,
        List<OAuthRealm> realms,
        String issuerName,
        String audienceName)
    {
        for(int i = 0; i < realms.size(); i++)
        {
            final OAuthRealm realm = realms.get(i);
            if(realm.issuerName.equals(issuerName) && realm.audienceName.equals(audienceName))
            {
                return realm;
            }
        }
        return new OAuthRealm(realmName, issuerName, audienceName);
    }

    private OAuthRealm getRealmByFilter(
        List<OAuthRealm> realms,
        String issuerName,
        String audienceName)
    {
        for(int i = 0; i < realms.size(); i++)
        {
            final OAuthRealm realm = realms.get(i);
            if(realm.issuerName.equals(issuerName) && realm.audienceName.equals(audienceName))
            {
                return realm;
            }
        }
        return null;
    }

    private void getRealmById(
        List<OAuthRealm> realms,
        long realmId)
    {
        realms.removeIf(r -> r.realmId == realmId);
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

        private final long realmId;
        private final String realmName;
        private final String issuerName;
        private final String audienceName;

        private long nextScopeBit;

//        private OAuthRealm(
//            String realmName)
//        {
//            assert nextRealmBit < MAX_REALMS;
//            this.realmName = realmName;
//            this.realmId = 1L << nextRealmBit++ << MAX_SCOPES;
//        }

        private OAuthRealm(
            String realmName,
            String issuerName,
            String audienceName)
        {
            assert nextRealmBit < MAX_REALMS;
            this.realmName = realmName;
            this.realmId = 1L << nextRealmBit++ << MAX_SCOPES;
            this.issuerName = issuerName;
            this.audienceName = audienceName;
        }

        private long resolve(
            String[] scopeNames)
        {
            long authorization = NO_AUTHORIZATION;
            if(nextScopeBit + scopeNames.length < MAX_SCOPES)
            {
                authorization = realmId;
                for (int i = 0; i < scopeNames.length; i++)
                {
                    authorization |= scopeBitsByName.computeIfAbsent(scopeNames[i], this::assignScopeBit);
                }
            }
            return authorization;
        }

        private long lookup(
            String[] scopeNames)
        {
            long authorization = realmId;
            for (int i = 0; i < scopeNames.length; i++)
            {
                authorization |= scopeBitsByName.getOrDefault(scopeNames[i], 0L);
            }
            return authorization;
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
            return String.format("Realm name: %s\n\tRealm id: %s\n\tScope bits: %s\n\tIssuer: %s\n\tAudience: %s",
                    realmName, realmId, scopeBitsByName, issuerName, audienceName);
        }
    }
}
