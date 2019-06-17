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

//    private final Map<String, OAuthRealm> realmsIdsByName = new CopyOnWriteHashMap<>();
//    private final Map<String, List<OAuthRealm>> realmsIdsByName = new CopyOnWriteHashMap<>();
//    private final Map<String, Map<OAuthRealmNames, OAuthRealm>> realmsIdsByName = new CopyOnWriteHashMap<>();
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

    // TODO: what if instead of doing Map<String, List<OAuthRealm>>, we made a class that contains issuer and audience
    //       and do Map<String, Map<IssAudObj, OAuthRealm>> where we can put/pull out realms via issuer/audience filter
    //       Rather than iterating through the List, filter and get from obj. could use computeIfAbsent and get

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
            // TODO: if kid doesn't exist, make new list for it. else, get the list of that realm
//            final List<OAuthRealm> realms = realmsIdsByName.computeIfAbsent(realmName, r -> new LinkedList<>());
//            final Map<OAuthRealmNames, OAuthRealm> realms =
//              realmsIdsByName.computeIfAbsent(realmName, r -> new CopyOnWriteHashMap<>());
//            final OAuthRealm realm = getNewRealmIfAbsent(realmName, realms, issuerName, audienceName);
//            final OAuthRealmNames realmInfos = new OAuthRealmNames(realmName, issuerName, audienceName);
//            final OAuthRealm realm = realms.computeIfAbsent(realmInfos, OAuthRealm::new);
//            System.out.println("realm: " + realm);
//            System.out.println("realmsss: " + realms);

            authorization = realm.resolve(scopeNames, issuerName, audienceName);
//            realms.add(realm);
        }
        return authorization;
    }

    public long resolve(
        String realmName)
    {
        return resolve(realmName, EMPTY_STRING_ARRAY, "", "");
    }

    // TODO: spec scripts mostly have "iss": "test issuer" claims.
    //       either add claims to the common script they use, or get rid of
    //       to specifically test the use of iss and aud claims
    public long lookup(
        JsonWebSignature verified)
    {
        final OAuthRealm realm = realmsIdsByName.get(verified.getKeyIdHeaderValue());
//        final List<OAuthRealm> realms = realmsIdsByName.get(verified.getKeyIdHeaderValue());
//        final String realmName = verified.getKeyIdHeaderValue();
//        final Map<OAuthRealmNames, OAuthRealm> realms = realmsIdsByName.get(realmName);
        long authorization = NO_AUTHORIZATION;
        if (realm != null)
        {
//        if(realms != null && !realms.isEmpty())
//        {
            try
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                final Object issuerClaim = claims.getClaimValue(ISSUER_CLAIM);
                final Object audienceClaim = claims.getClaimValue(AUDIENCE_CLAIM);
                final String issuerName = issuerClaim != null ? issuerClaim.toString() : "";
                final String audienceName = audienceClaim != null ? audienceClaim.toString() : "";
//                final OAuthRealmNames realmInfos = new OAuthRealmNames(realmName, issuerName, audienceName);
//                System.out.println("realmInfos: " + realmInfos);
//                System.out.println("realms keys: " + realms.keySet());
//                System.out.println("adad: " + realms.containsKey(realmInfos));

//                final OAuthRealm realm = realms.get(realmInfos);
//                final OAuthRealm realm = getRealmByFilter(realms, issuerName, audienceName);
//                System.out.println("iss : " + issuerName + "\taud: " + audienceName);
//                System.out.println("lookup - realm: " + realm);
//                if (realm != null)
//                {
                final Object scopeClaim = claims.getClaimValue(SCOPE_CLAIM);
                final String[] scopeNames = scopeClaim != null ?
                        scopeClaim.toString().split("\\s+")
                        : EMPTY_STRING_ARRAY;
                authorization = realm.lookup(scopeNames, issuerName, audienceName);
//                }
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
        return Long.bitCount(realmId) <= 1 && tryRemoveRealmInfoById(realmId);
//        return Long.bitCount(realmId) <= 1
//        && realmsIdsByName.entrySet().removeIf(e -> e.getValue().realmId == realmId);
//        return Long.bitCount(realmId) <= 1
//        && realmsIdsByName.entrySet().removeIf(
//          e -> e.getValue().entrySet().removeIf(
//              r -> r.getValue().realmId == realmId));
//        boolean removed = false;
//        if(Long.bitCount(realmId) <= 1)
//        {
//        }
//        return removed;
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

    public JsonWebKey supplyKey(
        String kid)
    {
        return keysByKid.get(kid);
    }

//    private OAuthRealm getNewRealmIfAbsent(
//        String realmName,
//        List<OAuthRealm> realms,
//        String issuerName,
//        String audienceName)
//    {
//        final OAuthRealm realm = getRealmByFilter(realms, issuerName, audienceName);
//        return realm != null ? realm : new OAuthRealm(realmName, issuerName, audienceName);
////        return realm != null ? realm : new OAuthRealm(realmName, issuerName, audienceName);
//    }
//
//    private OAuthRealm getRealmByFilter(
//        List<OAuthRealm> realms,
//        String issuerName,
//        String audienceName)
//    {
//        OAuthRealm result = null;
//        for(int i = 0; i < realms.size(); i++)
//        {
//            final OAuthRealm realm = realms.get(i);
//            if(realm.issuerName.equals(issuerName) && realm.audienceName.equals(audienceName))
//            {
//                result = realm;
//                break;
//            }
//        }
//        return result;
//    }

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

//    private final class OAuthRealmNames
//    {
//        private final String realmName;
//        private final String issuerName;
//        private final String audienceName;
//
//        private OAuthRealmNames(
//            String one,
//            String two,
//            String three) {
//            this.realmName = one;
//            this.issuerName = two;
//            this.audienceName = three;
//        }
//
//        @Override
//        public boolean equals(Object obj)
//        {
//            if(obj == this)
//            {
//                return true;
//            }
//            if(!(obj instanceof OAuthRealmNames))
//            {
//                return false;
//            }
//            OAuthRealmNames other = (OAuthRealmNames) obj;
//            return realmName.equals(other.realmName)
//                    && issuerName.equals(other.issuerName)
//                    && audienceName.equals(other.audienceName);
//        }
//
//        @Override
//        public int hashCode()
//        {
//            int result = 17;
//            result = 31 * result + realmName.hashCode();
//            result = 31 * result + issuerName.hashCode();
//            result = 31 * result + audienceName.hashCode();
//            return result;
//        }
//
//        @Override
//        public String toString()
//        {
//            return String.format("Tuple\nRealm name: %s\n\tIssuer name: %s\n\tAudience name: %s\n",
//                    realmName, issuerName, audienceName);
//        }
//    }

    private final class OAuthRealm
    {
        private static final int MAX_SCOPES = 48;

//        private final Map<String, Long> realmInfos = new CopyOnWriteHashMap<>();
        private final List<OAuthRealmInfo> realmInfos = new LinkedList<>();

//        private final long realmId;
        private final String realmName;
//        private final String issuerName;
//        private final String audienceName;

        private long nextScopeBit;

        private OAuthRealm(
            String realmName)
        {
            assert nextRealmBit < MAX_REALMS;
            this.realmName = realmName;
//            this.realmId = 1L << nextRealmBit++ << MAX_SCOPES;
        }

//        private OAuthRealm(
//            OAuthRealmNames realmNamesTuple)
//        {
//            assert nextRealmBit < MAX_REALMS;
//            this.realmName = realmNamesTuple.realmName;
//            this.realmId = 1L << nextRealmBit++ << MAX_SCOPES;
//            this.issuerName = realmNamesTuple.issuerName;
//            this.audienceName = realmNamesTuple.audienceName;
//        }

//        private long resolve(
//            String[] scopeNames)
//        {
//            long authorization = NO_AUTHORIZATION;
//            if(nextScopeBit + scopeNames.length < MAX_SCOPES)
//            {
//                authorization = realmId;
//                for (int i = 0; i < scopeNames.length; i++)
//                {
//                    authorization |= realmInfos.computeIfAbsent(scopeNames[i], this::assignScopeBit);
//                }
//            }
//            return authorization;
//        }

        private long resolve(
            String[] scopeNames,
            String issuerName,
            String audienceName)
        {
            long authorization = NO_AUTHORIZATION;
//                final OAuthRealmInfo realmInfo = realmInfos.get(i);
            final OAuthRealmInfo realmInfo = computeInfoIfAbsent(issuerName, audienceName);
            final long realmId = realmInfo.realmId;
            if (nextScopeBit + scopeNames.length < MAX_SCOPES)
            {
                authorization = realmId;
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
                realmInfos.add(info);
            }
            return info;
        }

        private OAuthRealmInfo getInfoByFilter(
            String issuerName,
            String audienceName)
        {
            OAuthRealmInfo result = null;
            for(int i = 0; i < realmInfos.size(); i++)
            {
                final OAuthRealmInfo realmInfo = realmInfos.get(i);
                if(realmInfo.containsClaims(issuerName, audienceName))
                {
                    result = realmInfo;
                    break;
                }
            }
            return result;
        }
//
//        private long lookup(
//            String[] scopeNames)
//        {
//            long authorization = realmId;
//            for (int i = 0; i < scopeNames.length; i++)
//            {
//                authorization |= realmInfos.getOrDefault(scopeNames[i], 0L);
//            }
//            return authorization;
//        }

        private boolean tryRemoveInfoById(
            long realmId)
        {
            return realmInfos.removeIf(r -> r.realmId == realmId);
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
                    realmName, realmInfos);
//                    realmName, realmId, realmInfos, issuerName, audienceName);
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
//            final Map<String, String> claims = new CopyOnWriteHashMap<>();
//            private void addClaim(
//                String key,
//                String value)
//            {
////                claims.put(key, value);
//            }

            @Override
            public String toString()
            {
                return String.format("[issuer=\"%s\", audience=\"%s\"]", issuerName, audienceName);
            }
        }
    }
}
