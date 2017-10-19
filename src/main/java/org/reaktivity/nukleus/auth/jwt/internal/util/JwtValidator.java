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
package org.reaktivity.nukleus.auth.jwt.internal.util;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.agrona.LangUtil.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

public class JwtValidator
{
    private JsonWebSignature jws = new JsonWebSignature();
    private final Map<String, JsonWebKey> keysByKid;
    private final LongSupplier supplyCurrentTimeMillis;

    public JwtValidator(Path keyFile, LongSupplier supplyCurrentTimeMillis)
    {
        Map<String, JsonWebKey> keysByKid = null;
        try
        {
            byte[] rawKeys = Files.readAllBytes(keyFile);
            keysByKid = toKeyMap(new String(rawKeys, UTF_8));
        }
        catch (IOException e)
        {
            rethrowUnchecked(e);
        }
        this.keysByKid = keysByKid;
        this.supplyCurrentTimeMillis = supplyCurrentTimeMillis;
    }

    public JwtValidator(String jwkSet, LongSupplier supplyCurrentTimeMillis)
    {
        this.keysByKid = toKeyMap(jwkSet);
        this.supplyCurrentTimeMillis = supplyCurrentTimeMillis;
    }

    private Map<String, JsonWebKey> toKeyMap(String keysAsJwkSet)
    {
        JsonWebKeySet keys = null;
        Map<String, JsonWebKey> keysByKid;

        try
        {
            keys = new JsonWebKeySet(keysAsJwkSet);
        }
        catch (JoseException e)
        {
            rethrowUnchecked(e);
        }
        keysByKid = new HashMap<>();
        keys.getJsonWebKeys().forEach((k) ->
        {
           String kid = k.getKeyId();
           if (kid == null)
           {
               throw new IllegalArgumentException("Key without kid");
           }
           if (k.getAlgorithm() == null)
           {
               throw new IllegalArgumentException("Key without alg");
           }
           if (keysByKid.put(kid, k) != null)
           {
               throw new IllegalArgumentException("Key with duplicate kid");
           }
        });
        return keysByKid;
    }

    public void forEachRealm(Consumer<String> consumer)
    {
        keysByKid.forEach((k, v) -> consumer.accept(k));
    }

    public String validateAndGetRealm(String token)
    {
        String realm = null;
        try
        {
            jws.setCompactSerialization(token);
            String kid = jws.getKeyIdHeaderValue();
            JsonWebKey key;
            if (kid != null && (key = keysByKid.get(kid)) != null)
            {
                if (key.getAlgorithm().equals(jws.getAlgorithmHeaderValue()))
                {
                    jws.setKey(key.getKey());
                    if (withinDuration(jws) && jws.verifySignature())
                    {
                        realm = kid;
                    }
                }
            }
        }
        catch (JoseException | MalformedClaimException | InvalidJwtException e)
        {
            // TODO: diagnostics?
        }
        return realm;
    }

    private boolean withinDuration(JsonWebSignature jws) throws MalformedClaimException, InvalidJwtException, JoseException
    {
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        long now = supplyCurrentTimeMillis.getAsLong();
        NumericDate exp = claims.getExpirationTime();
        NumericDate nbf = claims.getNotBefore();

        return (exp == null || now <= exp.getValueInMillis()) &&
               (nbf == null || now >= nbf.getValueInMillis());
    }

}
