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
package org.reaktivity.auth.jwt.internal.util;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.agrona.LangUtil.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

public class JwtValidator
{
    private JsonWebSignature jws = new JsonWebSignature();
    private final Map<String, JsonWebKey> keysByKid;

    public JwtValidator(Path keyFile)
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
    }

    public JwtValidator(String jwkSet)
    {
        this.keysByKid = toKeyMap(jwkSet);
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

    public int realmCount()
    {
        return keysByKid.size();
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
                    if (jws.verifySignature())
                    {
                        realm = kid;
                    }
                }
            }
        }
        catch (JoseException e)
        {
            // TODO: diagnostics?
        }
        return realm;
    }

}
