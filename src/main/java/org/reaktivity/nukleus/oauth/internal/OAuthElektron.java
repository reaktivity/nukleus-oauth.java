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

import static java.util.Collections.singletonMap;
import static org.reaktivity.nukleus.route.RouteKind.PROXY;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.ToLongBiFunction;
import java.util.function.ToLongFunction;

import org.jose4j.jwk.JsonWebKey;
import org.reaktivity.nukleus.Elektron;
import org.reaktivity.nukleus.oauth.internal.stream.OAuthProxyFactoryBuilder;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;

final class OAuthElektron implements Elektron
{
    private final Map<RouteKind, StreamFactoryBuilder> streamFactoryBuilders;

    OAuthElektron(
        Function<String, JsonWebKey> supplyKey,
        ToLongBiFunction<String, String[]> resolveRealm)
    {
        this.streamFactoryBuilders = singletonMap(PROXY, new OAuthProxyFactoryBuilder(supplyKey, resolveRealm));
    }

    @Override
    public StreamFactoryBuilder streamFactoryBuilder(
        RouteKind kind)
    {
        return streamFactoryBuilders.get(kind);
    }

    @Override
    public String toString()
    {
        return String.format("%s %s", getClass().getSimpleName(), streamFactoryBuilders);
    }
}
