/**
 * Copyright 2016-2018 The Reaktivity Project
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
package org.reaktivity.nukleus.auth.jwt.internal;

import static java.util.Collections.singletonMap;
import static org.reaktivity.nukleus.route.RouteKind.PROXY;

import java.util.Map;
import java.util.function.ToLongFunction;

import org.reaktivity.nukleus.Elektron;
import org.reaktivity.nukleus.auth.jwt.internal.stream.ProxyStreamFactoryBuilder;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;

final class AuthJwtElektron implements Elektron
{
    private final Map<RouteKind, StreamFactoryBuilder> streamFactoryBuilders;

    AuthJwtElektron(
        ToLongFunction<String> resolveTokenRealmId)
    {
        this.streamFactoryBuilders = singletonMap(PROXY, new ProxyStreamFactoryBuilder(resolveTokenRealmId));
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
