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
package org.reaktivity.auth.jwt.internal;

import static org.reaktivity.nukleus.route.RouteKind.PROXY;

import org.reaktivity.auth.jwt.internal.stream.ProxyStreamFactoryBuilder;
import org.reaktivity.nukleus.Configuration;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.NukleusBuilder;
import org.reaktivity.nukleus.NukleusFactorySpi;

public final class AuthJwtNukleusFactorySpi implements NukleusFactorySpi
{

    @Override
    public String name()
    {
        return "auth-jwt";
    }

    @Override
    public Nukleus create(
        Configuration config,
        NukleusBuilder builder)
    {
        AuthJwtConfiguration jwtConfig = new AuthJwtConfiguration(config);
        final ProxyStreamFactoryBuilder proxyFactoryBuilder = new ProxyStreamFactoryBuilder(
                jwtConfig);

        return builder.streamFactory(PROXY, proxyFactoryBuilder)
                      .build();
    }

}
