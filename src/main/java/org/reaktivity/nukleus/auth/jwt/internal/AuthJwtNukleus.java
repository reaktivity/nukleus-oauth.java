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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.UnaryOperator;

import org.agrona.collections.Int2ObjectHashMap;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.auth.jwt.internal.resolver.Realms;
import org.reaktivity.nukleus.auth.jwt.internal.resolver.Resolver;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.ResolveFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.UnresolveFW;
import org.reaktivity.nukleus.auth.jwt.internal.util.JwtValidator;
import org.reaktivity.nukleus.function.CommandHandler;

final class AuthJwtNukleus implements Nukleus
{
    static final String NAME = "auth-jwt";

    private final AuthJwtConfiguration config;
    private final Realms realms;
    private final UnaryOperator<String> validator;
    private final Int2ObjectHashMap<CommandHandler> commandHandlers;

    AuthJwtNukleus(
        AuthJwtConfiguration config)
    {
        this.config = config;

        final Realms realms = new Realms();
        final Path keyFile = config.directory().resolve(name()).resolve(config.keyFileName());

        if (Files.exists(keyFile))
        {
            final JwtValidator validator = new JwtValidator(keyFile, System::currentTimeMillis);
            validator.forEachRealm(r -> realms.add(r));
            this.validator = validator::validateAndGetRealm;
        }
        else
        {
            this.validator = t -> null;
        }

        final Resolver resolver = new Resolver(realms);
        final Int2ObjectHashMap<CommandHandler> commandHandlers = new Int2ObjectHashMap<>();
        commandHandlers.put(ResolveFW.TYPE_ID, resolver::resolve);
        commandHandlers.put(UnresolveFW.TYPE_ID, resolver::unresolve);

        this.realms = realms;
        this.commandHandlers = commandHandlers;
    }

    @Override
    public String name()
    {
        return AuthJwtNukleus.NAME;
    }

    @Override
    public AuthJwtConfiguration config()
    {
        return config;
    }

    @Override
    public CommandHandler commandHandler(
        int msgTypeId)
    {
        return commandHandlers.get(msgTypeId);
    }

    @Override
    public AuthJwtElektron supplyElektron()
    {
        return new AuthJwtElektron(this::resolveTokenRealmId);
    }

    private long resolveTokenRealmId(
        String token)
    {
        long authorization = 0L;
        String realm = validator.apply(token);
        if (realm != null)
        {
            authorization = realms.resolve(realm);
        }
        return authorization;
    }
}
