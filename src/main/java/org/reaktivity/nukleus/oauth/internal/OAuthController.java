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

import static java.nio.ByteBuffer.allocateDirect;
import static java.nio.ByteOrder.nativeOrder;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.reaktivity.nukleus.route.RouteKind.PROXY;

import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

import org.agrona.concurrent.AtomicBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.Controller;
import org.reaktivity.nukleus.ControllerSpi;
import org.reaktivity.nukleus.oauth.internal.types.Flyweight;
import org.reaktivity.nukleus.oauth.internal.types.OctetsFW;
import org.reaktivity.nukleus.oauth.internal.types.control.FreezeFW;
import org.reaktivity.nukleus.oauth.internal.types.control.OAuthResolveExFW;
import org.reaktivity.nukleus.oauth.internal.types.control.Role;
import org.reaktivity.nukleus.oauth.internal.types.control.RouteFW;
import org.reaktivity.nukleus.oauth.internal.types.control.UnrouteFW;
import org.reaktivity.nukleus.oauth.internal.types.control.ResolveFW;
import org.reaktivity.nukleus.oauth.internal.types.control.UnresolveFW;
import org.reaktivity.nukleus.route.RouteKind;

public class OAuthController implements Controller
{
    private static final int MAX_SEND_LENGTH = 1024; // TODO: Configuration and Context

    // TODO: thread-safe flyweights or command queue from public methods
    private final ResolveFW.Builder resolveRW = new ResolveFW.Builder();
    private final OAuthResolveExFW.Builder resolveExRW = new OAuthResolveExFW.Builder();
    private final UnresolveFW.Builder unresolveRW = new UnresolveFW.Builder();
    private final RouteFW.Builder routeRW = new RouteFW.Builder();
    private final UnrouteFW.Builder unrouteRW = new UnrouteFW.Builder();
    private final FreezeFW.Builder freezeRW = new FreezeFW.Builder();

    private final OctetsFW extensionRO = new OctetsFW().wrap(new UnsafeBuffer(new byte[0]), 0, 0);

    private final ControllerSpi controllerSpi;
    private final AtomicBuffer commandBuffer;
    private final AtomicBuffer extensionBuffer;

    public OAuthController(
        ControllerSpi controllerSpi)
    {
        this.controllerSpi = controllerSpi;
        this.commandBuffer = new UnsafeBuffer(allocateDirect(MAX_SEND_LENGTH).order(nativeOrder()));
        this.extensionBuffer = new UnsafeBuffer(allocateDirect(MAX_SEND_LENGTH).order(nativeOrder()));
    }

    @Override
    public int process()
    {
        return controllerSpi.doProcess();
    }

    @Override
    public void close() throws Exception
    {
        controllerSpi.doClose();
    }

    @Override
    public Class<OAuthController> kind()
    {
        return OAuthController.class;
    }

    @Override
    public String name()
    {
        return OAuthNukleus.NAME;
    }

    public CompletableFuture<Long> resolve(
        String realmName,
        String... roleNames)
    {
        return resolve(realmName, roleNames, null, null);
    }

    public CompletableFuture<Long> resolve(
        String realmName,
        String[] roleNames,
        String issuerName,
        String audienceName)
    {
        long correlationId = controllerSpi.nextCorrelationId();
        final ResolveFW.Builder resolveBuilder = resolveRW.wrap(commandBuffer, 0, commandBuffer.capacity())
                                               .correlationId(correlationId)
                                               .nukleus(name())
                                               .realm(realmName)
                                               .roles(b -> Arrays.asList(roleNames).forEach(s -> b.item(sb -> sb.set(s, UTF_8))));
        if (issuerName != null || audienceName != null)
        {
            final OAuthResolveExFW resolveEx = resolveExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                                                          .issuer(issuerName)
                                                          .audience(audienceName)
                                                          .build();
            resolveBuilder.extension(resolveEx.buffer(), resolveEx.offset(), resolveEx.sizeof());
        }
        final ResolveFW resolve = resolveBuilder.build();
        return controllerSpi.doResolve(resolve.typeId(), resolve.buffer(), resolve.offset(), resolve.sizeof());
    }

    public CompletableFuture<Void> unresolve(
        long authorization)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        UnresolveFW unresolveRO = unresolveRW.wrap(commandBuffer, 0, commandBuffer.capacity())
                                             .correlationId(correlationId)
                                             .nukleus(name())
                                             .authorization(authorization)
                                             .build();

        return controllerSpi.doUnresolve(unresolveRO.typeId(), unresolveRO.buffer(), unresolveRO.offset(), unresolveRO.sizeof());
    }

    @Deprecated
    public CompletableFuture<Long> routeProxy(
        String localAddress,
        String remoteAddress,
        long authorization)
    {
        return route(PROXY, localAddress, remoteAddress, authorization);
    }

    public CompletableFuture<Long> route(
        RouteKind kind,
        String localAddress,
        String remoteAddress,
        long authorization)
    {
        return doRoute(kind, localAddress, remoteAddress, authorization, extensionRO);
    }

    public CompletableFuture<Void> unroute(
        long routeId)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        UnrouteFW unrouteRO = unrouteRW.wrap(commandBuffer, 0, commandBuffer.capacity())
                                 .correlationId(correlationId)
                                 .nukleus(name())
                                 .routeId(routeId)
                                 .build();

        return controllerSpi.doUnroute(unrouteRO.typeId(), unrouteRO.buffer(), unrouteRO.offset(), unrouteRO.sizeof());
    }

    public CompletableFuture<Void> freeze()
    {
        long correlationId = controllerSpi.nextCorrelationId();

        FreezeFW freeze = freezeRW.wrap(commandBuffer, 0, commandBuffer.capacity())
                                  .correlationId(correlationId)
                                  .nukleus(name())
                                  .build();

        return controllerSpi.doFreeze(freeze.typeId(), freeze.buffer(), freeze.offset(), freeze.sizeof());
    }

    private CompletableFuture<Long> doRoute(
        RouteKind kind,
        String localAddress,
        String remoteAddress,
        long authorization,
        Flyweight extension)
    {
        final long correlationId = controllerSpi.nextCorrelationId();
        final Role role = Role.valueOf(kind.ordinal());

        final RouteFW routeRO = routeRW.wrap(commandBuffer, 0, commandBuffer.capacity())
                                 .correlationId(correlationId)
                                 .nukleus(name())
                                 .role(b -> b.set(role))
                                 .authorization(authorization)
                                 .localAddress(localAddress)
                                 .remoteAddress(remoteAddress)
                                 .extension(extension.buffer(), extension.offset(), extension.sizeof())
                                 .build();

        return controllerSpi.doRoute(routeRO.typeId(), routeRO.buffer(), routeRO.offset(), routeRO.sizeof());
    }
}
