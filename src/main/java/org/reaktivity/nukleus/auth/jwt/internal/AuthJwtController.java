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
package org.reaktivity.nukleus.auth.jwt.internal;

import static java.nio.ByteBuffer.allocateDirect;
import static java.nio.ByteOrder.nativeOrder;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.ToIntFunction;

import org.agrona.concurrent.AtomicBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.Controller;
import org.reaktivity.nukleus.ControllerSpi;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.Role;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.RouteFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.UnrouteFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.ResolveFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.UnresolveFW;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;

public class AuthJwtController implements Controller
{
    private static final int MAX_SEND_LENGTH = 1024; // TODO: Configuration and Context

    // TODO: thread-safe flyweights or command queue from public methods
    private final ResolveFW.Builder resolveRW = new ResolveFW.Builder();
    private final UnresolveFW.Builder unresolveRW = new UnresolveFW.Builder();
    private final RouteFW.Builder routeRW = new RouteFW.Builder();
    private final UnrouteFW.Builder unrouteRW = new UnrouteFW.Builder();

    private final ControllerSpi controllerSpi;
    private final AtomicBuffer atomicBuffer;

    public AuthJwtController(ControllerSpi controllerSpi)
    {
        this.controllerSpi = controllerSpi;
        this.atomicBuffer = new UnsafeBuffer(allocateDirect(MAX_SEND_LENGTH).order(nativeOrder()));
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
    public Class<AuthJwtController> kind()
    {
        return AuthJwtController.class;
    }

    @Override
    public String name()
    {
        return "auth-jwt";
    }

    public <T> T supplySource(
        String source,
        BiFunction<MessagePredicate, ToIntFunction<MessageConsumer>, T> factory)
    {
        return controllerSpi.doSupplySource(source, factory);
    }

    public <T> T supplyTarget(
        String target,
        BiFunction<ToIntFunction<MessageConsumer>, MessagePredicate, T> factory)
    {
        return controllerSpi.doSupplyTarget(target, factory);
    }

    public CompletableFuture<Long> resolve(
        String realm,
        String... roles)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        ResolveFW resolveRO = resolveRW.wrap(atomicBuffer, 0, atomicBuffer.capacity())
                .correlationId(correlationId)
                .realm(realm)
                .roles(b -> Arrays.asList(roles).forEach(s -> b.item(sb -> sb.set(s, UTF_8))))
                .build();
        return controllerSpi.doCommand(resolveRO.typeId(), resolveRO.buffer(), resolveRO.offset(), resolveRO.sizeof());
    }

    public CompletableFuture<Void> unresolve(
        long authorization)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        UnresolveFW unresolveRO = unresolveRW.wrap(atomicBuffer, 0, atomicBuffer.capacity())
                                             .correlationId(correlationId)
                                             .authorization(authorization)
                                             .build();
        return controllerSpi.doCommand(unresolveRO.typeId(), unresolveRO.buffer(), unresolveRO.offset(), unresolveRO.sizeof());
    }

    public CompletableFuture<Long> routeProxy(
        String source,
        long sourceRef,
        String target,
        long targetRef,
        long authorization)
    {
        return route(Role.PROXY, source, sourceRef, target, targetRef, authorization);
    }

    public CompletableFuture<Void> unrouteProxy(
        String source,
        long sourceRef,
        String target,
        long targetRef,
        long authorization)
    {
        return unroute(Role.PROXY, source, sourceRef, target, targetRef, authorization);
    }

    public long count(String name)
    {
        return controllerSpi.doCount(name);
    }

    private CompletableFuture<Long> route(
        Role role,
        String source,
        long sourceRef,
        String target,
        long targetRef,
        long authorization)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        RouteFW routeRO = routeRW.wrap(atomicBuffer, 0, atomicBuffer.capacity())
                                 .correlationId(correlationId)
                                 .role(b -> b.set(role))
                                 .source(source)
                                 .sourceRef(sourceRef)
                                 .target(target)
                                 .targetRef(targetRef)
                                 .authorization(authorization)
                                 .build();

        return controllerSpi.doRoute(routeRO.typeId(), routeRO.buffer(), routeRO.offset(), routeRO.sizeof());
    }

    private CompletableFuture<Void> unroute(
        Role role,
        String source,
        long sourceRef,
        String target,
        long targetRef,
        long authorization)
    {
        long correlationId = controllerSpi.nextCorrelationId();

        UnrouteFW unrouteRO = unrouteRW.wrap(atomicBuffer, 0, atomicBuffer.capacity())
                                 .correlationId(correlationId)
                                 .role(b -> b.set(role))
                                 .source(source)
                                 .sourceRef(sourceRef)
                                 .target(target)
                                 .targetRef(targetRef)
                                 .authorization(authorization)
                                 .build();

        return controllerSpi.doUnroute(unrouteRO.typeId(), unrouteRO.buffer(), unrouteRO.offset(), unrouteRO.sizeof());
    }

}
