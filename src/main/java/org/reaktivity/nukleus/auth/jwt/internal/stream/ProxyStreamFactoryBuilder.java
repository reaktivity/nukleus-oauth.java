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
package org.reaktivity.nukleus.auth.jwt.internal.stream;

import java.util.function.IntUnaryOperator;
import java.util.function.LongFunction;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.Supplier;
import java.util.function.ToLongFunction;

import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;

public class ProxyStreamFactoryBuilder implements StreamFactoryBuilder
{
    private final ToLongFunction<String> resolveTokenRealmId;

    private RouteManager router;
    private MutableDirectBuffer writeBuffer;
    private LongSupplier supplyInitialId;
    private LongUnaryOperator supplyReplyId;
    private LongSupplier supplyCorrelationId;
    private LongSupplier supplyTrace;

    static class Correlation
    {
        long acceptRouteId;
        long acceptInitialId;
        long acceptCorrelationId;
    }

    private final Long2ObjectHashMap<Correlation> correlations;

    public ProxyStreamFactoryBuilder(
        ToLongFunction<String> resolveTokenRealmId)
    {
        this.resolveTokenRealmId = resolveTokenRealmId;
        this.correlations = new Long2ObjectHashMap<>();
    }

    @Override
    public ProxyStreamFactoryBuilder setRouteManager(
            RouteManager router)
    {
        this.router = router;
        return this;
    }

    @Override
    public StreamFactoryBuilder setTraceSupplier(LongSupplier supplyTrace)
    {
        this.supplyTrace = supplyTrace;
        return this;
    }

    @Override
    public ProxyStreamFactoryBuilder setWriteBuffer(
        MutableDirectBuffer writeBuffer)
    {
        this.writeBuffer = writeBuffer;
        return this;
    }

    @Override
    public ProxyStreamFactoryBuilder setInitialIdSupplier(
        LongSupplier supplyInitialId)
    {
        this.supplyInitialId = supplyInitialId;
        return this;
    }

    @Override
    public StreamFactoryBuilder setReplyIdSupplier(
        LongUnaryOperator supplyReplyId)
    {
        this.supplyReplyId = supplyReplyId;
        return this;
    }

    @Override
    public ProxyStreamFactoryBuilder setGroupBudgetClaimer(
        LongFunction<IntUnaryOperator> groupBudgetClaimer)
    {
        return this;
    }

    @Override
    public ProxyStreamFactoryBuilder setGroupBudgetReleaser(
        LongFunction<IntUnaryOperator> groupBudgetReleaser)
    {
        return this;
    }

    @Override
    public ProxyStreamFactoryBuilder setTargetCorrelationIdSupplier(
        LongSupplier supplyCorrelationId)
    {
        this.supplyCorrelationId = supplyCorrelationId;
        return this;
    }

    @Override
    public StreamFactoryBuilder setBufferPoolSupplier(
        Supplier<BufferPool> supplyBufferPool)
    {
        return this;
    }

    @Override
    public StreamFactory build()
    {
        return new ProxyStreamFactory(
                router,
                writeBuffer,
                supplyInitialId,
                supplyTrace,
                supplyReplyId,
                supplyCorrelationId,
                correlations,
                resolveTokenRealmId);
    }
}
