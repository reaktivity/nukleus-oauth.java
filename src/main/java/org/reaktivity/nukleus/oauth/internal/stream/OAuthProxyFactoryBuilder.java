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
package org.reaktivity.nukleus.oauth.internal.stream;

import java.util.List;
import java.util.function.*;

import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.jose4j.jwk.JsonWebKey;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.concurrent.SignalingExecutor;
import org.reaktivity.nukleus.oauth.internal.stream.OAuthProxyFactory.OAuthProxy;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;

public class OAuthProxyFactoryBuilder implements StreamFactoryBuilder
{
    private final Function<String, JsonWebKey> supplyKey;
    private final ToLongBiFunction<String, String> resolveRealm;
    private final Long2ObjectHashMap<OAuthProxy> correlations;

    private RouteManager router;
    private MutableDirectBuffer writeBuffer;
    private LongUnaryOperator supplyInitialId;
    private LongUnaryOperator supplyReplyId;
    private LongSupplier supplyTrace;
    private SignalingExecutor executor;

    public OAuthProxyFactoryBuilder(
        Function<String, JsonWebKey> supplyKey,
        ToLongBiFunction<String, String> resolveRealm)
    {
        this.supplyKey = supplyKey;
        this.resolveRealm = resolveRealm;
        this.correlations = new Long2ObjectHashMap<>();
    }

    @Override
    public OAuthProxyFactoryBuilder setRouteManager(
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
    public OAuthProxyFactoryBuilder setWriteBuffer(
        MutableDirectBuffer writeBuffer)
    {
        this.writeBuffer = writeBuffer;
        return this;
    }

    @Override
    public OAuthProxyFactoryBuilder setInitialIdSupplier(
        LongUnaryOperator supplyInitialId)
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
    public OAuthProxyFactoryBuilder setGroupBudgetClaimer(
        LongFunction<IntUnaryOperator> groupBudgetClaimer)
    {
        return this;
    }

    @Override
    public OAuthProxyFactoryBuilder setGroupBudgetReleaser(
        LongFunction<IntUnaryOperator> groupBudgetReleaser)
    {
        return this;
    }

    @Override
    public StreamFactoryBuilder setBufferPoolSupplier(
        Supplier<BufferPool> supplyBufferPool)
    {
        return this;
    }

    @Override
    public StreamFactoryBuilder setExecutor(
        SignalingExecutor executor)
    {
        this.executor = executor;
        return this;
    }

    @Override
    public StreamFactory build()
    {
        return new OAuthProxyFactory(
                router,
                writeBuffer,
                supplyInitialId,
                supplyTrace,
                supplyReplyId,
                correlations,
                supplyKey,
                resolveRealm,
                executor);
    }
}
