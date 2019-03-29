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
package org.reaktivity.nukleus.auth.jwt.internal.stream;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.ToLongFunction;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.reaktivity.nukleus.auth.jwt.internal.stream.ProxyStreamFactoryBuilder.Correlation;
import org.reaktivity.nukleus.auth.jwt.internal.types.OctetsFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.String16FW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.RouteFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.DataFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.EndFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.HttpBeginExFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.WindowFW;
import org.reaktivity.nukleus.auth.jwt.internal.util.BufferUtil;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;

public class ProxyStreamFactory implements StreamFactory
{
    private static final byte[] BEARER_PREFIX = "Bearer ".getBytes(US_ASCII);
    private static final byte[] AUTHORIZATION = "authorization".getBytes(US_ASCII);

    private final RouteFW routeRO = new RouteFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();

    private final HttpBeginExFW httpBeginExRO = new HttpBeginExFW();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();
    private final AbortFW abortRO = new AbortFW();

    private final RouteManager router;

    private final LongUnaryOperator supplyInitialId;
    private final LongSupplier supplyTrace;
    private final LongUnaryOperator supplyReplyId;
    private final ToLongFunction<String> resolveTokenRealmId;

    private final Long2ObjectHashMap<Correlation> correlations;
    private final Writer writer;

    public ProxyStreamFactory(
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        LongUnaryOperator supplyInitialId,
        LongSupplier supplyTrace,
        LongUnaryOperator supplyReplyId,
        Long2ObjectHashMap<Correlation> correlations,
        ToLongFunction<String> resolveTokenRealmId)
    {
        this.router = requireNonNull(router);
        this.writer = new Writer(writeBuffer);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.supplyTrace = requireNonNull(supplyTrace);
        this.correlations = correlations;
        this.resolveTokenRealmId = resolveTokenRealmId;
    }

    @Override
    public MessageConsumer newStream(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer source)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long streamId = begin.streamId();

        MessageConsumer newStream;

        if ((streamId & 0x0000_0000_0000_0001L) != 0L)
        {
            newStream = newAcceptStream(begin, source);
        }
        else
        {
            newStream = newConnectReplyStream(begin, source);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer acceptReply)
    {
        final long acceptRouteId = begin.routeId();
        long authorization = authorize(begin);

        final MessagePredicate filter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(acceptRouteId, authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long acceptInitialId = begin.streamId();
            final long traceId = begin.trace();
            final OctetsFW extension = begin.extension();

            Correlation targetCorrelation = new Correlation();
            targetCorrelation.acceptRouteId = acceptRouteId;
            targetCorrelation.acceptInitialId = acceptInitialId;
            targetCorrelation.acceptReply = acceptReply;

            long connectRouteId = route.correlationId();
            long connectInitialId = supplyInitialId.applyAsLong(connectRouteId);
            MessageConsumer connectInitial = router.supplyReceiver(connectInitialId);
            long connectReplyId = supplyReplyId.applyAsLong(connectInitialId);

            correlations.put(connectReplyId, targetCorrelation);

            writer.doBegin(connectInitial, connectRouteId, connectInitialId, traceId,
                    authorization, extension);
            ProxyStream stream = new ProxyStream(acceptReply, acceptRouteId, acceptInitialId,
                    connectInitial, connectRouteId, connectInitialId);
            router.setThrottle(connectInitialId, stream::onThrottleMessage);

            newStream = stream::onStreamMessage;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer sender)
    {
        final long connectRouteId = begin.routeId();
        final long connectReplyId = begin.streamId();
        final long traceId = begin.trace();
        final long authorization = begin.authorization();
        final OctetsFW extension = begin.extension();

        Correlation correlation = correlations.remove(connectReplyId);

        MessageConsumer newStream = null;

        if (correlation != null)
        {
            long acceptRouteId = correlation.acceptRouteId;
            MessageConsumer acceptReply = correlation.acceptReply;
            long acceptReplyId = supplyReplyId.applyAsLong(correlation.acceptInitialId);

            writer.doBegin(acceptReply, acceptRouteId, acceptReplyId, traceId, authorization,
                    extension);
            ProxyStream stream = new ProxyStream(sender, connectRouteId, connectReplyId,
                    acceptReply, acceptRouteId, acceptReplyId);
            router.setThrottle(acceptReplyId, stream::onThrottleMessage);

            newStream = stream::onStreamMessage;
        }

        return newStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    private long authorize(
        BeginFW begin)
    {
        final long[] authorization = {0L};

        final HttpBeginExFW beginEx = begin.extension().get(httpBeginExRO::wrap);
        beginEx.headers().forEach(h ->
        {
            if (BufferUtil.equals(h.name(), AUTHORIZATION))
            {
                String16FW authorizationHeader = h.value();
                final DirectBuffer buffer = authorizationHeader.buffer();
                final int limit = authorizationHeader.limit();
                int offset = BufferUtil.limitOfBytes(buffer, authorizationHeader.offset(),
                        limit, BEARER_PREFIX);
                if (offset > 0)
                {
                    String token = buffer.getStringWithoutLengthUtf8(offset, limit - offset);
                    authorization[0] = resolveTokenRealmId.applyAsLong(token);
                }
            }
        });

        if (authorization[0] == 0L)
        {
            authorization[0] = begin.authorization();
        }

        return authorization[0];
    }

    private final class ProxyStream
    {
        private final MessageConsumer sourceThrottle;
        private final long sourceRouteId;
        private final long sourceStreamId;
        private final MessageConsumer target;
        private final long targetRouteId;
        private final long targetStreamId;

        private MessageConsumer streamState;

        private ProxyStream(
            MessageConsumer source,
            long sourceRouteId,
            long sourceId,
            MessageConsumer target,
            long targetRouteId,
            long targetId)
        {
            this.sourceThrottle = source;
            this.sourceRouteId = sourceRouteId;
            this.sourceStreamId = sourceId;
            this.target = target;
            this.targetRouteId = targetRouteId;
            this.targetStreamId = targetId;
            this.streamState = this::beforeBegin;
        }

        private void onStreamMessage(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                this.streamState = this::afterBegin;
            }
            else
            {
                writer.doReset(sourceThrottle, sourceRouteId, sourceStreamId, supplyTrace.getAsLong());
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                onData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                onEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                onAbort(abort);
                break;
            default:
                writer.doReset(sourceThrottle, sourceRouteId, sourceStreamId, supplyTrace.getAsLong());
                break;
            }
        }

        private void onThrottleMessage(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                onWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                onReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void onData(
            DataFW data)
        {
            final long traceId = data.trace();
            final long authorization = data.authorization();
            final int padding = data.padding();
            final long groupId = data.groupId();
            final OctetsFW payload = data.payload();
            final OctetsFW extension = data.extension();

            writer.doData(target, targetRouteId, targetStreamId, traceId, authorization, groupId, padding, payload, extension);
        }

        private void onEnd(
            EndFW end)
        {
            final long traceId = end.trace();
            final OctetsFW extension = end.extension();

            writer.doEnd(target, targetRouteId, targetStreamId, traceId, extension);
        }

        private void onAbort(
            AbortFW abort)
        {
            final long traceId = abort.trace();

            writer.doAbort(target, targetRouteId, targetStreamId, traceId);
        }

        private void onWindow(
            WindowFW window)
        {
            final int credit = window.credit();
            final long traceId = window.trace();
            final int padding = window.padding();
            final long groupId = window.groupId();

            writer.doWindow(sourceThrottle, sourceRouteId, sourceStreamId, traceId, credit, padding, groupId);
        }

        private void onReset(
            ResetFW reset)
        {
            final long traceId = reset.trace();

            writer.doReset(sourceThrottle, sourceRouteId, sourceStreamId, traceId);
        }
    }
}
