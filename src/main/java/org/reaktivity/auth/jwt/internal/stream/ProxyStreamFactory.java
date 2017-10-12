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
package org.reaktivity.auth.jwt.internal.stream;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

import java.util.function.LongSupplier;
import java.util.function.ToLongFunction;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.reaktivity.auth.jwt.internal.util.BufferUtil;
import org.reaktivity.auth.jwt.internal.util.JwtValidator;
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
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;

public class ProxyStreamFactory implements StreamFactory
{
    private static final byte[] BEARER_PREFIX = "Bearer ".getBytes(US_ASCII);
    private static final String AUTHORIZATION = "authorization";
    private final BeginFW beginRO = new BeginFW();
    private final HttpBeginExFW httpBeginExRO = new HttpBeginExFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final RouteFW routeRO = new RouteFW();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();
    private final AbortFW abortRO = new AbortFW();

    private final String16FW string16RO = new String16FW();

    private final RouteManager router;

    private final LongSupplier supplyStreamId;
    private final ToLongFunction<String> supplyRealmId;

    private final Long2ObjectHashMap<Correlation> correlations;
    private final Writer writer;
    private final JwtValidator validator;

    private static class Correlation
    {
        String acceptName;
        long acceptRef;
    }

    public ProxyStreamFactory(
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        LongSupplier supplyStreamId,
        ToLongFunction<String> supplyRealmId,
        JwtValidator validator)
    {
        this.router = requireNonNull(router);
        this.writer = new Writer(writeBuffer);
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyRealmId = supplyRealmId;
        this.validator = validator;
        correlations = new Long2ObjectHashMap<>();
    }

    @Override
    public MessageConsumer newStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length,
            MessageConsumer throttle)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long sourceRef = begin.sourceRef();

        MessageConsumer newStream;

        if (sourceRef == 0L)
        {
            newStream = newConnectReplyStream(begin, throttle);
        }
        else
        {
            newStream = newAcceptStream(begin, throttle);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
            final BeginFW begin,
            final MessageConsumer networkThrottle)
    {
        final long sourceRef = begin.sourceRef();
        final String acceptName = begin.source().asString();
        long authorization = authorize(begin);

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            return sourceRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString());
        };

        final RouteFW route = router.resolve(authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long networkId = begin.streamId();

            newStream = new ProxyAcceptStream(networkThrottle, networkId,
                    authorization, route.target().asString(), route.targetRef())::handleStream;
        }

        return newStream;
    }

    private long authorize(
        BeginFW begin)
    {
        long[] authorization = {0L};
        final HttpBeginExFW beginEx = begin.extension().get(httpBeginExRO::wrap);
        beginEx.headers().forEach(h ->
        {
            if (h.name().equals(AUTHORIZATION))
            {
                String16FW authorizationHeader = h.value();
                final DirectBuffer buffer = authorizationHeader.buffer();
                final int limit = authorizationHeader.limit();
                int offset = BufferUtil.limitOfBytes(buffer, authorizationHeader.offset(),
                        limit, BEARER_PREFIX);
                if (offset > 0)
                {
                    String token = string16RO.wrap(buffer, offset, limit).asString();
                    String realm = validator.validateAndGetRealm(token);
                    if (realm != null)
                    {
                        authorization[0] = supplyRealmId.applyAsLong(realm);
                    }
                }
            }
        });
        return authorization[0];
    }

    private MessageConsumer newConnectReplyStream(
            final BeginFW begin,
            final MessageConsumer throttle)
    {
        final long throttleId = begin.streamId();

        return new ProxyConnectReplyStream(throttle, throttleId)::handleStream;
    }

    private RouteFW wrapRoute(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    final class ProxyAcceptStream
    {
        private final MessageConsumer acceptThrottle;
        private final long acceptStreamId;
        private final long authorization;

        private MessageConsumer connect;
        private final String connectName;
        private final long connectRef;
        private long connectStreamId;

        private MessageConsumer streamState;

        private ProxyAcceptStream(
                MessageConsumer acceptThrottle,
                long acceptStreamId,
                long authorization,
                String connectName,
                long connectRef)
        {
            this.acceptThrottle = acceptThrottle;
            this.acceptStreamId = acceptStreamId;
            this.authorization = authorization;
            this.connectName = connectName;
            this.connectRef = connectRef;
            this.streamState = this::beforeBegin;
        }

        private void handleStream(
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
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                writer.doReset(acceptThrottle, acceptStreamId);
            }
        }

        private void handleBegin(BeginFW begin)
        {
            Correlation correlation = new Correlation();
            correlation.acceptName = begin.source().asString();
            correlation.acceptRef = begin.sourceRef();
            long correlationId = begin.correlationId();
            correlations.put(correlationId, correlation);

            this.connect = router.supplyTarget(connectName);
            this.connectStreamId = supplyStreamId.getAsLong();

            writer.doBegin(connect, connectStreamId, connectRef, correlationId,
                    authorization, begin.extension());

            router.setThrottle(connectName, connectStreamId, this::handleConnectThrottle);
            this.streamState = this::afterBegin;
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
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                writer.doReset(acceptThrottle, acceptStreamId);
                break;
            }
        }

        private void handleData(
                DataFW data)
        {
            final OctetsFW payload = data.payload();
            writer.doData(connect, connectStreamId, payload.buffer(), payload.offset(), payload.sizeof(),
                    data.extension());
        }

        private void handleEnd(
                EndFW end)
        {
            writer.doEnd(connect, connectStreamId, end.extension());
        }

        private void handleAbort(
                AbortFW abort)
        {
            writer.doAbort(connect, connectStreamId);
        }

        private void handleConnectThrottle(
                int msgTypeId,
                DirectBuffer buffer,
                int index,
                int length)
        {
            switch (msgTypeId)
            {
                case WindowFW.TYPE_ID:
                    final WindowFW window = windowRO.wrap(buffer, index, index + length);
                    handleConnectWindow(window);
                    break;
                case ResetFW.TYPE_ID:
                    final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                    handleConnectReset(reset);
                    break;
                default:
                    // ignore
                    break;
            }
        }

        private void handleConnectWindow(
            WindowFW window)
        {
            final int bytes = windowRO.update();
            final int frames = windowRO.frames();

            writer.doWindow(acceptThrottle, acceptStreamId, bytes, frames);
        }

        private void handleConnectReset(
            ResetFW reset)
        {
            writer.doReset(acceptThrottle, acceptStreamId);
        }

    }

    private final class ProxyConnectReplyStream
    {
        private MessageConsumer streamState;

        private final MessageConsumer connectReplyThrottle;
        private final long connectReplyStreamId;

        private MessageConsumer acceptReply;

        private long acceptReplyStreamId;

        private ProxyConnectReplyStream(
                MessageConsumer connectReplyThrottle,
                long connectReplyId)
        {
            this.connectReplyThrottle = connectReplyThrottle;
            this.connectReplyStreamId = connectReplyId;
            this.streamState = this::beforeBegin;
        }

        private void handleStream(
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
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                writer.doReset(connectReplyThrottle, connectReplyStreamId);
            }
        }

        private void handleBegin(
                BeginFW begin)
        {
            final long connectCorrelationId = begin.correlationId();

            Correlation correlation = correlations.remove(connectCorrelationId);

            if (correlation != null)
            {
                this.acceptReply = router.supplyTarget(correlation.acceptName);
                this.acceptReplyStreamId = supplyStreamId.getAsLong();
                writer.doBegin(acceptReply, acceptReplyStreamId, correlation.acceptRef,
                        begin.correlationId(), begin.authorization(), begin.extension());
            }
            else
            {
                writer.doReset(connectReplyThrottle, connectReplyStreamId);
            }
        }
    }

}
