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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.reaktivity.nukleus.oauth.internal.util.BufferUtil.indexOfBytes;

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.reaktivity.nukleus.concurrent.SignalingExecutor;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.oauth.internal.OAuthConfiguration;
import org.reaktivity.nukleus.oauth.internal.types.HttpHeaderFW;
import org.reaktivity.nukleus.oauth.internal.types.OctetsFW;
import org.reaktivity.nukleus.oauth.internal.types.String16FW;
import org.reaktivity.nukleus.oauth.internal.types.control.RouteFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.DataFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.EndFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.HttpBeginExFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.SignalFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.WindowFW;
import org.reaktivity.nukleus.oauth.internal.util.BufferUtil;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;

public class OAuthProxyFactory implements StreamFactory
{
    private static final long EXPIRES_NEVER = Long.MAX_VALUE;
    private static final long EXPIRES_IMMEDIATELY = 0L;

    private static final long TOKEN_EXPIRED_SIGNAL = 1L;

    private static final long REALM_MASK = 0xFFFF_000000000000L;

    private static final Pattern QUERY_PARAMS = Pattern.compile("(?:\\?|.*?&)access_token=([^&#]+)(?:&.*)?");

    private static final byte[] BEARER_PREFIX = "Bearer ".getBytes(US_ASCII);
    private static final byte[] QUERY_PREFIX = "?".getBytes(US_ASCII);
    private static final byte[] AUTHORIZATION = "authorization".getBytes(US_ASCII);
    private static final byte[] PATH = ":path".getBytes(US_ASCII);

    private final RouteFW routeRO = new RouteFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();

    private final OctetsFW octetsRO = new OctetsFW().wrap(new UnsafeBuffer(new byte[0]), 0, 0);

    private final HttpBeginExFW httpBeginExRO = new HttpBeginExFW();
    private final HttpBeginExFW.Builder httpBeginExRW = new HttpBeginExFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();
    private final AbortFW abortRO = new AbortFW();
    private final SignalFW signalRO = new SignalFW();

    private final JsonWebSignature signature = new JsonWebSignature();

    private final Map<Long, Map<String, OAuthAccessGrant>>[] inFlightAuthorizationsByRealm = new Long2ObjectHashMap[16];

    private final OAuthConfiguration config;
    private final RouteManager router;
    private final LongUnaryOperator supplyInitialId;
    private final LongSupplier supplyTrace;
    private final LongUnaryOperator supplyReplyId;
    private final Function<String, JsonWebKey> lookupKey;
    private final ToLongFunction<JsonWebSignature> lookupAuthorization;
    private final SignalingExecutor executor;
    private final Long2ObjectHashMap<OAuthProxy> correlations;
    private final Writer writer;
    private final UnsafeBuffer extensionBuffer;
    private final int httpTypeId;

    public OAuthProxyFactory(
        OAuthConfiguration config,
        MutableDirectBuffer writeBuffer,
        LongUnaryOperator supplyInitialId,
        LongSupplier supplyTrace,
        ToIntFunction<String> supplyTypeId,
        LongUnaryOperator supplyReplyId,
        Long2ObjectHashMap<OAuthProxy> correlations,
        Function<String, JsonWebKey> lookupKey,
        ToLongFunction<JsonWebSignature> lookupAuthorization,
        SignalingExecutor executor,
        RouteManager router)
    {
        this.config = config;
        this.router = requireNonNull(router);
        this.writer = new Writer(writeBuffer);
        this.extensionBuffer = new UnsafeBuffer(new byte[writeBuffer.capacity()]);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.supplyTrace = requireNonNull(supplyTrace);
        this.correlations = correlations;
        this.lookupKey = lookupKey;
        this.lookupAuthorization = lookupAuthorization;
        this.executor = executor;
        this.httpTypeId = supplyTypeId.applyAsInt("http");
        for(int i = 0; i < inFlightAuthorizationsByRealm.length; i++)
        {
            inFlightAuthorizationsByRealm[i] = new Long2ObjectHashMap<>();
        }
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
            newStream = newInitialStream(begin, source);
        }
        else
        {
            newStream = newReplyStream(begin, source);
        }

        return newStream;
    }

    private MessageConsumer newInitialStream(
        final BeginFW begin,
        final MessageConsumer acceptReply)
    {
        final long acceptAuthorization = begin.authorization();
        final JsonWebSignature verified = verifiedSignature(begin);

        long connectAuthorization = acceptAuthorization;
        if (verified != null)
        {
            connectAuthorization = lookupAuthorization.applyAsLong(verified);
        }

        final long acceptRouteId = begin.routeId();
        final MessagePredicate filter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(acceptRouteId, connectAuthorization, filter, this::wrapRoute);
        MessageConsumer newStream = null;

        if (route != null)
        {
            final long acceptInitialId = begin.streamId();
            final long traceId = begin.trace();
            final OctetsFW extension = begin.extension();

            long acceptReplyId = supplyReplyId.applyAsLong(acceptInitialId);
            long connectRouteId = route.correlationId();
            long connectInitialId = supplyInitialId.applyAsLong(connectRouteId);
            MessageConsumer connectInitial = router.supplyReceiver(connectInitialId);
            long connectReplyId = supplyReplyId.applyAsLong(connectInitialId);
            long expiresAtMillis = config.expireInFlightRequests() ? expiresAtMillis(verified) : EXPIRES_NEVER;

            modifyAuthorizationState(begin, verified, connectAuthorization, expiresAtMillis);

            OAuthProxy initialStream = new OAuthProxy(acceptReply, acceptRouteId, acceptInitialId, acceptAuthorization,
                    connectInitial, connectRouteId, connectInitialId, connectAuthorization,
                    acceptInitialId, connectReplyId, expiresAtMillis);

            OAuthProxy replyStream = new OAuthProxy(connectInitial, connectRouteId, connectReplyId, connectAuthorization,
                    acceptReply, acceptRouteId, acceptReplyId, acceptAuthorization,
                    acceptInitialId, connectReplyId, expiresAtMillis);

            correlations.put(connectReplyId, replyStream);
            router.setThrottle(acceptReplyId, replyStream::onThrottleMessage);

            writer.doBegin(connectInitial, connectRouteId, connectInitialId, traceId,
                    connectAuthorization, extension);
            router.setThrottle(connectInitialId, initialStream::onThrottleMessage);

            newStream = initialStream::onStreamMessage;
        }

        return newStream;
    }

    private MessageConsumer newReplyStream(
        final BeginFW begin,
        final MessageConsumer sender)
    {
        final long connectReplyId = begin.streamId();
        final long traceId = begin.trace();
        final long authorization = begin.authorization();
        final OctetsFW extension = begin.extension();

        OAuthProxy replyStream = correlations.remove(connectReplyId);

        MessageConsumer newStream = null;

        if (replyStream != null)
        {
            MessageConsumer acceptReply = replyStream.target;
            long acceptRouteId = replyStream.targetRouteId;
            long acceptReplyId = replyStream.targetStreamId;
// TODO: change to not decrement before token is actually expired or successfully replies
//            System.out.println("replyStream: " + replyStream);
//            try
//            {
//                final long sourceAuthorization = replyStream.sourceAuthorization;
//                final int realmId = (int) ((sourceAuthorization & REALM_MASK) >> 48);
//                final JwtClaims claims = JwtClaims.parse(signature.getPayload());
//                final String subject = claims.getSubject();
//                if(subject != null)
//                {
//                    final Map<String, OAuthAccessGrant> authStateMap = inFlightAuthorizationsByRealm[realmId]
//                            .computeIfAbsent(begin.affinity(), g -> new IdentityHashMap<>());
//                    final OAuthAccessGrant authState = authStateMap.get(subject.intern());
//                    if (authState != null)
//                    {
//                        System.out.println("Dec ref count");
//                        authState.decrementReferenceCount();
//                    }
//                }
//            } catch (MalformedClaimException | JoseException | InvalidJwtException e)
//            {
//                e.printStackTrace();
//            }

            writer.doBegin(acceptReply, acceptRouteId, acceptReplyId, traceId, authorization, extension);

            newStream = replyStream::onStreamMessage;
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

    private void modifyAuthorizationState(
        BeginFW begin,
        JsonWebSignature verified,
        long connectAuthorization,
        long expiresAtMillis)
    {
        try
        {
            final int realmId = (int) ((connectAuthorization & REALM_MASK) >> 48);
            if(verified != null)
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                final String subject = claims.getSubject();
                if(subject != null)
                {
                    final Map<String, OAuthAccessGrant> authStateMap = inFlightAuthorizationsByRealm[realmId]
                            .computeIfAbsent(begin.affinity(), g -> new IdentityHashMap<>());
                    final OAuthAccessGrant authState = supplyAuthState(authStateMap, subject,
                            connectAuthorization, expiresAtMillis);

                    authState.referenceCount++;
                    if(authStateMap.containsKey(subject.intern()))
                    {
                        final long authStateAuthorization = authState.authorization;

                        if((authStateAuthorization & connectAuthorization) == authStateAuthorization &&
                                expiresAtMillis > authState.expiresAt)
                        {
                            authState.expiresAt = expiresAtMillis;
                        }
                    }
                    else
                    {
                        authStateMap.put(subject.intern(), authState);
                    }
                }
            }
        }
        catch (InvalidJwtException | JoseException | MalformedClaimException e)
        {
            // TODO: diagnostics?
        }
    }

    private OAuthAccessGrant supplyAuthState(
        Map<String, OAuthAccessGrant> authStateMap,
        String subject,
        long connectAuthorization,
        long expiresAtMillis)
    {
        final OAuthAccessGrant authState;
        if(authStateMap.containsKey(subject.intern()))
        {
            authState = authStateMap.get(subject.intern());
        }
        else
        {
            authState = new OAuthAccessGrant(connectAuthorization, expiresAtMillis);
        }

        return authState;
    }

    private static long expiresAtMillis(
        JsonWebSignature verified)
    {
        long expiresAtMillis = EXPIRES_NEVER;

        if (verified != null)
        {
            try
            {
                JwtClaims claims = JwtClaims.parse(verified.getPayload());
                NumericDate expirationTime = claims.getExpirationTime();
                if (expirationTime != null)
                {
                    expiresAtMillis = expirationTime.getValueInMillis();
                }
            }
            catch (MalformedClaimException | InvalidJwtException | JoseException ex)
            {
                expiresAtMillis = EXPIRES_IMMEDIATELY;
            }
        }

        return expiresAtMillis;
    }

    private final class OAuthAccessGrant
    {
        private long authorization;
        private long expiresAt;
        private int referenceCount;

        private OAuthAccessGrant(
            long authorization,
            long expiresAt)
        {
            this.authorization = authorization;
            this.expiresAt = expiresAt;
        }

        // TODO: inc/dec refCount based off of incoming/outgoing resp/req. if reach 0 refCount, then remove this auth from map

//        private void decrementReferenceCount()
//        {
//            referenceCount--;
//            if(referenceCount == 0)
//            {
//                cleanup();
//            }
//        }

//        private void cleanup()
//        {
//        // TODO: do NOT want to cleanup before the token actually expires. need to keep this reference to check if can update
//            System.out.println("Cleaning up reference.");
//            for(int i = 0; i < inFlightAuthorizationsByRealm.length; i++)
//            {
//                inFlightAuthorizationsByRealm[i].values()
//                                                .forEach(im -> im.values()
//                                                                 .removeIf(state -> state == this));
////                System.out.println("inFlightAuthorizationsByRealm: " + Arrays.toString(inFlightAuthorizationsByRealm));
//            }
//        }

        @Override
        public String toString()
        {
            return String.format("OAuthAccessGrant=[authorization=%d, expiresAt=%d, referenceCount=%d]",
                                  authorization, expiresAt, referenceCount);
        }
    }

    final class OAuthProxy
    {
        private final MessageConsumer source;
        private final long sourceRouteId;
        private final long sourceStreamId;
        private final long sourceAuthorization;
        private final MessageConsumer target;
        private final long targetRouteId;
        private final long targetStreamId;
        private final long targetAuthorization;
        private final long acceptInitialId;
        private final long connectReplyId;

        private Future<?> expiryFuture;

        private OAuthProxy(
            MessageConsumer source,
            long sourceRouteId,
            long sourceId,
            long sourceAuthorization,
            MessageConsumer target,
            long targetRouteId,
            long targetId,
            long targetAuthorization,
            long acceptInitialId,
            long connectReplyId,
            long expiresAtMillis)
        {
            this.source = source;
            this.sourceRouteId = sourceRouteId;
            this.sourceStreamId = sourceId;
            this.sourceAuthorization = sourceAuthorization;
            this.target = target;
            this.targetRouteId = targetRouteId;
            this.targetStreamId = targetId;
            this.targetAuthorization = targetAuthorization;
            this.acceptInitialId = acceptInitialId;
            this.connectReplyId = connectReplyId;

            if (expiresAtMillis != EXPIRES_NEVER)
            {
                final long delay = expiresAtMillis - System.currentTimeMillis();

                this.expiryFuture = executor.schedule(delay, MILLISECONDS, targetRouteId, targetStreamId, TOKEN_EXPIRED_SIGNAL);
            }
        }

        private void onStreamMessage(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case BeginFW.TYPE_ID:
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                onBegin(begin);
                break;
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
                writer.doReset(source, sourceRouteId, sourceStreamId, supplyTrace.getAsLong(), sourceAuthorization);
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
            case SignalFW.TYPE_ID:
                final SignalFW signal = signalRO.wrap(buffer, index, index + length);
                onSignal(signal);
                break;
            default:
                // ignore
                break;
            }
        }

        private void onBegin(
            BeginFW begin)
        {
        }

        private void onData(
            DataFW data)
        {
            final long traceId = data.trace();
            final int padding = data.padding();
            final long authorization = data.authorization();
            final long groupId = data.groupId();
            final OctetsFW payload = data.payload();
            final OctetsFW extension = data.extension();

            writer.doData(target, targetRouteId, targetStreamId, traceId,
                          authorization, groupId, padding, payload, extension);
        }

        private void onEnd(
            EndFW end)
        {
            final long traceId = end.trace();
            final OctetsFW extension = end.extension();

            writer.doEnd(target, targetRouteId, targetStreamId, traceId, targetAuthorization, extension);

            cancelTimerIfNecessary();
        }

        private void onAbort(
            AbortFW abort)
        {
            final long traceId = abort.trace();

            writer.doAbort(target, targetRouteId, targetStreamId, traceId, targetAuthorization);

            cleanupCorrelationIfNecessary();
            cancelTimerIfNecessary();
        }

        private void onWindow(
            WindowFW window)
        {
            final int credit = window.credit();
            final long traceId = window.trace();
            final int padding = window.padding();
            final long groupId = window.groupId();

            writer.doWindow(source, sourceRouteId, sourceStreamId, traceId, sourceAuthorization, credit, padding, groupId);
        }

        private void onReset(
            ResetFW reset)
        {
            final long traceId = reset.trace();

            writer.doReset(source, sourceRouteId, sourceStreamId, traceId, sourceAuthorization);

            cleanupCorrelationIfNecessary();
            cancelTimerIfNecessary();
        }

        private void onSignal(
            SignalFW signal)
        {
            final long signalId = signal.signalId();

            if (signalId == TOKEN_EXPIRED_SIGNAL &&
                !tryExtendAuthStateExpiration((int) ((sourceAuthorization & REALM_MASK) >> 48)))
            {
                final long traceId = signal.trace();
                writer.doReset(source, sourceRouteId, sourceStreamId, traceId, sourceAuthorization);

                final boolean replyNotStarted = cleanupCorrelationIfNecessary();

                if (sourceStreamId == connectReplyId && replyNotStarted)
                {
                    final HttpBeginExFW httpBeginEx = httpBeginExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                            .typeId(httpTypeId)
                            .headersItem(h -> h.name(":status").value("401"))
                            .build();

                    writer.doBegin(target, targetRouteId, targetStreamId, traceId, targetAuthorization, httpBeginEx);
                    writer.doEnd(target, targetRouteId, targetStreamId, traceId, targetAuthorization, octetsRO);
                }
                else
                {
                    writer.doAbort(target, targetRouteId, targetStreamId, traceId, targetAuthorization);
                }
            }
        }

        private boolean tryExtendAuthStateExpiration(
            int sourceRealmId)
        {
            boolean extendedExpiration = false;

            try
            {
                final JwtClaims claims = JwtClaims.parse(signature.getPayload());
                final String subject = claims.getSubject();
                final Map<String, OAuthAccessGrant> authStateMap = lookupAuthState(sourceRealmId, subject);

                if(authStateMap != null)
                {
                    final OAuthAccessGrant authState = authStateMap.get(subject.intern());
                    final long delay = authState.expiresAt - System.currentTimeMillis();

                    extendedExpiration = delay >= 0;

                    if(extendedExpiration)
                    {
                        this.expiryFuture = executor.schedule(delay, MILLISECONDS,
                                targetRouteId, targetStreamId, TOKEN_EXPIRED_SIGNAL);
                    }
                }
            }
            catch (InvalidJwtException | JoseException | MalformedClaimException e)
            {
                // TODO: diagnostics?
            }
            return extendedExpiration;
        }

        private Map<String, OAuthAccessGrant> lookupAuthState(
            int sourceRealmId,
            String subject)
        {
            return inFlightAuthorizationsByRealm[sourceRealmId].values()
                                                               .stream()
                                                               .filter(map -> map.containsKey(subject.intern()))
                                                               .findFirst()
                                                               .orElse(null);
        }

        private boolean cleanupCorrelationIfNecessary()
        {
            final OAuthProxy correlated = correlations.remove(connectReplyId);
            if (correlated != null)
            {
                router.clearThrottle(acceptInitialId);
                // TODO: add authstate cleanup here
            }

            return correlated != null;
        }

        private void cancelTimerIfNecessary()
        {
            if (expiryFuture != null)
            {
                expiryFuture.cancel(true);
                expiryFuture = null;
            }
        }

        @Override
        public String toString()
        {
            return String.format("OAuthProxy - {sourceRouteId=%d, sourceStreamId=%d, sourceAuthorization=%d, targetRouteId=%d, " +
                    "targetStreamId=%d, targetAuthorization=%d, acceptInitialId=%d, connectReplyId=%d}",
                    sourceRouteId, sourceStreamId, sourceAuthorization, targetRouteId, targetStreamId, targetAuthorization,
                    acceptInitialId, connectReplyId);
        }
    }

    private JsonWebSignature verifiedSignature(
        BeginFW begin)
    {
        JsonWebSignature verified = null;

        final String token = bearerToken(begin);
        if (token != null)
        {
            try
            {
                signature.setCompactSerialization(token);
                final String kid = signature.getKeyIdHeaderValue();
                final String algorithm = signature.getAlgorithmHeaderValue();
                final JsonWebKey key = lookupKey.apply(kid);
                if (algorithm != null && key != null && algorithm.equals(key.getAlgorithm()))
                {
                    signature.setKey(null);
                    signature.setKey(key.getKey());

                    final JwtClaims claims = JwtClaims.parse(signature.getPayload());
                    final NumericDate expirationTime = claims.getExpirationTime();
                    final NumericDate notBefore = claims.getNotBefore();
                    final long now = System.currentTimeMillis();
                    if ((expirationTime == null || now <= expirationTime.getValueInMillis()) &&
                        (notBefore == null || now >= notBefore.getValueInMillis()) &&
                        signature.verifySignature())
                    {
                        verified = signature;
                    }
                }
            }
            catch (JoseException | MalformedClaimException | InvalidJwtException ex)
            {
                // TODO: diagnostics?
            }
        }

        return verified;
    }

    private String bearerToken(
        BeginFW begin)
    {
        String token = null;

        final HttpBeginExFW beginEx = begin.extension().get(httpBeginExRO::tryWrap);
        if (beginEx != null)
        {
            final HttpHeaderFW path = beginEx.headers().matchFirst(h -> BufferUtil.equals(h.name(), PATH));
            if (path != null)
            {
                final String16FW value = path.value();
                final int queryAt = indexOfBytes(value, QUERY_PREFIX);
                if (queryAt != -1)
                {
                    final String query = path.value().asString().substring(queryAt);
                    final Matcher matcher = QUERY_PARAMS.matcher(query);
                    if (matcher.matches())
                    {
                        token = matcher.group(1);
                    }
                }
            }

            final HttpHeaderFW authorization = beginEx.headers().matchFirst(h -> BufferUtil.equals(h.name(), AUTHORIZATION));
            if (authorization != null)
            {
                final String16FW value = authorization.value();

                final int tokenAt = BufferUtil.limitOfBytes(value, BEARER_PREFIX);

                if (tokenAt > 0)
                {
                    final DirectBuffer buffer = value.buffer();
                    final int limit = value.limit();
                    token = buffer.getStringWithoutLengthUtf8(tokenAt, limit - tokenAt);
                }
            }
        }

        return token;
    }
}
