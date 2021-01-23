/**
 * Copyright 2016-2020 The Reaktivity Project
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

import static java.lang.Integer.parseInt;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.reaktivity.nukleus.concurrent.Signaler.NO_CANCEL_ID;
import static org.reaktivity.nukleus.oauth.internal.Capabilities.canChallenge;
import static org.reaktivity.nukleus.oauth.internal.util.BufferUtil.indexOfBytes;

import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.MutableInteger;
import org.agrona.concurrent.UnsafeBuffer;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.reaktivity.nukleus.concurrent.Signaler;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.oauth.internal.OAuthConfiguration;
import org.reaktivity.nukleus.oauth.internal.types.Array32FW;
import org.reaktivity.nukleus.oauth.internal.types.Flyweight;
import org.reaktivity.nukleus.oauth.internal.types.HttpHeaderFW;
import org.reaktivity.nukleus.oauth.internal.types.OctetsFW;
import org.reaktivity.nukleus.oauth.internal.types.String16FW;
import org.reaktivity.nukleus.oauth.internal.types.String8FW;
import org.reaktivity.nukleus.oauth.internal.types.control.RouteFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.DataFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.EndFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.FlushFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.HttpBeginExFW;
import org.reaktivity.nukleus.oauth.internal.types.stream.HttpChallengeExFW;
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

    private static final int GRANT_VALIDATION_SIGNAL = 1;

    private static final long REALM_MASK = 0xFFFF_000000000000L;

    private static final int SCOPE_BITS = 48;

    private static final Consumer<String> NOOP_CLEANER = s -> {};

    private static final Pattern QUERY_PARAMS = Pattern.compile("(?:\\?|.*?&)access_token=([^&#]+)(?:&.*)?");

    private static final String END_CHALLENGE_TYPE = "application/x-challenge-response";

    private static final byte[] BEARER_PREFIX = "Bearer ".getBytes(US_ASCII);
    private static final byte[] QUERY_PREFIX = "?".getBytes(US_ASCII);
    private static final byte[] AUTHORIZATION = "authorization".getBytes(US_ASCII);
    private static final byte[] PATH = ":path".getBytes(US_ASCII);

    private static final String8FW HEADER_NAME_METHOD = new String8FW(":method");
    private static final String8FW HEADER_NAME_CONTENT_TYPE = new String8FW("content-type");
    private static final String8FW HEADER_NAME_STATUS = new String8FW(":status");
    private static final String8FW HEADER_NAME_ACCESS_CONTROL_ALLOW_METHODS = new String8FW("access-control-allow-methods");
    private static final String8FW HEADER_NAME_ACCESS_CONTROL_ALLOW_HEADERS = new String8FW("access-control-allow-headers");
    private static final String8FW HEADER_NAME_ACCESS_CONTROL_REQUEST_METHOD = new String8FW("access-control-request-method");
    private static final String8FW HEADER_NAME_ACCESS_CONTROL_REQUEST_HEADERS = new String8FW("access-control-request-headers");

    private static final String16FW HEADER_VALUE_STATUS_204 = new String16FW("204");
    private static final String16FW HEADER_VALUE_METHOD_OPTIONS = new String16FW("OPTIONS");
    private static final String16FW HEADER_VALUE_METHOD_POST = new String16FW("POST");

    private static final String16FW CHALLENGE_RESPONSE_METHOD = HEADER_VALUE_METHOD_POST;
    private static final String16FW CHALLENGE_RESPONSE_CONTENT_TYPE = new String16FW("application/x-challenge-response");

    private static final String16FW CORS_PREFLIGHT_METHOD = HEADER_VALUE_METHOD_OPTIONS;
    private static final String16FW CORS_ALLOWED_METHODS = HEADER_VALUE_METHOD_POST;
    private static final String16FW CORS_ALLOWED_HEADERS = new String16FW("authorization,content-type");

    private final RouteFW routeRO = new RouteFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final AbortFW abortRO = new AbortFW();
    private final FlushFW flushRO = new FlushFW();

    private final OctetsFW octetsRO = new OctetsFW().wrap(new UnsafeBuffer(new byte[0]), 0, 0);

    private final HttpBeginExFW httpBeginExRO = new HttpBeginExFW();
    private final HttpBeginExFW.Builder httpBeginExRW = new HttpBeginExFW.Builder();

    private final HttpChallengeExFW.Builder httpChallengeExRW = new HttpChallengeExFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();
    private final SignalFW signalRO = new SignalFW();

    private final JsonWebSignature signature = new JsonWebSignature();

    private final Long2ObjectHashMap<Map<String, OAuthAccessGrant>>[] grantsBySubjectByAffinityPerRealm;

    private final OAuthConfiguration config;
    private final RouteManager router;
    private final LongUnaryOperator supplyInitialId;
    private final LongSupplier supplyTraceId;
    private final LongUnaryOperator supplyReplyId;
    private final Function<String, JsonWebKey> lookupKey;
    private final ToLongFunction<JsonWebSignature> lookupAuthorization;
    private final Signaler signaler;
    private final Long2ObjectHashMap<OAuthProxy> correlations;
    private final Writer writer;
    private final UnsafeBuffer extensionBuffer;
    private final int httpTypeId;

    private final String challengeTimeoutClaimName;

    public OAuthProxyFactory(
        OAuthConfiguration config,
        MutableDirectBuffer writeBuffer,
        LongUnaryOperator supplyInitialId,
        LongSupplier supplyTraceId,
        ToIntFunction<String> supplyTypeId,
        LongUnaryOperator supplyReplyId,
        Function<String, JsonWebKey> lookupKey,
        ToLongFunction<JsonWebSignature> lookupAuthorization,
        Signaler signaler,
        RouteManager router)
    {
        this.config = config;
        this.router = requireNonNull(router);
        this.writer = new Writer(writeBuffer);
        this.extensionBuffer = new UnsafeBuffer(new byte[writeBuffer.capacity()]);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.supplyTraceId = requireNonNull(supplyTraceId);
        this.correlations = new Long2ObjectHashMap<>();
        this.lookupKey = lookupKey;
        this.lookupAuthorization = lookupAuthorization;
        this.signaler = signaler;
        this.httpTypeId = supplyTypeId.applyAsInt("http");
        this.grantsBySubjectByAffinityPerRealm = initGrantsBySubjectByAffinityPerRealm();
        this.challengeTimeoutClaimName = String.format("%s%s", config.getCanonicalClaimNamespace(),
            config.getClaimNameChallengeTimeout());
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
        final long acceptRouteId = begin.routeId();
        final long acceptInitialId = begin.streamId();
        final long acceptSeq = begin.sequence();
        final long acceptAck = begin.acknowledge();
        final int acceptMax = begin.maximum();
        final long affinity = begin.affinity();
        final OctetsFW extension = begin.extension();
        final HttpBeginExFW httpBeginEx = extension.get(httpBeginExRO::tryWrap);

        final JsonWebSignature verified = verifiedSignature(begin);

        long connectAuthorization = acceptAuthorization;
        if (verified != null)
        {
            connectAuthorization = lookupAuthorization.applyAsLong(verified);
        }

        final String subject = resolveSubject(verified);
        final long expiresAtMillis = config.expireInFlightRequests() ? expiresAtMillis(verified) : EXPIRES_NEVER;
        final int realmId = (int) ((connectAuthorization & REALM_MASK) >> SCOPE_BITS);

        final MessagePredicate filter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(acceptRouteId, connectAuthorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (isChallengeResponseRequest(httpBeginEx))
        {
            final long newTraceId = supplyTraceId.getAsLong();
            final long acceptReplyId = supplyReplyId.applyAsLong(acceptInitialId);
            final long challengeTimeout = resolveChallengeTimeout(verified);
            final OAuthAccessGrant grant = lookupGrant(realmId, affinity, subject);
            if (grant != null)
            {
                grant.reauthorize(subject, connectAuthorization, expiresAtMillis, challengeTimeout);
            }

            writer.doWindow(acceptReply, acceptRouteId, acceptInitialId, acceptSeq, acceptAck, acceptMax,
                    newTraceId, 0L, 0, 0, 0);

            final HttpBeginExFW newHttpBeginEx = httpBeginExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                    .typeId(httpTypeId)
                    .headers(OAuthProxyFactory::setChallengeResponseHeaders)
                    .build();

            writer.doBegin(acceptReply, acceptRouteId, acceptReplyId, 0L, 0L, 0, newTraceId, 0L, affinity, newHttpBeginEx);
            writer.doEnd(acceptReply, acceptRouteId, acceptReplyId, 0L, 0L, 0, newTraceId, 0L, octetsRO);

            newStream = (t, b, i, l) -> {};
        }
        else if (route != null)
        {
            final long traceId = begin.traceId();

            final long acceptReplyId = supplyReplyId.applyAsLong(acceptInitialId);
            final long connectRouteId = route.correlationId();
            final long connectInitialId = supplyInitialId.applyAsLong(connectRouteId);
            final MessageConsumer connectInitial = router.supplyReceiver(connectInitialId);
            final long connectReplyId = supplyReplyId.applyAsLong(connectInitialId);

            final boolean isCorsPreflight = isCorsPreflightRequest(extension.get(httpBeginExRO::tryWrap));

            final long challengeTimeout = resolveChallengeTimeout(verified);
            final OAuthAccessGrant grant = supplyGrant(realmId, affinity, subject);
            grant.reauthorize(subject, connectAuthorization, expiresAtMillis, challengeTimeout);

            final MutableInteger acceptCapabilities = new MutableInteger();
            final MutableInteger connectCapabilities = new MutableInteger();

            final OAuthProxy initialStream = new OAuthProxy(
                    acceptReply, acceptRouteId, acceptInitialId, acceptSeq, acceptAck, acceptAuthorization, acceptCapabilities,
                    connectRouteId, connectInitialId, connectAuthorization, connectCapabilities,
                    connectReplyId, expiresAtMillis, 0, grant, isCorsPreflight, connectInitial, acceptReplyId);

            final OAuthProxy replyStream = new OAuthProxy(
                    connectInitial, connectRouteId, connectReplyId, 0L, 0L, connectAuthorization, connectCapabilities,
                    acceptRouteId, acceptReplyId, acceptAuthorization, acceptCapabilities,
                    connectReplyId, expiresAtMillis, challengeTimeout, grant, isCorsPreflight, acceptReply, acceptReplyId);

            correlations.put(connectReplyId, replyStream);
            router.setThrottle(acceptReplyId, replyStream::onThrottleMessage);

            writer.doBegin(connectInitial, connectRouteId, connectInitialId, acceptSeq, acceptAck, acceptMax, traceId,
                    connectAuthorization, affinity, extension);
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
        final long connectSeq = begin.sequence();
        final long connectAck = begin.acknowledge();
        final int connectMax = begin.maximum();
        final long traceId = begin.traceId();
        final long authorization = begin.authorization();
        final long affinity = begin.affinity();
        final OctetsFW extension = begin.extension();
        final HttpBeginExFW httpBeginEx = extension.get(httpBeginExRO::tryWrap);

        OAuthProxy replyStream = correlations.remove(connectReplyId);

        MessageConsumer newStream = null;

        if (replyStream != null)
        {
            MessageConsumer acceptReply = replyStream.target;
            long acceptRouteId = replyStream.targetRouteId;
            long acceptReplyId = replyStream.targetStreamId;

            Flyweight beginEx = extension;
            if (replyStream.isCorsPreflight)
            {
                final HttpBeginExFW.Builder newHttpBeginEx =
                        httpBeginExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                                     .typeId(httpTypeId);

                if (httpBeginEx != null)
                {
                    httpBeginEx.headers().forEach(h -> newHttpBeginEx.headersItem(i -> i.name(h.name()).value(h.value())));
                }

                setCorsPreflightResponseHeaders(newHttpBeginEx);

                beginEx = newHttpBeginEx.build();
            }

            replyStream.sourceSeq = connectSeq;
            replyStream.targetAck = connectAck;

            writer.doBegin(acceptReply, acceptRouteId, acceptReplyId, connectSeq, connectAck, connectMax, traceId,
                    authorization, affinity, beginEx);

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

    private long resolveChallengeTimeout(
        JsonWebSignature verified)
    {
        long challengeTimeout = 0;

        try
        {
            if (verified != null)
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                final Object claimValue = claims.getClaimValue(challengeTimeoutClaimName);
                if (claimValue != null)
                {
                    challengeTimeout = SECONDS.toMillis(parseInt(claimValue.toString()));
                }
            }
        }
        catch (InvalidJwtException | JoseException | NumberFormatException e)
        {
            // invalid token
        }
        return challengeTimeout;
    }

    private OAuthAccessGrant supplyGrant(
        final int realmIndex,
        final long affinityId,
        final String subject)
    {
        OAuthAccessGrant grant;

        if (affinityId != 0L && subject != null)
        {
            final Map<String, OAuthAccessGrant> grantsBySubject = supplyGrantsBySubject(realmIndex, affinityId);
            final String subjectKey = subject.intern();
            grant = grantsBySubject.computeIfAbsent(subjectKey, s -> new OAuthAccessGrant(grantsBySubject::remove));
        }
        else
        {
            grant = new OAuthAccessGrant();
        }

        return grant;
    }

    private Map<String, OAuthAccessGrant> supplyGrantsBySubject(
        final int realmIndex,
        final long affinityId)
    {
        final Long2ObjectHashMap<Map<String, OAuthAccessGrant>> grantsBySubjectByAffinity =
                grantsBySubjectByAffinityPerRealm[realmIndex];
        return grantsBySubjectByAffinity.computeIfAbsent(affinityId, a -> new IdentityHashMap<>());
    }

    private OAuthAccessGrant lookupGrant(
        final int realmIndex,
        final long affinityId,
        final String subject)
    {
        OAuthAccessGrant grant = null;

        if (affinityId != 0L && subject != null)
        {
            final Map<String, OAuthAccessGrant> grantsBySubject = lookupGrantsBySubject(realmIndex, affinityId);
            if (grantsBySubject != null)
            {
                final String subjectKey = subject.intern();
                grant = grantsBySubject.get(subjectKey);
            }
        }

        return grant;
    }

    private Map<String, OAuthAccessGrant> lookupGrantsBySubject(
        final int realmIndex,
        final long affinityId)
    {
        final Long2ObjectHashMap<Map<String, OAuthAccessGrant>> grantsBySubjectByAffinity =
                grantsBySubjectByAffinityPerRealm[realmIndex];
        return grantsBySubjectByAffinity.get(affinityId);
    }

    private final class OAuthAccessGrant
    {
        private String subject;
        private long authorization;
        private long expiresAtMillis;
        private long challengeTimeoutMillis;
        private long lastChallengedAt;
        private int referenceCount;
        private Consumer<String> cleaner;

        private OAuthAccessGrant(
            Consumer<String> cleaner)
        {
            this.cleaner = cleaner;
        }

        private OAuthAccessGrant()
        {
            this.cleaner = NOOP_CLEANER;
        }

        private boolean reauthorize(
            String subject,
            long connectAuthorization,
            long expiresAtMillis,
            long challengeTimeoutMillis)
        {
            boolean reauthorized = false;
            if (referenceCount > 0)
            {
                final long grantAuthorization = authorization;
                reauthorized = (grantAuthorization & connectAuthorization) == grantAuthorization &&
                    expiresAtMillis > this.expiresAtMillis;

                if (reauthorized)
                {
                    this.expiresAtMillis = expiresAtMillis;
                    this.challengeTimeoutMillis = challengeTimeoutMillis;
                }
            }
            else
            {
                this.subject = subject != null ? subject.intern() : null;
                this.authorization = connectAuthorization;
                this.expiresAtMillis = expiresAtMillis;
                this.challengeTimeoutMillis = challengeTimeoutMillis;
            }
            return reauthorized;
        }

        private void acquire()
        {
            assert cleaner != null;
            referenceCount++;
        }

        private void release()
        {
            assert cleaner != null && referenceCount > 0;
            referenceCount--;
            if (referenceCount == 0)
            {
                if (subject != null)
                {
                    cleaner.accept(subject);
                }
                cleaner = null;
            }
        }

        private long challenge(
            long now,
            long traceId,
            LongConsumer doChallenge)
        {
            long challengeAt = expiresAtMillis;
            final long challengeAfter = this.expiresAtMillis - this.challengeTimeoutMillis;
            if (challengeAfter <= now && now < expiresAtMillis)
            {
                // Challenge now if not already sent
                if (lastChallengedAt < challengeAfter)
                {
                    lastChallengedAt = now;
                    doChallenge.accept(traceId);
                }
                assert lastChallengedAt >= challengeAfter;
            }
            else if (now < challengeAfter)
            {
                // reassess at challenge-after
                challengeAt = challengeAfter;
            }
            return challengeAt;
        }
    }

    private final class OAuthProxy
    {
        private final MessageConsumer source;
        private final long sourceRouteId;
        private final long sourceStreamId;
        private final long sourceAuthorization;
        private final MutableInteger sourceCapabilities;
        private final MessageConsumer target;
        private final long targetRouteId;
        private final long targetStreamId;
        private final long targetAuthorization;
        private final MutableInteger targetCapabailities;
        private final long acceptReplyId;
        private final long connectReplyId;
        private final OAuthAccessGrant grant;
        private final boolean isCorsPreflight;

        private long sourceSeq;
        private long targetAck;
        private int targetMax;

        private long sourceAffinity;
        private long cancelId = NO_CANCEL_ID;

        private OAuthProxy(
            MessageConsumer source,
            long sourceRouteId,
            long sourceId,
            long sourceSeq,
            long sourceAck,
            long sourceAuthorization,
            MutableInteger sourceCapabilities,
            long targetRouteId,
            long targetId,
            long targetAuthorization,
            MutableInteger targetCapabilities,
            long connectReplyId,
            long expiresAtMillis,
            long challengeTimeout,
            OAuthAccessGrant grant,
            boolean isCorsPreflight,
            MessageConsumer target,
            long acceptReplyId)
        {
            this.source = source;
            this.sourceRouteId = sourceRouteId;
            this.sourceStreamId = sourceId;
            this.sourceSeq = sourceSeq;
            this.targetAck = sourceAck;
            this.sourceAuthorization = sourceAuthorization;
            this.sourceCapabilities = sourceCapabilities;
            this.target = target;
            this.targetRouteId = targetRouteId;
            this.targetStreamId = targetId;
            this.targetAuthorization = targetAuthorization;
            this.targetCapabailities = targetCapabilities;
            this.acceptReplyId = acceptReplyId;
            this.connectReplyId = connectReplyId;
            this.grant = Objects.requireNonNull(grant);
            this.isCorsPreflight = isCorsPreflight;

            this.grant.acquire();

            assert challengeTimeout >= 0;
            if (expiresAtMillis != EXPIRES_NEVER)
            {
                final long challengeAt = expiresAtMillis - challengeTimeout;
                this.cancelId = signaler.signalAt(challengeAt, targetRouteId, targetStreamId, GRANT_VALIDATION_SIGNAL);
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
            case FlushFW.TYPE_ID:
                final FlushFW flush = flushRO.wrap(buffer, index, index + length);
                onFlush(flush);
                break;
            default:
                writer.doReset(source, sourceRouteId, sourceStreamId, sourceSeq, targetAck, targetMax,
                        supplyTraceId.getAsLong(), sourceAuthorization);
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
            final long sequence = begin.sequence();
            final long acknowledge = begin.acknowledge();
            final long affinity = begin.affinity();

            assert acknowledge <= sequence;
            assert sequence >= sourceSeq;

            sourceSeq = sequence;
            targetAck = acknowledge;

            assert targetAck <= sourceSeq;

            this.sourceAffinity = affinity;
        }

        private void onData(
            DataFW data)
        {
            final long sequence = data.sequence();
            final long acknowledge = data.acknowledge();
            final int maximum = data.maximum();
            final long traceId = data.traceId();
            final int reserved = data.reserved();
            final long authorization = data.authorization();
            final long budgetId = data.budgetId();
            final OctetsFW payload = data.payload();
            final OctetsFW extension = data.extension();

            assert acknowledge <= sequence;
            assert sequence >= sourceSeq;

            sourceSeq = sequence + reserved;

            assert targetAck <= sourceSeq;

            writer.doData(target, targetRouteId, targetStreamId, sequence, acknowledge, maximum, traceId,
                          authorization, budgetId, reserved, payload, extension);
        }

        private void onFlush(
            FlushFW flush)
        {
            final long sequence = flush.sequence();
            final long acknowledge = flush.acknowledge();
            final int maximum = flush.maximum();
            final long traceId = flush.traceId();
            final long budgetId = flush.budgetId();
            final int reserved = flush.reserved();

            assert acknowledge <= sequence;
            assert sequence >= sourceSeq;

            sourceSeq = sequence;

            assert targetAck <= sourceSeq;

            writer.doFlush(target, targetRouteId, targetStreamId, sequence, acknowledge, maximum,
                    traceId, targetAuthorization, budgetId, reserved);
        }

        private void onEnd(
            EndFW end)
        {
            final long sequence = end.sequence();
            final long acknowledge = end.acknowledge();
            final int maximum = end.maximum();
            final long traceId = end.traceId();
            final OctetsFW extension = end.extension();

            assert acknowledge <= sequence;
            assert sequence >= sourceSeq;

            sourceSeq = sequence;

            assert targetAck <= sourceSeq;

            // TODO: avoid sending request END when CORS response defaulted after request RESET
            writer.doEnd(target, targetRouteId, targetStreamId, sequence, acknowledge, maximum,
                    traceId, targetAuthorization, extension);

            cancelTimerIfNecessary();
        }

        private void onAbort(
            AbortFW abort)
        {
            final long sequence = abort.sequence();
            final long acknowledge = abort.acknowledge();
            final int maximum = abort.maximum();
            final long traceId = abort.traceId();

            assert acknowledge <= sequence;
            assert sequence >= sourceSeq;

            sourceSeq = sequence;

            assert targetAck <= sourceSeq;

            writer.doAbort(target, targetRouteId, targetStreamId, sequence, acknowledge, maximum,
                    traceId, targetAuthorization);

            cleanupCorrelationIfNecessary();
            cancelTimerIfNecessary();
        }

        private void onWindow(
            WindowFW window)
        {
            final long sequence = window.sequence();
            final long acknowledge = window.acknowledge();
            final int maximum = window.maximum();
            final long traceId = window.traceId();
            final long budgetId = window.budgetId();
            final int padding = window.padding();

            this.targetCapabailities.value = window.capabilities();

            assert acknowledge <= sequence;
            assert acknowledge >= targetAck;
            assert maximum >= targetMax;

            targetMax = maximum;
            targetAck = acknowledge;

            assert targetAck <= sourceSeq;

            writer.doWindow(source, sourceRouteId, sourceStreamId, sequence, acknowledge, maximum,
                    traceId, sourceAuthorization, budgetId, padding, this.targetCapabailities.value);
        }

        private void onReset(
            ResetFW reset)
        {
            final long sequence = reset.sequence();
            final long acknowledge = reset.acknowledge();
            final int maximum = reset.maximum();
            final long traceId = reset.traceId();

            final boolean replyNotStarted = cleanupCorrelationIfNecessary();

            assert acknowledge <= sequence;
            assert acknowledge >= targetAck;

            targetAck = acknowledge;

            assert targetAck <= sourceSeq;

            if (isCorsPreflight && sourceStreamId != connectReplyId && replyNotStarted)
            {
                writer.doWindow(source, sourceRouteId, sourceStreamId, sequence, acknowledge, maximum,
                        traceId, 0L, 0, 0, 0);

                final HttpBeginExFW.Builder httpBeginEx = httpBeginExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                        .typeId(httpTypeId);

                setCorsPreflightResponse(httpBeginEx);

                final long sourceReplyId = supplyReplyId.applyAsLong(sourceStreamId);
                writer.doBegin(source, sourceRouteId, sourceReplyId, 0L, 0L, 0, traceId, 0L, sourceAffinity, httpBeginEx.build());
                writer.doEnd(source, sourceRouteId, sourceReplyId, 0L, 0L, 0, traceId, 0L, octetsRO);
            }
            else
            {
                writer.doReset(source, sourceRouteId, sourceStreamId, sequence, acknowledge, maximum,
                        traceId, sourceAuthorization);
            }

            cancelTimerIfNecessary();
        }

        private void onSignal(
            SignalFW signal)
        {
            final long signalId = signal.signalId();

            switch ((int) signalId)
            {
            case GRANT_VALIDATION_SIGNAL:
                onGrantValidationSignal(signal);
                break;
            default:
                break;
            }
        }

        private void onGrantValidationSignal(
            SignalFW signal)
        {
            final long now = System.currentTimeMillis();
            long nextSignalAt = grant.expiresAtMillis;
            long nextCancelId = NO_CANCEL_ID;

            if (nextSignalAt > now)
            {
                if (canChallenge(sourceCapabilities.value))
                {
                    nextSignalAt = grant.challenge(now, signal.traceId(), this::doChallenge);
                }
                nextCancelId = signaler.signalAt(nextSignalAt, targetRouteId, targetStreamId, GRANT_VALIDATION_SIGNAL);
            }
            else
            {
                final long traceId = signal.traceId();
                writer.doReset(source, sourceRouteId, sourceStreamId, sourceSeq, targetAck, targetMax,
                        traceId, sourceAuthorization);

                final boolean replyNotStarted = cleanupCorrelationIfNecessary();

                if (sourceStreamId == connectReplyId && replyNotStarted)
                {
                    final HttpBeginExFW httpBeginEx = httpBeginExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                            .typeId(httpTypeId)
                            .headersItem(h -> h.name(HEADER_NAME_STATUS).value("401"))
                            .build();

                    writer.doBegin(target, targetRouteId, targetStreamId, sourceSeq, targetAck, targetMax,
                            traceId, targetAuthorization, sourceAffinity, httpBeginEx);
                    writer.doEnd(target, targetRouteId, targetStreamId, sourceSeq, targetAck, targetMax,
                            traceId, targetAuthorization, octetsRO);
                }
                else
                {
                    writer.doAbort(target, targetRouteId, targetStreamId, sourceSeq, targetAck, targetMax,
                            traceId, targetAuthorization);
                }

                grant.release();
            }

            this.cancelId = nextCancelId;
        }

        private void doChallenge(
            long traceId)
        {
            final HttpChallengeExFW httpChallengeEx = httpChallengeExRW.wrap(extensionBuffer, 0, extensionBuffer.capacity())
                    .typeId(httpTypeId)
                    .headersItem(h -> h.name(HEADER_NAME_METHOD).value(HEADER_VALUE_METHOD_POST))
                    .headersItem(h -> h.name(HEADER_NAME_CONTENT_TYPE).value(END_CHALLENGE_TYPE))
                    .build();

            writer.doChallenge(source, sourceRouteId, sourceStreamId, sourceSeq, targetAck, targetMax,
                    traceId, sourceAuthorization, httpChallengeEx);
        }

        private boolean cleanupCorrelationIfNecessary()
        {
            final OAuthProxy correlated = correlations.remove(connectReplyId);
            if (correlated != null)
            {
                router.clearThrottle(acceptReplyId);
            }

            return correlated != null;
        }

        private void cancelTimerIfNecessary()
        {
            if (cancelId != NO_CANCEL_ID)
            {
                signaler.cancel(cancelId);
                cancelId = NO_CANCEL_ID;
                grant.release();
            }
        }
    }

    private JsonWebSignature verifiedSignature(
        BeginFW begin)
    {
        final HttpBeginExFW httpBeginEx = begin.extension().get(httpBeginExRO::tryWrap);

        JsonWebSignature verified = null;

        final String token = bearerToken(httpBeginEx);
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
                // invalid token
            }
        }

        return verified;
    }

    private static String bearerToken(
        HttpBeginExFW httpBeginEx)
    {
        String token = null;

        if (httpBeginEx != null)
        {
            final Array32FW<HttpHeaderFW> headers = httpBeginEx.headers();

            final HttpHeaderFW authorization = headers.matchFirst(h -> BufferUtil.equals(h.name(), AUTHORIZATION));
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

            if (token == null)
            {
                final HttpHeaderFW path = headers.matchFirst(h -> BufferUtil.equals(h.name(), PATH));
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
            }
        }

        return token;
    }

    private static String resolveSubject(
        JsonWebSignature verified)
    {
        String subject = null;
        try
        {
            if (verified != null)
            {
                final JwtClaims claims = JwtClaims.parse(verified.getPayload());
                subject = claims.getSubject();
            }
        }
        catch (InvalidJwtException | JoseException | MalformedClaimException e)
        {
            // invalid token
        }
        return subject;
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

    @SuppressWarnings("unchecked")
    private static Long2ObjectHashMap<Map<String, OAuthAccessGrant>>[] initGrantsBySubjectByAffinityPerRealm()
    {
        final Long2ObjectHashMap<Map<String, OAuthAccessGrant>>[] grantsBySubjectByAffinityPerRealm = new Long2ObjectHashMap[16];
        Arrays.setAll(grantsBySubjectByAffinityPerRealm, i -> new Long2ObjectHashMap<>());
        return grantsBySubjectByAffinityPerRealm;
    }

    private static boolean isCorsPreflightRequest(
        HttpBeginExFW httpBeginEx)
    {
        return httpBeginEx != null &&
               httpBeginEx.headers().anyMatch(h -> HEADER_NAME_METHOD.equals(h.name()) &&
                                                   CORS_PREFLIGHT_METHOD.equals(h.value())) &&
               httpBeginEx.headers().anyMatch(h -> HEADER_NAME_ACCESS_CONTROL_REQUEST_METHOD.equals(h.name()) ||
                                                   HEADER_NAME_ACCESS_CONTROL_REQUEST_HEADERS.equals(h.name()));
    }

    private static void setCorsPreflightResponse(
        HttpBeginExFW.Builder httpBeginEx)
    {
        httpBeginEx.headersItem(h -> h.name(HEADER_NAME_STATUS).value(HEADER_VALUE_STATUS_204));
        setCorsPreflightResponseHeaders(httpBeginEx);
    }

    private static void setCorsPreflightResponseHeaders(
        HttpBeginExFW.Builder httpBeginEx)
    {
        httpBeginEx.headersItem(h -> h.name(HEADER_NAME_ACCESS_CONTROL_ALLOW_METHODS).value(CORS_ALLOWED_METHODS))
                   .headersItem(h -> h.name(HEADER_NAME_ACCESS_CONTROL_ALLOW_HEADERS).value(CORS_ALLOWED_HEADERS));
    }

    private static boolean isChallengeResponseRequest(
        HttpBeginExFW httpBeginEx)
    {
        return httpBeginEx != null &&
               httpBeginEx.headers().anyMatch(h -> HEADER_NAME_METHOD.equals(h.name()) &&
                                                   CHALLENGE_RESPONSE_METHOD.equals(h.value())) &&
               httpBeginEx.headers().anyMatch(h -> HEADER_NAME_CONTENT_TYPE.equals(h.name()) &&
                                                   CHALLENGE_RESPONSE_CONTENT_TYPE.equals(h.value()));
    }

    private static void setChallengeResponseHeaders(
        Array32FW.Builder<HttpHeaderFW.Builder, HttpHeaderFW> headers)
    {
        headers.item(h -> h.name(HEADER_NAME_STATUS).value(HEADER_VALUE_STATUS_204));
    }
}
