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
package org.reaktivity.nukleus.auth.jwt.internal.resolver;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.ErrorFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.ResolveFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.ResolvedFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.UnresolveFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.control.auth.UnresolvedFW;
import org.reaktivity.nukleus.function.MessageConsumer;

public class Resolver
{
    private final ResolveFW resolveRO = new ResolveFW();
    private final ResolvedFW.Builder resolvedRW = new ResolvedFW.Builder();
    private final UnresolveFW unresolveRO = new UnresolveFW();
    private final UnresolvedFW.Builder unresolvedRW = new UnresolvedFW.Builder();
    private final ErrorFW.Builder errorRW = new ErrorFW.Builder();

    private final Realms realms;

    public Resolver(Realms realms)
    {
        this.realms = realms;
    }

    public void resolve(
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer reply,
        MutableDirectBuffer replyBuffer)
    {
        ResolveFW resolve = resolveRO.wrap(buffer, index, index + length);
        long authorization = realms.resolve(resolve.realm().asString());
        if (authorization != 0L)
        {
            ResolvedFW resolved = resolvedRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(resolve.correlationId())
                    .authorization(authorization)
                    .build();
            reply.accept(ResolvedFW.TYPE_ID, resolved.buffer(), resolved.offset(), resolved.limit() - resolved.offset());
        }
        else
        {
            ErrorFW error = errorRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(resolve.correlationId())
                    .build();
            reply.accept(ErrorFW.TYPE_ID, error.buffer(), error.offset(), error.limit() - error.offset());
        }
    }

    public void unresolve(
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer reply,
        MutableDirectBuffer replyBuffer)
    {
        UnresolveFW unresolve = unresolveRO.wrap(buffer, index, index + length);
        if (realms.unresolve(unresolve.authorization()))
        {
            UnresolvedFW result = unresolvedRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(unresolve.correlationId())
                    .build();
            reply.accept(UnresolvedFW.TYPE_ID, result.buffer(), result.offset(), result.limit() - result.offset());
        }
        else
        {
            ErrorFW error = errorRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(unresolve.correlationId())
                    .build();
            reply.accept(ErrorFW.TYPE_ID, error.buffer(), error.offset(), error.limit() - error.offset());
        }
    }
}
