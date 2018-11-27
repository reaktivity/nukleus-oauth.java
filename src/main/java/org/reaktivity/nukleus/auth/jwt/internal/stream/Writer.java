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

import static java.nio.charset.StandardCharsets.UTF_8;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.auth.jwt.internal.types.OctetsFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.DataFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.EndFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.auth.jwt.internal.types.stream.WindowFW;
import org.reaktivity.nukleus.function.MessageConsumer;

public class Writer
{
    private static final DirectBuffer SOURCE_NAME_BUFFER = new UnsafeBuffer("auth-jwt".getBytes(UTF_8));

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();
    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();
    private final AbortFW.Builder abortRW = new AbortFW.Builder();

    private final MutableDirectBuffer writeBuffer;

    public Writer(MutableDirectBuffer writeBuffer)
    {
        this.writeBuffer = writeBuffer;
    }

    public void doBegin(
        MessageConsumer target,
        long targetId,
        long targetRef,
        long correlationId,
        long traceId,
        long authorization,
        OctetsFW extension)
    {
        BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                               .streamId(targetId)
                               .trace(traceId)
                               .authorization(authorization)
                               .source(SOURCE_NAME_BUFFER, 0, SOURCE_NAME_BUFFER.capacity())
                               .sourceRef(targetRef)
                               .correlationId(correlationId)
                               .extension(e -> e.set(extension))
                               .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());

    }

    public void doData(
        MessageConsumer target,
        long targetId,
        long traceId,
        long authorization,
        long groupId,
        int padding,
        OctetsFW payload,
        OctetsFW extension)
    {
        DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                            .streamId(targetId)
                            .trace(traceId)
                            .authorization(authorization)
                            .groupId(groupId)
                            .padding(padding)
                            .payload(payload)
                            .extension(e -> e.set(extension))
                            .build();

        target.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    public void doEnd(
        MessageConsumer target,
        long targetId,
        long traceId,
        OctetsFW extension)
    {
        EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                         .streamId(targetId)
                         .trace(traceId)
                         .extension(e -> e.set(extension))
                         .build();

        target.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    public void doAbort(
        MessageConsumer target,
        long targetId,
        long traceId)
    {
        AbortFW abort = abortRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .trace(traceId)
                .build();

        target.accept(abort.typeId(), abort.buffer(), abort.offset(), abort.sizeof());
    }

    public void doWindow(
        final MessageConsumer source,
        final long sourceId,
        final long traceId,
        final int credit,
        final int padding,
        final long groupId)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(sourceId)
                .trace(traceId)
                .credit(credit)
                .padding(padding)
                .groupId(groupId)
                .build();

        source.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    public void doReset(
        final MessageConsumer source,
        final long sourceId,
        final long traceId)
    {
        final ResetFW reset = resetRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(sourceId)
                                     .trace(traceId)
                                     .build();

        source.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

}
