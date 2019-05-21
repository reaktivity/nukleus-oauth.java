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
package org.reaktivity.nukleus.oauth.internal.util;

import static org.agrona.BitUtil.SIZE_OF_BYTE;
import static org.agrona.BitUtil.SIZE_OF_SHORT;

import org.agrona.DirectBuffer;
import org.reaktivity.nukleus.oauth.internal.types.String16FW;
import org.reaktivity.nukleus.oauth.internal.types.StringFW;

public final class BufferUtil
{
    public static boolean equals(
        StringFW flyweight,
        byte[] value)
    {
        return equals(flyweight.buffer(), flyweight.offset() + SIZE_OF_BYTE, flyweight.limit(), value);
    }

    public static int limitOfBytes(
        String16FW flyweight,
        byte[] value)
    {
        final DirectBuffer buffer = flyweight.buffer();
        final int offset = flyweight.offset();
        final int limit = flyweight.limit();
        return limitOfBytes(buffer, offset + SIZE_OF_SHORT, limit, value);
    }

    public static int indexOfBytes(
        String16FW flyweight,
        byte[] value)
    {
        return Math.max(limitOfBytes(flyweight, value) - flyweight.offset() - value.length - SIZE_OF_SHORT, -1);
    }

    public static boolean equals(
        DirectBuffer buffer,
        int offset,
        int limit,
        byte[] value)
    {
        return (limit - offset == value.length &&
                limit == limitOfBytes(buffer, offset, limit, value));
    }

    public static int limitOfBytes(
        DirectBuffer buffer,
        int offset,
        int limit,
        byte[] value)
    {
        int matchedBytes = 0;

        for (int cursor = offset; cursor < limit; cursor++)
        {
            if (buffer.getByte(cursor) != value[matchedBytes])
            {
                matchedBytes = 0;
                continue;
            }

            if (value.length == ++matchedBytes)
            {
                return cursor + 1;
            }
        }

        return -1;
    }

    private BufferUtil()
    {
        // utility class, no instances
    }
}
