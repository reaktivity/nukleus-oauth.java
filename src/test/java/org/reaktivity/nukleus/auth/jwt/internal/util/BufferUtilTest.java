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
package org.reaktivity.nukleus.auth.jwt.internal.util;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.Test;
import org.reaktivity.nukleus.auth.jwt.internal.types.StringFW;

public class BufferUtilTest
{
    @Test
    public void shouldEqualStringWhenValueAtStart()
    {
        DirectBuffer buffer = new UnsafeBuffer("cookie".getBytes(US_ASCII));
        assertTrue(BufferUtil.equals(buffer, 0, buffer.capacity(), "cookie".getBytes()));
    }

    @Test
    public void shouldEqualStringValueInMiddle()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice warm cookie cutter".getBytes(US_ASCII));
        assertTrue(BufferUtil.equals(buffer, 2, 6, "nice".getBytes()));
    }

    @Test
    public void shouldEqualStringFW()
    {
        MutableDirectBuffer buffer = new UnsafeBuffer("1234567890123456789012345678901234567890".getBytes());
        StringFW value = new StringFW.Builder().wrap(buffer, 5, 40)
                .set("cookie", US_ASCII)
                .build();
        assertTrue(BufferUtil.equals(value, "cookie".getBytes()));
    }

    @Test
    public void shouldReportUnequalString()
    {
        DirectBuffer buffer = new UnsafeBuffer("cookie".getBytes(US_ASCII));
        assertFalse(BufferUtil.equals(buffer, 0, buffer.capacity(), "cook".getBytes()));
    }

    @Test
    public void shouldReportUnequalStringFW()
    {
        MutableDirectBuffer buffer = new UnsafeBuffer("1234567890".getBytes());
        StringFW value = new StringFW.Builder().wrap(buffer, 0, 10)
                .set("cookie", US_ASCII)
                .build();
        assertFalse(BufferUtil.equals(value, "cookie890".getBytes()));
    }

    @Test
    public void shouldReportUnequalStringValueLongerThanBuffer()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice".getBytes(US_ASCII));
        assertFalse(BufferUtil.equals(buffer, 2, 6, "nicer".getBytes()));
    }

    @Test
    public void shouldReportUnequalStringFWValueLongerThanBuffer()
    {
        MutableDirectBuffer buffer = new UnsafeBuffer("1234567890".getBytes());
        StringFW value = new StringFW.Builder().wrap(buffer, 0, 10)
                .set("cookie", US_ASCII)
                .build();
        assertFalse(BufferUtil.equals(value, "cookies and cream".getBytes()));
    }

    @Test
    public void shouldReportUnequalWhenBothOfEqualLength()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice".getBytes(US_ASCII));
        assertFalse(BufferUtil.equals(buffer, 0, 6, "a nick".getBytes()));
    }

    @Test
    public void shouldLocateLimitWhenValueAtEndBuffer()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice warm cookie cutter".getBytes(US_ASCII));
        assertEquals(buffer.capacity(), BufferUtil.limitOfBytes(buffer, 0, buffer.capacity(), "cutter".getBytes()));
    }

    @Test
    public void shouldLocateLimitWhenValueInsideBuffer()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice warm cookie cutter".getBytes(US_ASCII));
        assertEquals("a nice".length(), BufferUtil.limitOfBytes(buffer, 0, buffer.capacity(), "nice".getBytes()));
    }

    @Test
    public void shouldReportLimitMinusOneWhenValueNotFound()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice warm cookie cutter".getBytes(US_ASCII));
        assertEquals(-1, BufferUtil.limitOfBytes(buffer, 0, buffer.capacity(), "cutlass".getBytes()));
    }

    @Test
    public void shouldReportLimitMinusOneWhenValueLongerThanBuffer()
    {
        DirectBuffer buffer = new UnsafeBuffer("a nice warm cookie cutter".getBytes(US_ASCII));
        assertEquals(-1, BufferUtil.limitOfBytes(buffer, 0, buffer.capacity(),
                "a nice warm cookie cutter indeed".getBytes()));
    }
}

