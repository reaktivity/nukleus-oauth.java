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
package org.reaktivity.nukleus.auth.jwt.internal.streams;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.test.ReaktorRule;

public class StreamsIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/auth/jwt/control/route/proxy")
            .addScriptRoot("streams", "org/reaktivity/specification/nukleus/auth/jwt/streams/proxy");

    private final TestRule timeout = new DisableOnDebug(new Timeout(5, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(4096)
            .responseBufferCapacity(4096)
            .counterValuesBufferCapacity(1024)
            .nukleus("auth-jwt"::equals)
            .configure("auth.jwt.keys", "keys/keys.jwk")
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/proxy.accept.aborts/accept/client",
        "${streams}/proxy.accept.aborts/connect/server"
        })
    public void shouldAbortClientConnectWhenAcceptAborts() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/proxy.accept.reply.is.reset/accept/client",
        "${streams}/proxy.accept.reply.is.reset/connect/server"
        })
    public void shouldResetClientReplyWhenAcceptReplyIsReset() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/proxy.connect.is.reset/accept/client",
        "${streams}/proxy.connect.is.reset/connect/server"
        })
    public void shouldResetAcceptWhenConnectIsReset() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/proxy.connect.reply.aborts/accept/client",
        "${streams}/proxy.connect.reply.aborts/connect/server"
        })
    public void shouldAbortAcceptReplyWhenConnectReplyAborts() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.and.response.with.fragmented.data/accept/client",
        "${streams}/request.and.response.with.fragmented.data/connect/server"
        })
    public void shouldPropagateWindows() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.expired.jwt.forwarded/accept/client",
        "${streams}/request.with.expired.jwt.forwarded/connect/server"
        })
    public void shouldForwardRequestWithExpiredJwtOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.expired.jwt.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithExpiredJwt() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.invalid.jwt.forwarded/accept/client",
        "${streams}/request.with.invalid.jwt.forwarded/connect/server"
        })
    public void shouldForwardRequestWithInvalidJwtOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.invalid.jwt.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithInvalidJwt() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.signed.jwt.es256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.es256.forwarded/connect/server"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldForwardRequestWithValidJwtEC256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.rs256.forwarded/connect/server"
        })
    @ScriptProperty({"authorization 0x0002_000000000000L",
                    "expectedAuthorization 0x0002_000000000000L"})
    public void shouldForwardRequestWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.unready.jwt.forwarded/accept/client",
        "${streams}/request.with.unready.jwt.forwarded/connect/server"
        })
    public void shouldForwardRequestWithUnreadyJwtOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.unready.jwt.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithUnreadyJwt() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.unsigned.jwt.forwarded/accept/client",
        "${streams}/request.with.unsigned.jwt.forwarded/connect/server"
        })
    public void shouldForwardRequestWithUnsignedJwtOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.unsigned.jwt.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithUnsignedJwt() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.without.authorization.forwarded/accept/client",
        "${streams}/request.without.authorization.forwarded/connect/server"
        })
    public void shouldForwardRequestWithoutAuthorizationOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.without.authorization.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithoutAuthorization() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.without.bearer.forwarded/accept/client",
        "${streams}/request.without.bearer.forwarded/connect/server"
        })
    public void shouldForwardRequestWithoutBearerOnUnsecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.without.bearer.no.route/accept/client"
        })
    @ScriptProperty("authorization 0x0001_000000000000L")
    public void shouldRejectRequestWithoutBearer() throws Exception
    {
        k3po.finish();
    }

}
