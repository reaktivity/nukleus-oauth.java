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
package org.reaktivity.nukleus.oauth.internal.streams;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.AUTO_DISCOVER_REALMS_NAME;
import static org.reaktivity.nukleus.oauth.internal.OAuthConfiguration.KEYS_NAME;
import static org.reaktivity.reaktor.test.ReaktorRule.EXTERNAL_AFFINITY_MASK;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.test.ReaktorRule;
import org.reaktivity.reaktor.test.annotation.Configure;

public class StreamsIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/oauth/control/route/proxy")
            .addScriptRoot("streams", "org/reaktivity/specification/nukleus/oauth/streams/proxy");

    private final TestRule timeout = new DisableOnDebug(new Timeout(15, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(4096)
            .responseBufferCapacity(4096)
            .counterValuesBufferCapacity(8192)
            .nukleus("oauth"::equals)
            .configure(KEYS_NAME, "keys/keys.jwk")
            .affinityMask("target#0", EXTERNAL_AFFINITY_MASK)
            .affinityMask("target#1", EXTERNAL_AFFINITY_MASK)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/default.cors.preflight/accept/client"
        })
    public void shouldDefaultCorsPreflight() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/proxy.cors.preflight/accept/client",
        "${streams}/proxy.cors.preflight/connect/server"
        })
    public void shouldProxyCorsPreflight() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/authorize.challenge.response/accept/client"
        })
    public void shouldAuthorizeChallengeResponse() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.no.roles.then.route.proxy/controller",
        "${streams}/authorize.then.abort.expiring.request/accept/client",
        "${streams}/authorize.then.abort.expiring.request/connect/server"
        })
    public void shouldAuthorizeThenAbortExpiringRequest() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.no.roles.then.route.proxy/controller",
        "${streams}/authorize.then.reset.expiring.response/accept/client",
        "${streams}/authorize.then.reset.expiring.response/connect/server"
        })
    public void shouldAuthorizeThenResetExpiringResponse() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.no.roles.then.route.proxy/controller",
        "${streams}/authorize.then.reset.expiring.response.early/accept/client",
        "${streams}/authorize.then.reset.expiring.response.early/connect/server"
        })
    public void shouldAuthorizeThenResetExpiringResponseEarly() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.multiple.realms.with.no.roles.then.route.proxy/controller",
        "${streams}/authorize.query.with.signed.jwt.es256/accept/client",
        "${streams}/authorize.query.with.signed.jwt.es256/connect/server"
        })
    public void shouldAuthorizeQueryWithValidJwtEC256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

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
        "${streams}/proxy.accept.flush/accept/client",
        "${streams}/proxy.accept.flush/connect/server"
        })
    public void shouldFlushClientConnectWhenAcceptFlushes() throws Exception
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
        "${streams}/proxy.accept.reply.is.reset.early/accept/client",
        "${streams}/proxy.accept.reply.is.reset.early/connect/server"
        })
    public void shouldResetClientReplyEarlyWhenAcceptReplyIsResetEarly() throws Exception
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
        "${streams}/proxy.connect.reply.flush/accept/client",
        "${streams}/proxy.connect.reply.flush/connect/server"
        })
    public void shouldFlushAcceptReplyWhenConnectReplyFlushes() throws Exception
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
    public void shouldRejectRequestWithInvalidJwt() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.multiple.realms.with.no.roles.then.route.proxy/controller",
        "${streams}/request.with.signed.jwt.es256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.es256.forwarded/connect/server"
        })
    public void shouldForwardRequestWithValidJwtEC256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Specification({
        "${route}/resolve.one.realm.with.set.roles.then.route.proxy/controller",
        "${streams}/request.with.scopes.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.scopes.with.signed.jwt.rs256.forwarded/connect/server"
        })
    public void shouldForwardRequestWithSetScopesWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.extra.roles.then.route.proxy/controller",
        "${streams}/request.with.extra.scope.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.extra.scope.with.signed.jwt.rs256.forwarded/connect/server"
        })
    public void shouldForwardRequestWithExtraScopeWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.then.route.proxy/controller",
        "${streams}/request.with.scopes.issuer.and.audience.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.scopes.issuer.and.audience.with.signed.jwt.rs256.forwarded/connect/server"
    })
    public void shouldForwardRequestWithSetScopesIssuerAndAudienceWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.reauthorizes.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.reauthorizes.inflight.request/connect/server"
    })
    public void shouldReauthorizeInFlightRequestWithLaterExpiringToken() throws Exception
    {
        k3po.start();
        Thread.sleep(5000); // first token would expire if expiration is not updated.
        k3po.notifyBarrier("TOKEN_EXPIRATION");
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.with.fewer.roles.does.not.reauthorize.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.with.fewer.roles.does.not.reauthorize.inflight.request/connect/server"
    })
    public void shouldNotReauthorizeInFlightRequestWithLaterExpiringTokenWithLessPrivileges() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/earlier.expiring.authorization.does.not.reauthorize.inflight.request/accept/client",
        "${streams}/earlier.expiring.authorization.does.not.reauthorize.inflight.request/connect/server"
    })
    public void shouldNotReauthorizeInFlightRequestWithEarlierExpiringTokenWithSamePrivileges() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.with.more.roles.reauthorizes.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.with.more.roles.reauthorizes.inflight.request/connect/server"
    })
    public void shouldReauthorizeInFlightRequestWithTokenWithLaterExpiringMorePrivileges() throws Exception
    {
        k3po.start();
        Thread.sleep(5000); // first token would expire if expiration is not updated.
        k3po.notifyBarrier("TOKEN_EXPIRATION");
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.with.different.affinity.does.not.reauthorize.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.with.different.affinity.does.not.reauthorize.inflight.request/connect/server"
    })
    public void shouldNotReauthorizeInFlightRequestWithLaterExpiringTokenWithDifferentAffinity() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.without.affinity.does.not.reauthorize.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.without.affinity.does.not.reauthorize.inflight.request/connect/server"
    })
    public void shouldNotReauthorizeInFlightRequestWithLaterExpiringTokenWithoutAffinity() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.multiple.routes.then.route.proxy/controller",
        "${streams}/later.expiring.authorization.with.different.subject.does.not.reauthorize.inflight.request/accept/client",
        "${streams}/later.expiring.authorization.with.different.subject.does.not.reauthorize.inflight.request/connect/server"
    })
    public void shouldNotReauthorizeInFlightRequestWithLaterExpiringTokenWithDifferentSubject() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.then.route.proxy/controller",
        "${streams}/request.with.scopes.issuer.and.audience.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.scopes.issuer.and.audience.with.signed.jwt.rs256.forwarded/connect/server"
    })
    public void shouldForwardRequestWithATokenWithIssuerOrAudienceWithoutSpecifiedClaimsOnTheSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.and.audience.and.no.issuer.then.route.proxy/controller",
        "${streams}/request.with.scopes.and.audience.and.no.issuer.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.scopes.and.audience.and.no.issuer.with.signed.jwt.rs256.forwarded/connect/server"
    })
    public void shouldForwardRequestWithSetScopesAndAudienceWithNoIssuerWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.and.audience.and.no.issuer.then.route.proxy/controller",
        "${streams}/request.with.scopes.and.multiple.audiences.and.no.issuer.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.scopes.and.multiple.audiences.and.no.issuer.with.signed.jwt.rs256.forwarded/connect/server"
    })
    public void shouldForwardRequestWithSetScopesAndMultipleAudiencesWithNoIssuerWithValidJwtRS256OnSecuredRoute()
        throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.issuer.and.audience.expect.no.authorization.then.route.proxy/controller",
        "${streams}/request.without.issuer.and.audience.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.without.issuer.and.audience.with.signed.jwt.rs256.forwarded/connect/server"
    })
    public void shouldForwardRequestWithoutIssuerOrAudienceWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.no.roles.then.route.proxy/controller",
        "${streams}/request.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.rs256.forwarded/connect/server"
        })
    public void shouldForwardRequestWithValidJwtRS256OnSecuredRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/controller",
        "${streams}/request.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.rs256.forwarded/connect/server"
        })
    @Configure(name = AUTO_DISCOVER_REALMS_NAME, value = "true")
    public void shouldForwardRequestWithValidJwtRS256OnSecuredRouteWithAutoDiscoveredRealm() throws Exception
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
    public void shouldRejectRequestWithoutBearer() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/resolve.one.realm.with.set.roles.issuer.and.audience.then.route.proxy/controller",
        "${streams}/challenge.before.expiration/accept/client",
        "${streams}/challenge.before.expiration/connect/server"
        })
    public void shouldChallengeBeforeExpiration() throws Exception
    {
        k3po.start();
        Thread.sleep(5000); // first token would expire if expiration is not updated.
        k3po.finish();
    }

}
