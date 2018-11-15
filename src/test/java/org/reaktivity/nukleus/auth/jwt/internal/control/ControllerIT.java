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
package org.reaktivity.nukleus.auth.jwt.internal.control;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.hamcrest.Matchers.either;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.rules.RuleChain.outerRule;

import java.util.Random;
import java.util.concurrent.ExecutionException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.nukleus.auth.jwt.internal.AuthJwtController;
import org.reaktivity.reaktor.test.ReaktorRule;

public class ControllerIT
{
    private final K3poRule k3po = new K3poRule()
        .addScriptRoot("resolve", "org/reaktivity/specification/nukleus/auth/jwt/control/resolve")
        .addScriptRoot("unresolve", "org/reaktivity/specification/nukleus/auth/jwt/control/unresolve")
        .addScriptRoot("route", "org/reaktivity/specification/nukleus/auth/jwt/control/route")
        .addScriptRoot("unroute", "org/reaktivity/specification/nukleus/auth/jwt/control/unroute")
        .addScriptRoot("freeze", "org/reaktivity/specification/nukleus/control/freeze");

    private final TestRule timeout = new DisableOnDebug(new Timeout(5, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
        .directory("target/nukleus-itests")
        .commandBufferCapacity(4096)
        .responseBufferCapacity(4096)
        .counterValuesBufferCapacity(1024)
        .controller("auth-jwt"::equals);

    @Rule
    public final TestRule chain = outerRule(k3po).around(timeout).around(reaktor);

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    @Specification({
        "${resolve}/fails.too.many.roles/nukleus"
    })
    public void shouldFailToResolveWithTooManyRoles() throws Exception
    {
        thrown.expect(either(is(instanceOf(IllegalStateException.class)))
                .or(is(instanceOf(ExecutionException.class))));
        thrown.expectCause(either(nullValue(Exception.class)).or(is(instanceOf(IllegalStateException.class))));

        k3po.start();

        reaktor.controller(AuthJwtController.class)
          .resolve("realm",
                  "role1", "role2", "role3", "role4", "role5", "role6", "role7", "role8", "role9", "role10",
                  "role11", "role12", "role13", "role14", "role15", "role16", "role17", "role18", "role19", "role20",
                  "role21", "role22", "role23", "role24", "role25", "role26", "role27", "role28", "role29", "role30",
                  "role31", "role32", "role33", "role34", "role35", "role36", "role37", "role38", "role39", "role40",
                  "role41", "role42", "role43", "role44", "role45", "role46", "role47", "role48", "role49TooMany")
          .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/multiple.realms/nukleus"
    })
    public void shouldResolveMultipleRealms() throws Exception
    {
        k3po.start();

        long authorization1 = reaktor.controller(AuthJwtController.class)
            .resolve("key1")
            .get();
        assertEquals(0x0001_000000000000L, authorization1);

        long authorization2 = reaktor.controller(AuthJwtController.class)
            .resolve("key2")
            .get();
        assertEquals(0x0002_000000000000L, authorization2);

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/one.realm/nukleus"
    })
    public void shouldResolveOneRealm() throws Exception
    {
        k3po.start();

        long authorization1 = reaktor.controller(AuthJwtController.class)
            .resolve("key1")
            .get();
        assertEquals(0x0001_000000000000L, authorization1);

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/with.roles/nukleus"
    })
    public void shouldResolveWithRoles() throws Exception
    {
        k3po.start();

        long authorization = reaktor.controller(AuthJwtController.class)
            .resolve("key1", "role1", "role2")
            .get();
        assertEquals(0x0001_00000000000cL, authorization);

        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/proxy/nukleus"
    })
    public void shouldRouteProxy() throws Exception
    {
        long targetRef = new Random().nextLong();

        k3po.start();

        reaktor.controller(AuthJwtController.class)
            .routeProxy("source", 0L, "target", targetRef, 0L)
            .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${unresolve}/fails.unknown.realm/nukleus"
    })
    public void shouldFailToUnresolveUnkownRealm() throws Exception
    {
        thrown.expect(either(is(instanceOf(IllegalStateException.class)))
                .or(is(instanceOf(ExecutionException.class))));
        thrown.expectCause(either(nullValue(Exception.class)).or(is(instanceOf(IllegalStateException.class))));

        k3po.start();

        long authorizationWithUnknownRealm = 0x1000_000000000000L;
        reaktor.controller(AuthJwtController.class)
            .unresolve(authorizationWithUnknownRealm)
            .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${unresolve}/fails.unknown.role/nukleus"
    })
    public void shouldFailToUnresolveUnkownRole() throws Exception
    {
        thrown.expect(either(is(instanceOf(IllegalStateException.class)))
                .or(is(instanceOf(ExecutionException.class))));
        thrown.expectCause(either(nullValue(Exception.class)).or(is(instanceOf(IllegalStateException.class))));

        k3po.start();

        long authorizationWithUnknownRoleBits = 0x0001_ffff0000ffffL;
        reaktor.controller(AuthJwtController.class)
            .unresolve(authorizationWithUnknownRoleBits)
            .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/multiple.realms/nukleus",
        "${unresolve}/multiple.realms/nukleus"
    })
    public void shouldUnresolveMultipleRealms() throws Exception
    {
        k3po.start();

        long authorization1 = reaktor.controller(AuthJwtController.class)
          .resolve("key1")
          .get();
        assertEquals(0x0001_000000000000L, authorization1);

        long authorization2 = reaktor.controller(AuthJwtController.class)
                .resolve("key2")
                .get();
        assertEquals(0x0002_000000000000L, authorization2);

        reaktor.controller(AuthJwtController.class)
            .unresolve(authorization1)
            .get();

        reaktor.controller(AuthJwtController.class)
            .unresolve(authorization2)
            .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/one.realm/nukleus",
        "${unresolve}/one.realm/nukleus"
    })
    public void shouldUnresolveOneRealm() throws Exception
    {
        k3po.start();

        long authorization = reaktor.controller(AuthJwtController.class)
          .resolve("key1")
          .get();
        assertEquals(0x0001_000000000000L, authorization);

        reaktor.controller(AuthJwtController.class)
            .unresolve(authorization)
            .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/with.roles/nukleus",
        "${unresolve}/with.roles/nukleus"
    })
    public void shouldUnresolveWithRoles() throws Exception
    {
        k3po.start();

        long authorization = reaktor.controller(AuthJwtController.class)
                .resolve("key1", "role1", "role2")
                .get();
        assertEquals(0x0001_00000000000cL, authorization);

        reaktor.controller(AuthJwtController.class)
           .unresolve(authorization)
           .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${unroute}/proxy/fails.unknown.route/nukleus"
    })
    public void shouldFailToUnrouteProxyWithUnknownAcceptRouteRef() throws Exception
    {
        thrown.expect(either(is(instanceOf(IllegalStateException.class)))
                      .or(is(instanceOf(ExecutionException.class))));
        thrown.expectCause(either(nullValue(Exception.class)).or(is(instanceOf(IllegalStateException.class))));
        k3po.start();
        long sourceRef = new Random().nextLong();
        long targetRef = new Random().nextLong();
        reaktor.controller(AuthJwtController.class)
           .unrouteProxy("source", sourceRef, "target", targetRef, 0L)
           .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/proxy/nukleus",
        "${unroute}/proxy/nukleus"
    })
    public void shouldUnrouteProxy() throws Exception
    {
        long targetRef = new Random().nextLong();

        k3po.start();

        long sourceRef = reaktor.controller(AuthJwtController.class)
              .routeProxy("source", 0L, "target", targetRef, 0L)
              .get();

        k3po.notifyBarrier("ROUTED_PROXY");

        reaktor.controller(AuthJwtController.class)
               .unrouteProxy("source", sourceRef, "target", targetRef, 0L)
               .get();

        k3po.finish();
    }

    @Test
    @Specification({
        "${freeze}/nukleus"
    })
    @ScriptProperty({
        "nameF00N \"auth-jwt\"",
        "commandCapacityF00N 4096",
        "responseCapacityF00N 4096"
    })
    public void shouldFreeze() throws Exception
    {
        k3po.start();

        reaktor.controller(AuthJwtController.class)
               .freeze()
               .get();

        k3po.finish();
    }
}
