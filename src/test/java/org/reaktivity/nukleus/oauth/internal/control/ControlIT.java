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
package org.reaktivity.nukleus.oauth.internal.control;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.test.ReaktorRule;

public class ControlIT
{
    private final K3poRule k3po = new K3poRule()
        .addScriptRoot("resolve", "org/reaktivity/specification/nukleus/oauth/control/resolve")
        .addScriptRoot("unresolve", "org/reaktivity/specification/nukleus/oauth/control/unresolve")
        .addScriptRoot("route", "org/reaktivity/specification/nukleus/oauth/control/route")
        .addScriptRoot("unroute", "org/reaktivity/specification/nukleus/oauth/control/unroute")
        .addScriptRoot("freeze", "org/reaktivity/specification/nukleus/control/freeze");

    private final TestRule timeout = new DisableOnDebug(new Timeout(5, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(4096)
            .responseBufferCapacity(4096)
            .counterValuesBufferCapacity(4096)
            .nukleus("oauth"::equals)
            .configure("oauth.keys", "keys/keys.jwk");

    @Rule
    public final TestRule chain = outerRule(k3po).around(timeout).around(reaktor);

    @Ignore("roles not yet implemented")
    @Test
    @Specification({
        "${resolve}/fails.too.many.roles/controller"
    })
    public void shouldFailToResolveWithTooManyRoles() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/multiple.realms/controller"
    })
    public void shouldResolveMultipleRealms() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/one.realm/controller"
    })
    public void shouldResolveOneRealm() throws Exception
    {
        k3po.finish();
    }

    @Ignore("roles not yet implemented")
    @Test
    @Specification({
        "${resolve}/with.roles/controller"
    })
    public void shouldResolveWithRoles() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/proxy/controller"
    })
    public void shouldRouteProxy() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${unresolve}/fails.unknown.realm/controller"
    })
    public void shouldFailToUnresolveUnkownRealm() throws Exception
    {
        k3po.finish();
    }

    @Ignore("roles not yet implemented")
    @Test
    @Specification({
        "${unresolve}/fails.unknown.role/controller"
    })
    public void shouldFailToUnresolveUnkownRole() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/multiple.realms/controller",
        "${unresolve}/multiple.realms/controller"
    })
    public void shouldUnresolveMultipleRealms() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${resolve}/one.realm/controller",
        "${unresolve}/one.realm/controller"
    })
    public void shouldUnresolveOneRealm() throws Exception
    {
        k3po.finish();
    }

    @Ignore("roles not yet implemented")
    @Test
    @Specification({
        "${resolve}/with.roles/controller",
        "${unresolve}/with.roles/controller"
    })
    public void shouldUnresolveWithRoles() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${unroute}/proxy/fails.unknown.route/controller"
    })
    public void shouldFailToUnrouteProxyWithUnknownRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/proxy/controller",
        "${unroute}/proxy/controller"
    })
    public void shouldUnrouteProxy() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${freeze}/controller",
    })
    @ScriptProperty({
        "nameF00C \"oauth\"",
        "commandCapacityF00C 4096",
        "responseCapacityF00C 4096"
    })
    public void shouldFreeze() throws Exception
    {
        k3po.finish();
    }
}
