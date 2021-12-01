/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.service.idbroker.azure;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.routing.HttpRoute;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ProxyRoutePlannerTest {
    private static final HttpHost TARGET_1 = new HttpHost("target.host");
    private static final HttpHost SUB_TARGET_1 = new HttpHost("subdomain.target.host");
    private static final HttpHost TARGET_2 = new HttpHost("target2.host");
    private static final HttpHost PROXY = new HttpHost("proxy.server", 8080);

    @Test
    public void testGoesThroughProxyWhenNoExclude() throws Exception {
        ProxyRoutePlanner planner = planner(new String[]{});
        assertEquals(throughProxy(TARGET_1), planRoute(planner, TARGET_1));
        assertEquals(throughProxy(TARGET_2), planRoute(planner, TARGET_2));
        assertEquals(throughProxy(SUB_TARGET_1), planRoute(planner, SUB_TARGET_1));
    }

    @Test
    public void testOnlyGoesThroughProxyIfHostIsNotExcluded() throws Exception {
        ProxyRoutePlanner planner = planner(new String[]{ TARGET_2.getHostName() });
        assertEquals(throughProxy(TARGET_1), planRoute(planner, TARGET_1));
        assertEquals(direct(TARGET_2), planRoute(planner, TARGET_2));
        assertEquals(throughProxy(SUB_TARGET_1), planRoute(planner, SUB_TARGET_1));
    }

    @Test
    public void testWildcardExclude() throws Exception {
        ProxyRoutePlanner planner = planner(new String[]{ "*.target.host" });
        assertEquals(direct(TARGET_1), planRoute(planner, TARGET_1));
        assertEquals(direct(SUB_TARGET_1), planRoute(planner, SUB_TARGET_1));
        assertEquals(throughProxy(TARGET_2), planRoute(planner, TARGET_2));
    }

    private static ProxyRoutePlanner planner(String[] nonProxyHosts) {
        return new ProxyRoutePlanner(PROXY, nonProxyHosts);
    }

    private static HttpRoute throughProxy(HttpHost target2) {
        return new HttpRoute(target2, PROXY);
    }

    private static HttpRoute direct(HttpHost target) {
        return new HttpRoute(target);
    }

    private HttpRoute planRoute(ProxyRoutePlanner planner, HttpHost target) throws HttpException {
        return planner.determineRoute(target, new HttpGet(target.toURI()), new HttpClientContext());
    }
}