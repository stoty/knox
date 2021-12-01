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
import org.apache.http.HttpRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.protocol.HttpContext;

public class ProxyRoutePlanner extends DefaultProxyRoutePlanner {
    private final String[] nonProxyHosts;

    public ProxyRoutePlanner(HttpHost proxy, String[] nonProxyHosts) {
        super(proxy);
        this.nonProxyHosts = nonProxyHosts;
    }

    @Override
    public HttpRoute determineRoute(HttpHost target, HttpRequest request, HttpContext context) throws HttpException {
        for (String nonProxyHost : nonProxyHosts) {
            if (isNonProxyHost(target.getHostName(), nonProxyHost)) {
                return new HttpRoute(target); // skip proxy, use direct host
            }
        }
        return super.determineRoute(target, request, context);
    }

    private boolean isNonProxyHost(String hostname, String nonProxyHost) {
        return (nonProxyHost.startsWith("*.") && hostname.endsWith(nonProxyHost.substring(nonProxyHost.indexOf("*.") + 2)))
                || nonProxyHost.equalsIgnoreCase(hostname);
    }
}
