/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.cloud.idbroker.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

public class DefaultEndpointManager implements EndpointManager {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultEndpointManager.class);

  private ConcurrentLinkedQueue<String> endpoints = new ConcurrentLinkedQueue<>();

  /**
   * When this is used, setURLs() must be invoked before this instance can be used.
   */
  protected DefaultEndpointManager() {
  }

  public DefaultEndpointManager(final List<String> endpoints) {
    setURLs(endpoints);
  }

  @Override
  public synchronized String getActiveURL() {
    return endpoints.peek();
  }


  protected synchronized void setActiveURL(String url) {
    String top = endpoints.peek();
    if (top != null && top.equalsIgnoreCase(url)) {
      return;
    }
    if (endpoints.contains(url)) {
      endpoints.remove(url);
      List<String> remainingList = getURLs();
      endpoints.clear();
      endpoints.add(url);
      endpoints.addAll(remainingList);
    }
  }


  @Override
  public synchronized List<String> getURLs() {
    return new ArrayList<>(endpoints);
  }


  protected synchronized void setURLs(List<String> endpoints) {
    if (endpoints != null && !endpoints.isEmpty()) {
      this.endpoints.clear();
      for (String endpoint : endpoints) {
        // Trim the values here in case spaces were included between delimiters and values (e.g., "value1, value2")
        this.endpoints.add(endpoint.trim());
      }
    }
  }


  @Override
  public synchronized void markFailed(String url) {
    String top = endpoints.peek();
    if (top != null) {
      boolean pushToBottom = false;
      URI topUri = URI.create(top);
      URI incomingUri = URI.create(url);
      String topHostPort = topUri.getHost() + ":" + topUri.getPort();
      String incomingHostPort = incomingUri.getHost() + ":" + incomingUri.getPort();
      if (topHostPort.equals(incomingHostPort)) {
        pushToBottom = true;
      }
      //put the failed url at the bottom
      if (pushToBottom) {
        String failed = endpoints.poll();
        endpoints.offer(failed);
        LOG.error("Failed endpoint {}; Failing over to {} ...", failed, endpoints.peek());
      }
    }
  }

}
