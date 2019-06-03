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
package org.apache.knox.gateway.shell.knox.token;

import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;

import java.net.URI;
import java.util.concurrent.Callable;

/**
 * Adapter for the standard KnoxToken request, which allows such requests to failover
 * in the Cloud Access Broker context.
 */
public class CloudAccessBrokerTokenGet extends AbstractCloudAccessBrokerRequest<BasicResponse> {

  private Get.Request delegate;

  public CloudAccessBrokerTokenGet(Get.Request delegate) {
    super((CloudAccessBrokerSession) delegate.getSession());
    this.delegate = delegate;
  }

  @Override
  protected Callable callable() {
    return delegate.callable();
  }

  public URI getRequestURI() {
    return delegate.getRequestURI();
  }

}
