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

import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;

import java.util.List;

public interface RequestExecutor {

  /**
   * @return The current active endpoint
   */
  String getEndpoint();


  /**
   *
   * @return The endpoints configured for this instance.
   */
  List<String> getConfiguredEndpoints();


  /**
   * Execute the specified request.
   *
   * @param request The request
   *
   * @return The request-type-specific response object.
   */
  <T> T execute(AbstractCloudAccessBrokerRequest<T> request);

}
