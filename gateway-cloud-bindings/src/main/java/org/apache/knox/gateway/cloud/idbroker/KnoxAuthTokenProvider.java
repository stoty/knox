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
package org.apache.knox.gateway.cloud.idbroker;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.common.AuthenticationTokenProvider;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;

import java.io.IOException;

public class KnoxAuthTokenProvider implements AuthenticationTokenProvider {

  IDBClient<?> client;
  Configuration config;

  public KnoxAuthTokenProvider(final IDBClient client, Configuration conf) {
    Preconditions.checkArgument(client != null, "A CloudAccessBrokerClient is required.");
    this.client = client;
    this.config = conf;
  }

  @Override
  public String authenticate(final String endpoint) {
    String token = null;

    try {
      // Create a new session for authenticating with the currently-active CAB delegation token endpoint
      Pair<KnoxSession, String> session = client.login(config);
      RequestDTResponseMessage response = client.requestKnoxDelegationToken(session.getKey(), session.getValue(), null);
      token = response.access_token;
    } catch (IOException e) {
      e.printStackTrace(); // TODO: PJZ: Logging
    }

    return token;
  }
}
