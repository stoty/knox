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

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;

import java.io.IOException;
import java.net.URISyntaxException;

public interface CloudAccessBrokerClient {
  String getCloudAccessBrokerAddress();

  CloudAccessBrokerSession getCloudSession(String delegationToken,
                                           String delegationTokenType)
      throws URISyntaxException;


  CloudAccessBrokerSession getCloudSession(String delegationToken,
                                           String delegationTokenType,
                                           String cabPublicCert)
      throws URISyntaxException;


  RequestDTResponseMessage requestDelegationToken(KnoxSession dtSession) throws IOException;


  RequestDTResponseMessage updateDelegationToken(String delegationToken,
                                                 String delegationTokenType,
                                                 String cabPublicCert) throws Exception;


  KnoxSession createDTSession(String gatewayCertificate) throws IllegalStateException;


  KnoxSession createUsernamePasswordDTSession();


  KnoxSession createKerberosDTSession(String gatewayCertificate) throws URISyntaxException;


  AccessTokenProvider.AccessToken getCloudCredentials(CloudAccessBrokerSession session)
      throws IOException;

}
