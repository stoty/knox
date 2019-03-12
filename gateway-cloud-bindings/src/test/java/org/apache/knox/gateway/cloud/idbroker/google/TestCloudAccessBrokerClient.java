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
package org.apache.knox.gateway.cloud.idbroker.google;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;

import java.io.IOException;
import java.net.URISyntaxException;

public class TestCloudAccessBrokerClient implements CloudAccessBrokerClient {

  private KnoxSession testSession = null;

  private RequestDTResponseMessage testDTResponse = null;

  private AccessTokenProvider.AccessToken testAccessToken = null;


  void setCloudSession(KnoxSession session) {
    this.testSession = session;
  }

  void setAccessToken(String token, long expiration) {
    this.testAccessToken = new AccessTokenProvider.AccessToken(token, expiration);
  }

  void setTestDTResponse(RequestDTResponseMessage response) {
    this.testDTResponse = response;
  }

  @Override
  public KnoxSession getCloudSession(String cabAddress, String delegationToken, String delegationTokenType) throws URISyntaxException {
    return testSession;
  }

  @Override
  public KnoxSession getCloudSession(Configuration config, String delegationToken, String delegationTokenType) throws URISyntaxException {
    return testSession;
  }

  @Override
  public KnoxSession getCloudSession(String cabAddress, String delegationToken, String delegationTokenType, String trustStoreLocation, String trustStorePass) throws URISyntaxException {
    return testSession;
  }

  @Override
  public KnoxSession getCloudSession(String cabAddress, String delegationToken, String delegationTokenType, String cabPublicCert) throws URISyntaxException {
    return testSession;
  }

  @Override
  public RequestDTResponseMessage requestDelegationToken(Configuration conf, KnoxSession dtSession) throws IOException {
    return testDTResponse;
  }

  @Override
  public RequestDTResponseMessage updateDelegationToken(Configuration conf, String delegationToken, String delegationTokenType) throws Exception {
    return testDTResponse;
  }

  @Override
  public KnoxSession createDTSession(Configuration conf, String gatewayCertificate) throws IllegalStateException {
    return testSession;
  }

  @Override
  public KnoxSession createUsernamePasswordDTSession(Configuration conf, String dtAddress) {
    return testSession;
  }

  @Override
  public KnoxSession createKerberosDTSession(Configuration conf, String dtAddress, String gatewayCertificate) throws URISyntaxException {
    return testSession;
  }

  @Override
  public AccessTokenProvider.AccessToken getCloudCredentials(Configuration config, KnoxSession session) throws IOException {
    return testAccessToken;
  }

}
