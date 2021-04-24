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
package org.apache.knox.gateway.cloud.idbroker.abfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.apache.knox.gateway.cloud.idbroker.common.AbstractIDBTokenRenewer;
import org.apache.knox.gateway.cloud.idbroker.common.AbstractIDBTokenRenewerTest;
import org.easymock.EasyMock;

public class AbfsIDBTokenRenewerTest extends AbstractIDBTokenRenewerTest<AbfsIDBTokenIdentifier> {

  @Override
  protected Text getTokenKindForTest() {
    return AbfsIDBConstants.IDB_TOKEN_KIND;
  }

  @Override
  protected AbstractIDBTokenRenewer getTokenRenewerInstance() {
    return new AbfsIDBTokenRenewer();
  }

  @Override
  protected Configuration getConfiguration() {
    return getConfiguration("http://gateway:8444/gateway/");
  }

  @Override
  protected Configuration getConfiguration(final String... gatewayAddresses) {
    Configuration config = EasyMock.createNiceMock(Configuration.class);
    EasyMock.expect(config.getStrings(AbfsIDBProperty.IDBROKER_GATEWAY.getPropertyName()))
            .andReturn(gatewayAddresses)
            .anyTimes();
    EasyMock.expect(config.get(AbfsIDBProperty.IDBROKER_DT_PATH.getPropertyName()))
            .andReturn("dt")
            .anyTimes();
    EasyMock.expect(config.getInt(EasyMock.eq(AbfsIDBProperty.IDBROKER_MAX_FAILOVER_ATTEMPTS.getPropertyName()), EasyMock.anyInt())).andReturn(2).anyTimes();
    EasyMock.expect(config.getInt(EasyMock.eq(AbfsIDBProperty.IDBROKER_FAILOVER_SLEEP.getPropertyName()),  EasyMock.anyInt())).andReturn(1).anyTimes();
    EasyMock.expect(config.getInt(EasyMock.eq(AbfsIDBProperty.IDBROKER_MAX_RETRY_ATTEMPTS.getPropertyName()), EasyMock.anyInt())).andReturn(2).anyTimes();
    EasyMock.expect(config.getInt(EasyMock.eq(AbfsIDBProperty.IDBROKER_RETRY_SLEEP.getPropertyName()),  EasyMock.anyInt())).andReturn(5).anyTimes();
    EasyMock.expect(config.getBoolean(EasyMock.eq(AbfsIDBProperty.IDBROKER_TOKEN_MANAGEMENT_ENABLED.getPropertyName()),  EasyMock.anyBoolean())).andReturn(true).anyTimes();

    EasyMock.replay(config);
    return config;
  }

  @Override
  protected Token<AbfsIDBTokenIdentifier> createTestToken(Text allowedRenewer) throws Exception {
    final AbfsIDBTokenIdentifier identifier = EasyMock.createNiceMock(AbfsIDBTokenIdentifier.class);
    EasyMock.expect(identifier.getKind()).andReturn(getTokenKindForTest()).anyTimes();
    EasyMock.expect(identifier.getRenewer()).andReturn(allowedRenewer).anyTimes();
    EasyMock.expect(identifier.getAccessToken()).andReturn("junkaccesstoken").anyTimes();
    EasyMock.expect(identifier.getExpiryTime()).andReturn(System.currentTimeMillis() + (60 * 1000)).anyTimes();
    EasyMock.replay(identifier);

    final Token<AbfsIDBTokenIdentifier> token = EasyMock.createNiceMock(Token.class);
    EasyMock.expect(token.decodeIdentifier()).andReturn(identifier).anyTimes();
    EasyMock.expect(token.getKind()).andReturn(getTokenKindForTest()).anyTimes();
    EasyMock.replay(token);

    return token;
  }

}
