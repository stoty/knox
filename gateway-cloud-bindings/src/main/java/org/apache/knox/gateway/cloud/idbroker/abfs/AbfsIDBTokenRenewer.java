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
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.knox.gateway.cloud.idbroker.common.AbstractIDBTokenRenewer;

public class AbfsIDBTokenRenewer extends AbstractIDBTokenRenewer {

  private static final String GATEWAY_ADDRESS_PROPERTY = AbfsIDBProperty.IDBROKER_GATEWAY.getPropertyName();
  private static final String DT_PATH_PROPERTY         = AbfsIDBProperty.IDBROKER_DT_PATH.getPropertyName();


  @Override
  public boolean handleKind(Text text) {
    return AbfsIDBConstants.IDB_TOKEN_KIND.equals(text);
  }

  @Override
  protected String getAccessToken(DelegationTokenIdentifier identifier) {
    return ((AbfsIDBTokenIdentifier)identifier).getAccessToken();
  }

  @Override
  protected long getTokenExpiration(DelegationTokenIdentifier identifier) {
    return ((AbfsIDBTokenIdentifier)identifier).getExpiryTime();
  }

  @Override
  protected String getGatewayAddressConfigProperty(Configuration config) {
    return config.get(GATEWAY_ADDRESS_PROPERTY);
  }

  @Override
  protected String getDelegationTokenPathConfigProperty(Configuration config) {
    return config.get(DT_PATH_PROPERTY);
  }

}
