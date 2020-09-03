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
package org.apache.knox.gateway.cloud.idbroker.s3a;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.knox.gateway.cloud.idbroker.common.AbstractIDBTokenRenewer;

import java.util.Arrays;
import java.util.List;

public class IDBS3ATokenRenewer extends AbstractIDBTokenRenewer {

  private static final String GATEWAY_ADDRESS_PROPERTY = S3AIDBProperty.IDBROKER_GATEWAY.getPropertyName();
  private static final String DT_PATH_PROPERTY         = S3AIDBProperty.IDBROKER_DT_PATH.getPropertyName();


  @Override
  public boolean handleKind(Text text) {
    return IDBS3AConstants.IDB_TOKEN_KIND.equals(text);
  }

  @Override
  protected String getAccessToken(DelegationTokenIdentifier identifier) {
    return ((IDBS3ATokenIdentifier)identifier).getAccessToken();
  }

  @Override
  protected long getTokenExpiration(DelegationTokenIdentifier identifier) {
    return ((IDBS3ATokenIdentifier)identifier).getExpiryTime();
  }

  @Override
  protected List<String> getGatewayAddressConfigProperty(Configuration config) {
    return Arrays.asList(config.getStrings(GATEWAY_ADDRESS_PROPERTY));
  }

  @Override
  protected String getDelegationTokenPathConfigProperty(Configuration config) {
    return config.get(DT_PATH_PROPERTY);
  }

}
