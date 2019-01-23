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

import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;

/**
 * The GCS credentials are just OAuth tokens.
 */
public class GoogleTempCredentials extends OAuthPayload {

  private static final long serialVersionUID = 4067867391558151465L;

  public GoogleTempCredentials() {
  }

  public GoogleTempCredentials(AccessTokenProvider.AccessToken accessToken) {
    super(accessToken.getToken(), accessToken.getExpirationTimeMilliSeconds());
  }

  public AccessTokenProvider.AccessToken toAccessToken() {
    if (isEmpty()) {
      throw new IllegalStateException("Empty credentials");
    }
    return new AccessTokenProvider.AccessToken(getToken(), getExpiration());
  }

}
