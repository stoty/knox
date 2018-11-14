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
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.Serializable;
import java.util.Date;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

public class GoogleTempCredentials implements Writable, Serializable {

  private static final long serialVersionUID = 4067867391558151465L;

  private String token = "";

  private long expiration = 0;

  public GoogleTempCredentials() {
  }

  public GoogleTempCredentials(AccessTokenProvider.AccessToken accessToken) {
    this.token      = accessToken.getToken();
    this.expiration = accessToken.getExpirationTimeMilliSeconds();
  }

  public void setToken(String token) {
    this.token = token;
  }

  public String getToken() {
    return token;
  }

  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }

  public long getExpiration() {
    return expiration;
  }

  public AccessTokenProvider.AccessToken toAccessToken() {
    if (isEmpty()) {
      throw new IllegalStateException("Empty credentials");
    }
    return new AccessTokenProvider.AccessToken(token, expiration);
  }

  @Override
  public void write(DataOutput dataOutput) throws IOException {
    Text.writeString(dataOutput, token);
    dataOutput.writeLong(expiration);
  }

  @Override
  public void readFields(DataInput dataInput) throws IOException {
    token = Text.readString(dataInput);
    expiration = dataInput.readLong();
  }

  /**
   * String value does not include
   * any secrets.
   * @return a string value for logging.
   */
  @Override
  public String toString() {
    if (isEmpty()) {
      return "Empty credentials";
    }
    return String.format("short-lived credentials (token='%s')%s",
                         (token.substring(0, 8) + "..."),
                         (expiration == 0 ? "" : (", expiring on " + (new Date(expiration)))));
  }

  /**
   * Is this empty: does it contain any credentials at all?
   * This test returns true if either the access key or secret key is empty.
   * @return true if there are no credentials.
   */
  public boolean isEmpty() {
    return !isNotEmpty(token);
  }

}
