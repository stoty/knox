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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

/**
 * This is a payload for OAuth Tokens.
 */
public class OAuthPayload implements Writable, Serializable {

  private static final long serialVersionUID = 174663489540834820L;

  private String token = "";

  private long expiration;

  public OAuthPayload() {
  }

  /**
   * Create from a token.
   * @param token token string; may be null
   * @param expiration expiration time in milliseconds since the epoch.
   */
  public OAuthPayload(final String token, final long expiration) {
    this.token = token;
    this.expiration = expiration;
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
    int len = token.length();
    int end = len > 8 ? 8 : 1;
    return String.format(Locale.ROOT, "short-lived credentials (token='%s')%s",
                         (token.substring(0, end) + "..."),
                         (expiration == 0
                             ? ""
                             : (", expiring on " + (new Date(expiration)))));
  }

  /**
   * Is this empty: does it contain any credentials at all?
   * This test returns true if either the access key or secret key is empty.
   * @return true if there are no credentials.
   */
  public boolean isEmpty() {
    return !isNotEmpty(token);
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) { return true; }
    if (o == null || getClass() != o.getClass()) { return false; }
    final OAuthPayload that = (OAuthPayload) o;
    return expiration == that.expiration &&
        Objects.equals(token, that.token);
  }

  @Override
  public int hashCode() {
    return Objects.hash(token, expiration);
  }
}
