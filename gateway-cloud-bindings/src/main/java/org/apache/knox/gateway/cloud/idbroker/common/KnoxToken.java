/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.knox.gateway.cloud.idbroker.common;

import static java.time.temporal.ChronoUnit.SECONDS;

import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkArgument;

import org.apache.commons.lang3.StringUtils;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalUnit;

/**
 * KnoxToken represents a Knox Delegation token.
 * <p>
 * This implementation provides helper methods to determine if the KnoxToken is expired or will
 * expire within some offset time.
 */
public class KnoxToken {
  public static final String DEFAULT_TOKEN_TYPE = "Bearer";

  private static final Logger LOG = LoggerFactory.getLogger(KnoxToken.class);

  private final String origin;
  private final String accessToken;
  private final String tokenType;
  private final long expiry;
  private final String endpointPublicCert;

  public KnoxToken(String origin, String accessToken, long expiry, String endpointPublicCert) {
    this(origin, accessToken, DEFAULT_TOKEN_TYPE, expiry, endpointPublicCert);

  }

  public KnoxToken(String origin, String accessToken, String tokenType, long expiry, String endpointPublicCert) {
    this.origin = origin;
    this.accessToken = accessToken;
    this.tokenType = tokenType;
    this.expiry = expiry;
    this.endpointPublicCert = endpointPublicCert;
  }

  public static KnoxToken fromDTResponse(String origin, RequestDTResponseMessage message) {
    checkArgument(message != null, "Missing RequestDTResponseMessage");
    return new KnoxToken(origin, message.access_token, message.token_type, message.expiryTimeSeconds(), message.endpoint_public_cert);
  }

  public static KnoxToken fromDTResponse(RequestDTResponseMessage message) {
    return fromDTResponse("unknown", message);
  }

  public String getOrigin() {
    return origin;
  }

  public String getAccessToken() {
    return accessToken;
  }

  public String getTokenType() {
    return (StringUtils.isEmpty(tokenType)) ? DEFAULT_TOKEN_TYPE : tokenType;
  }

  public long getExpiry() {
    return expiry;
  }

  public String getEndpointPublicCert() {
    return endpointPublicCert;
  }

  public boolean isExpired() {
    return isAboutToExpire(0);
  }

  public boolean isAboutToExpire(long offsetSeconds) {
    return isAboutToExpire(offsetSeconds, SECONDS);
  }

  public boolean isAboutToExpire(long offset, TemporalUnit unit) {
    Instant now = Instant.now();

    if (LOG.isDebugEnabled()) {
      LOG.debug("Knox token expiration:" +
              "\n\tExpires in:\t{} seconds" +
              "\n\tOffset:\t{} seconds" +
              "\n\tTime left:\t{} seconds",
          expiry - now.getEpochSecond(),
          Duration.of(offset, unit).getSeconds(),
          expiry - now.plus(offset, unit).getEpochSecond());
    }

    // Expired if the expiration time is the same as or before the current time plus any offset.
    return !Instant.ofEpochSecond(expiry).isAfter(now.plus(offset, unit));
  }

  public boolean isValid() {
    return StringUtils.isNotEmpty(accessToken) && !isExpired();
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(128)
                                 .append("KnoxToken{origin=").append(origin)
                                 .append(", accessToken=").append(accessToken)
                                 .append(", TokenType=").append(tokenType)
                                 .append(", expiry=").append(expiry)
                                 .append(", endpointPublicCert=");

    if (StringUtils.isNotEmpty(endpointPublicCert)) {
      sb.append(endpointPublicCert, 0, Math.min(5, endpointPublicCert.length())).append("...");
    } else {
      sb.append("<unset>");
    }

    return sb.append('}').toString();

  }
}
