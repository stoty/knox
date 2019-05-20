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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.apache.hadoop.util.JsonSerialization;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Marshaled JSON data from IDBroker for an Azure access token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonSerialize
public class AbfsAuthResponseMessage {

  @JsonProperty("access_token")
  private String accessToken;

  @JsonProperty("expires_in")
  private Integer expiresIn;

  @JsonProperty("expires_on")
  private Long expiresOn;

  @JsonProperty("resource")
  private String resource;

  @JsonProperty("token_type")
  private String tokenType;

  /**
   * Get a JSON serializer for this class.
   *
   * @return a serializer.
   */
  public static JsonSerialization<AbfsAuthResponseMessage> serializer() {
    return new JsonSerialization<>(AbfsAuthResponseMessage.class, false, true);
  }

  /**
   * Calculates the expiry in UTC for the access token in this AbfsAuthResponseMessage.
   * <p>
   * If <code>expires_on</code> is set, the use it over the <code>expires_in</code> value.  If neither
   * are set, assume the expiry is now.
   *
   * @return the calculated expiry (in UTC) for the access token in this AbfsAuthResponseMessage
   */
  public Instant getExpiry() {
    Instant instant;

    if (expiresOn != null) {
      instant = Instant.ofEpochSecond(expiresOn);
    } else if (expiresIn != null) {
      instant = Instant.now().plus(expiresIn, ChronoUnit.SECONDS);
    } else {
      instant = Instant.now();
    }

    return instant;
  }

  /**
   * Returns the access token type in this AbfsAuthResponseMessage.
   *
   * @return the access token; or <code>null</code> if not supplied
   */
  public String getAccessToken() {
    return accessToken;
  }

  /**
   * Returns the number of <b>seconds from the current time</b> when the access token in this
   * AbfsAuthResponseMessage will expire.
   *
   * @return seconds from current time, used to calculate expiry; or <code>null</code> if not supplied
   */
  public Integer getExpiresIn() {
    return expiresIn;
  }

  /**
   * Returns the number of <b>seconds from the Epoch</b>, indicating the exact time when the access
   * token in this AbfsAuthResponseMessage will expire.
   *
   * @return seconds from the Epoch, used to calculate expiry; or <code>null</code> if not supplied
   */
  public Long getExpiresOn() {
    return expiresOn;
  }

  /**
   * Returns the token type of the access token in this AbfsAuthResponseMessage.
   *
   * @return the token type; or <code>null</code> if not supplied
   */
  public String getTokenType() {
    return tokenType;
  }

  /**
   * Returns the relevant resource for the access token in this AbfsAuthResponseMessage.
   *
   * @return the relevant resource; or <code>null</code> if not supplied
   */
  public String getResource() {
    return resource;
  }
}
