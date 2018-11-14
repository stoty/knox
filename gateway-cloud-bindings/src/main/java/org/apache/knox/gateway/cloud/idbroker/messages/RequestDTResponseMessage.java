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

package org.apache.knox.gateway.cloud.idbroker.messages;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.fs.s3a.commit.ValidationFailure;

/**
 * Response from a DT request.
 */
public class RequestDTResponseMessage {

  public static final String BEARER_TOKEN = "Bearer";

  public String access_token;

  public String token_type;

  public String target_url;

  public BigInteger expires_in;

  public RequestDTResponseMessage validate() throws IOException {
    ValidationFailure.verify(StringUtils.isNotEmpty(access_token),
        "Empty Access Token");
    ValidationFailure.verify(BEARER_TOKEN.equals(token_type),
        "Token type isn't %s: %s",
        BEARER_TOKEN, token_type);
    return this;
  }

  /**
   * Get the expiry time in seconds.
   * @return expiry time converted to seconds.
   */
  public long expiryTimeSeconds() {

    return expires_in != null
        ? TimeUnit.MILLISECONDS.toSeconds(expires_in.longValue())
        : 0;
  }

}
