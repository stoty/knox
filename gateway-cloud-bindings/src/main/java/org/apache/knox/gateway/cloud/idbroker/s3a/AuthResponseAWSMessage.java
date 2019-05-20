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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import org.apache.hadoop.util.JsonSerialization;

/**
 * Marshalled JSON; expect IDEs and checkstyle to complain about choice of
 * field names.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonSerialize()
public class AuthResponseAWSMessage {

  public AssumedRoleUserStruct AssumedRoleUser;

  public CredentialsStruct Credentials;

  /**
   * Get a JSON serializer for this class.
   * @return a serializer.
   */
  public static JsonSerialization<AuthResponseAWSMessage> serializer() {
    return new JsonSerialization<>(AuthResponseAWSMessage.class, false, true);
  }

  public static class AssumedRoleUserStruct {

    public String AssumedRole;

    public String Arn;
  }

  public static class CredentialsStruct {

    public String AccessKeyId;

    public String SecretAccessKey;

    public String SessionToken;

    public long Expiration;
  }

}
