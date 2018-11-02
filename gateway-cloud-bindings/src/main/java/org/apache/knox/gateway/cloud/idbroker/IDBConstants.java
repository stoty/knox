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

package org.apache.knox.gateway.cloud.idbroker;

import org.apache.hadoop.io.Text;

public final class IDBConstants {

  public static final String IDBROKER_TOKEN = "fs.s3a.idbroker.token";

  public static final String IDBROKER_GATEWAY = "fs.s3a.idbroker.gateway";

  public static final String IDBROKER_USERNAME = "fs.s3a.idbroker.username";

  public static final String IDBROKER_PASSWORD = "fs.s3a.idbroker.password";

  /**
   * Path in local fs to a jks file where HTTPS certificates are found.
   */
  public static final String IDBROKER_TRUST_PATH =
      "fs.s3a.idbroker.trust.path";

  public static final String DEFAULT_CERTIFICATE_FILENAME
      = "gateway-client-trust.jks";

  /** set to null and the standard bonding takes over */
  public static final String DEFAULT_CERTIFICATE_PATH = null;
  public static final String DEFAULT_CERTIFICATE_PASSWORD = null;
      

  
  public static final String LOCAL_GATEWAY
      = "https://localhost:8443/gateway/";

  public static final String ADMIN_USER = "admin";

  public static final String ADMIN_PASSWORD = "admin-password";

  /** Name of token: {@value}. */
  public static final String IDB_TOKEN_NAME = "S3ADelegationToken/IDBroker";

  /** Kind of token; value is {@link #IDB_TOKEN_NAME}. */
  public static final Text IDB_TOKEN_KIND = new Text(IDB_TOKEN_NAME);


  /**
   * How long can any of the secrets, role policy be.
   * Knox DTs can be long, so set this to a big value: {@value}
   */
  public static final int MAX_TEXT_LENGTH = 32768;


  /**
   * Token binding classname: {@value}.
   */
  public static final String DELEGATION_TOKEN_IDB_BINDING =
      "org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding";

  public static final String MIME_TYPE_JSON = "application/json";

  public static final String CLUSTERNAME = "dt";

  private IDBConstants() {
  }
}
