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

public final class IDBConstants {

  /**
   * set to null and the standard bonding takes over
   */
  public static final String DEFAULT_CERTIFICATE_PATH = null;
  public static final String DEFAULT_CERTIFICATE_PASSWORD = null;

  /**
   * {@value}.
   */
  public static final String LOCAL_GATEWAY = "https://localhost:8443/gateway/";

  /**
   * {@value}.
   */
  public static final String IDBROKER_GATEWAY_DEFAULT = LOCAL_GATEWAY;

  /**
   * {@value}.
   */
  public static final String IDBROKER_DT_PATH_DEFAULT = "dt";

  /**
   * How long can any of the secrets, role policy be.
   * Knox DTs can be long, so set this to a big value: {@value}
   */
  public static final int MAX_TEXT_LENGTH = 32768;

  public static final String MIME_TYPE_JSON = "application/json";

  /**
   * Name of the Hadoop configuration option which controls authentication: {@value}.
   */
  public static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";

  public static final String IDBROKER_CREDENTIALS_KERBEROS = "kerberos";

  public static final String IDBROKER_CREDENTIALS_BASIC_AUTH = "basic-auth";

  public static final String HADOOP_AUTH_SIMPLE = "simple";

  public static final String HADOOP_AUTH_KERBEROS = "kerberos";

  public static final String DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_LOCATION = "ssl.client.truststore.location";

  public static final String DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_PASS = "ssl.client.truststore.password";

  public static final String IDBROKER_DT_EXPIRATION_OFFSET_SECONDS_DEFAULT = "120";

  private IDBConstants() {
  }
}
