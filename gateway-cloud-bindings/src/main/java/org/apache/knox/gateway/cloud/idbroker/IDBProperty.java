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

public interface IDBProperty {
  String PROPERTY_PREFIX = "fs";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The base URL for the Knox Gateway or IDBroker server.
   * <p>
   * Example {@code https://localhost:8443/gateway/}
   */
  String PROPERTY_SUFFIX_GATEWAY = ".ext.cab.address";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The username to use to access the IDBroker if the authentication method
   * ({@value IDBConstants#HADOOP_SECURITY_AUTHENTICATION}) is {@value IDBConstants#HADOOP_AUTH_SIMPLE}
   * and {@value #PROPERTY_SUFFIX_CREDENTIALS_TYPE} is {@value IDBConstants#IDBROKER_CREDENTIALS_BASIC_AUTH}
   */
  String PROPERTY_SUFFIX_USERNAME = ".ext.cab.username";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The password to use to access the IDBroker if the authentication method
   * ({@value IDBConstants#HADOOP_SECURITY_AUTHENTICATION}) is {@value IDBConstants#HADOOP_AUTH_SIMPLE}
   * and {@value #PROPERTY_SUFFIX_CREDENTIALS_TYPE} is {@value IDBConstants#IDBROKER_CREDENTIALS_BASIC_AUTH}
   */
  String PROPERTY_SUFFIX_PASSWORD = ".ext.cab.password";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The absolute path to the truststore to use for trusting the certificate provided by the Knox Gateway or IDBroker.
   */
  String PROPERTY_SUFFIX_TRUSTSTORE_LOCATION = ".ext.cab.truststore.location";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The password to access to configured truststore. If not set, the password is expected to be set
   * in the Hadoop credential store.
   * <p>
   * This is the same as {@value #PROPERTY_SUFFIX_TRUSTSTORE_PASS}. If both this and {@value #PROPERTY_SUFFIX_TRUSTSTORE_PASS}
   * are set, {@link #PROPERTY_SUFFIX_TRUSTSTORE_PASS} will take precedence.
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_PASS
   */
  String PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD = ".ext.cab.truststore.password";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * The password to access to configured truststore. If not set, the password is expected to be set
   * in the Hadoop credential store.
   * <p>
   * This is the same as {@value #PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD}. If both this and {@value #PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD}
   * are set, this will take precedence.
   */
  String PROPERTY_SUFFIX_TRUSTSTORE_PASS = ".ext.cab.truststore.pass";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * Group name used to disambiguate the situation where there are multiple group mappings and we
   * need to specify which group should be used to choose the desired role mapping.
   * This will result in the CAB API that specifies the desired group->role mapping to be used.
   * <p>
   * Example:
   * <pre>
   * {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group/{groupid})}
   * </pre>
   */
  String PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD = ".ext.cab.required.group";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * Role id that allows the job submitter to indicate that the specified role is required for the job.
   * This will result in the CAB API to retrieve credentials for a given role to be used.
   */
  String PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD = ".ext.cab.required.role";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * A Boolean value used to switch to group role over group roles. This is interpreted as meaning
   * that the CAB API for acquiring credentials for the role mapped to a group even if there is a
   * user mapping.
   * <p>
   * Example:
   * <pre>
   * {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group}
   * </pre>
   */
  String PROPERTY_SUFFIX_ONLY_GROUPS_METHOD = ".ext.cab.employ.group.role";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * A Boolean value used to switch to user role over group roles.  This means interrogate user
   * mapping and not check group mappings for this job submission.
   * <p>
   * Example:
   * <pre>
   * {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/user}
   * </pre>
   */
  String PROPERTY_SUFFIX_ONLY_USER_METHOD = ".ext.cab.employ.user.role";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * Relative path, from IDBroker base URL, for the endpoint to obtain a cloud storage access token
   * <p>
   * Example {@code aws-cab} will yield something like {@code https://localhost:8443/gateway/aws-cab}
   *
   * @see #PROPERTY_SUFFIX_GATEWAY
   */
  String PROPERTY_SUFFIX_PATH = ".ext.cab.path";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * Relative path, from IDBroker base URL, for the endpoint to obtain a Knox delegation token
   * <p>
   * Example {@code dt} will yield something like {@code https://localhost:8443/gateway/dt}
   *
   * @see #PROPERTY_SUFFIX_GATEWAY
   */
  String PROPERTY_SUFFIX_DT_PATH = ".ext.cab.dt.path";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * Time, in seconds, from the Knox delegation token's expiration time for which to consider obtaining
   * a new delegation token so the cached one does not expire.
   * <p>
   * Example {@code 120} will yield {@code 120 seconds}
   */
  String PROPERTY_SUFFIX_DT_EXPIRATION_OFFSET = ".ext.cab.dt.path.expiration.offset";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * What credentials to support: {@value IDBConstants#IDBROKER_CREDENTIALS_KERBEROS} or {@value IDBConstants#IDBROKER_CREDENTIALS_BASIC_AUTH}
   */
  String PROPERTY_SUFFIX_CREDENTIALS_TYPE = ".ext.idbroker.credentials.type";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * A Boolean property indicating whether or not to include an initial set of cloud credentials in delegation tokens.
   */
  String PROPERTY_SUFFIX_INIT_CAB_CREDENTIALS = ".ext.cab.init.credentials";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * A Boolean property indicating weather to use the certificate provided in the IDBroker's delegation
   * token or not.
   */
  String PROPERTY_SUFFIX_USE_DT_CERT = ".ext.cab.use.dt.cert";

  /**
   * Added to "fs.(s3a | gs | abfs)" to get the relevant property name for the cloud storage provider.
   * <p>
   * This is for testing purposes only.
   * <p>
   * The path to a JSON document containing an IDBroker response to a get credentials request.  The
   * access token in this document will be used in initial calls to get an access token.  Subsequent
   * calls to get access tokens may follow non-testing logic, where a new (or valid) access token
   * will be retried, if necessary.
   */
  String PROPERTY_SUFFIX_TEST_TOKEN_PATH = ".ext.cab.test.token.path";

  /**
   * Returns the property name for this property
   *
   * @return a property name
   */
  String getPropertyName();

  /**
   * Returns the default value for this property
   *
   * @return a default value or {@code null} if there is no default value
   */
  String getDefaultValue();
}
