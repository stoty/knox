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

  /** Configuration prefix for S3A extensions: {@value}. */
  public static final String FS_S3A_EXT = "fs.s3a.ext.";

  /** Prefix for all IDBroker extensions : {@value}.  */
  public static final String CAB = FS_S3A_EXT + "cab.";

  /** URL to IDB: {@value}. */
  public static final String IDBROKER_GATEWAY = CAB +"address";

  /** {@value}. */
  public static final String IDBROKER_USERNAME = CAB + "username";

  /** {@value}. */
  public static final String IDBROKER_PASSWORD = CAB + "password";
  
  /**
   * Should the S3A Delegation Token include the AWS Secrets?
   * For testing token refresh, setting this to false guarantees immediate
   * AWS Credential renewal on first use.
   * Value {@value}.
   */
  public static final String DELEGATION_TOKENS_INCLUDE_AWS_SECRETS =
      CAB +"delegation.tokens.include.aws.secrets";

  /**
   * Path in local fs to a jks file where HTTPS certificates are found.
   * {@value}.
   */
  public static final String IDBROKER_TRUSTSTORE_LOCATION =
      CAB + "truststore.location";

  /** {@value}. */
  public static final String IDBROKER_TRUSTSTORE_PASS = CAB + "truststore.pass";

  /**
   * fs.(s3a | gs | abfs).ext.cab.required.group - group name.
   * this is used to disambiguate the situation where there are multiple
   * group mappings and we need to specify which group should be used to
   * choose the desired role mapping.
   * This will result in the CAB API that specifies the desired group->role
   * mapping to be used.
   * {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group/{groupid})}
   */
  public static final String IDBROKER_SPECIFIC_GROUP_METHOD = CAB + "required.group";

  public static final String IDBROKER_SPECIFIC_GROUP_DEFAULT = "";

  /**
   * fs.(s3a | gs | abfs).ext.cab.required.role -role id.
   *  this allows the job submitter to indicate that the specified role
   *  is required for the job.
   *  This will result in the CAB API to retrieve credentials for a given role
   *  to be used.
   */
  public static final String IDBROKER_SPECIFIC_ROLE_METHOD = CAB + "required.role";

  /**
   * Default value for {@link #IDBROKER_SPECIFIC_ROLE_METHOD}.
   */
  public static final String IDBROKER_SPECIFIC_ROLE_DEFAULT = "";
  
  /**
   *  Boolean: switch to group role over group roles: {@value}.
   *  this is interpreted as meaning that the CAB API for acquiring
   *  credentials for the role mapped to a group even if there is a
   *  user mapping.
   *  e.g.
   *  {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group}
   */
  public static final String IDBROKER_ONLY_GROUPS_METHOD = CAB + "employ.group.role";

  /**
   *  Boolean: switch to user role over group roles: {@value}.
   *  this means interrogate user mapping and not check group mappings
   *  for this job submission.
   *
   *  e.g.
   *  {@code https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/user}
   */
  public static final String IDBROKER_ONLY_USER_METHOD = CAB + "employ.user.role";

  public static final String IDBROKER_TRUSTSTORE_PASSWORD =
      CAB +"truststore.password";

  /** {@value}. */
  public static final String DEFAULT_CERTIFICATE_FILENAME
      = "gateway-client-trust.jks";

  /** set to null and the standard bonding takes over */
  public static final String DEFAULT_CERTIFICATE_PATH = null;
  public static final String DEFAULT_CERTIFICATE_PASSWORD = null;

  /** {@value}. */
  public static final String LOCAL_GATEWAY
      = "https://localhost:8443/gateway/";

  /** {@value}. */
  public static final String IDBROKER_GATEWAY_DEFAULT = LOCAL_GATEWAY;

  /** {@value}. */
  public static final String IDBROKER_AWS_PATH
      = CAB +"path";

  /** {@value}. */
  public static final String IDBROKER_DT_PATH
      = CAB +"dt.path";
  
  /** {@value}. */
  public static final String IDBROKER_AWS_PATH_DEFAULT =
      "aws-cab";

  /** {@value}. */
  public static final String IDBROKER_DT_PATH_DEFAULT =
      "dt";

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

  public static final String ID_BROKER = "IDBroker";

  /**
   * What credentials to support: kerberos or
   */
  public static final String IDBROKER_CREDENTIALS_TYPE =
      "fs.s3a.ext.idbroker.credentials.type";

  /**
   * Name of the Hadoop configuration option which controls authentication: {@value}.
   */
  public static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";

  public static final String IDBROKER_CREDENTIALS_KERBEROS = "kerberos";

  public static final String IDBROKER_CREDENTIALS_BASIC_AUTH
      = "basic-auth";


  /** Name of token: {@value}. */
  public static final String IDB_ABFS_TOKEN_NAME
      = "ABFS/IDBroker";


  /** Kind of token; value is {@link #IDB_ABFS_TOKEN_NAME}. */
  public static final Text IDB_ABFS_TOKEN_KIND = new Text(IDB_ABFS_TOKEN_NAME);


  /**
   * This is the canonical name of the ABFS DT, at least until we can
   * get the real FS name into the plugins: {@value}.
   */
  public static final String IDB_ABFS_CANONICAL_NAME = 
      "abfs://canonical.fs.name/";

  public static final Text TEXT_IDB_ABFS_CANONICAL_NAME =
      new Text(IDB_ABFS_CANONICAL_NAME);
  
  private IDBConstants() {
  }
}
