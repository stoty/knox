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

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.securitytoken.model.AWSSecurityTokenServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AUtils;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.knox.gateway.shell.KnoxSession;

/**
 * AWS credential provider which does the e2e login and GET.
 */
public class IDBAWSCredentialProvider implements AWSCredentialsProvider,
    Closeable {

  public static final String NAME
      = "org.apache.knox.gateway.cloud.idbroker.IDBAWSCredentialProvider";

  private static final Logger LOG =
      LoggerFactory.getLogger(IDBAWSCredentialProvider.class);

  private final IDBClient idbClient = new IDBClient(
      IDBConstants.LOCAL_GATEWAY, IDBConstants.DEFAULT_CERTIFICATE_PATH,
      IDBConstants.DEFAULT_CERTIFICATE_PASSWORD);

  private MarshalledCredentials sessionCreds;

  /**
   * Instantiate.
   * This calls {@link #getCredentials()} to fail fast on the inner
   * role credential retrieval.
   * @param fsUri URI of the filesystem.
   * @param conf configuration
   * @throws IOException on IO problems and some parameter checking
   * @throws IllegalArgumentException invalid parameters
   * @throws AWSSecurityTokenServiceException problems getting credentials
   */
  public IDBAWSCredentialProvider(URI fsUri, Configuration conf)
      throws IOException {

    LOG.info("Using IDB AWS Credential Provider");

    String bucket = fsUri.getHost();
    String delegationToken = S3AUtils.lookupPassword(bucket, conf,
        IDBConstants.IDBROKER_TOKEN, "");
    if (delegationToken.isEmpty()) {
      throw new IOException("Unset property " + IDBConstants.IDBROKER_TOKEN);
    }
    final KnoxSession session = idbClient.cloudSessionFromDT(delegationToken);
    sessionCreds = idbClient.fetchAWSCredentials(session);
    getCredentials();
  }

  @Override
  public AWSCredentials getCredentials() {
    return sessionCreds.getCredentials();
  }

  @Override
  public void refresh() {
    LOG.info("refresh");
  }

  @Override
  public void close() throws IOException {
    LOG.info("Closing");
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBAWSCredentialProvider{");
    sb.append("sessionCreds=").append(sessionCreds.toString());
    sb.append(", idbClient=").append(idbClient);
    sb.append('}');
    return sb.toString();
  }
}
