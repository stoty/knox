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

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URI;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.NoAwsCredentialsException;
import org.apache.hadoop.security.UserGroupInformation;

import static org.apache.knox.gateway.cloud.idbroker.IDBClient.buildDiagnosticsString;

/**
 * This is a special AWS authenticator which builds up a diagnostics string
 * during construction and then throws it on every failure.
 * This can be used to generat
 */
public class AlwaysFailToAuthenticate implements AWSCredentialsProvider {

  private final URI uri;

  private final Configuration conf;

  private final UserGroupInformation user;

  private final String diagnosticsText;

  public AlwaysFailToAuthenticate(@Nullable URI fsUri, Configuration conf)
      throws IOException {
    this.uri = fsUri;
    this.user = UserGroupInformation.getCurrentUser();
    this.conf = conf;
    diagnosticsText = "Authentication disabled for " +
        buildDiagnosticsString(uri, user);
  }

  @Override
  public AWSCredentials getCredentials() {
    throw new NoAwsCredentialsException(diagnosticsText);
  }

  @Override
  public void refresh() {

  }
}
