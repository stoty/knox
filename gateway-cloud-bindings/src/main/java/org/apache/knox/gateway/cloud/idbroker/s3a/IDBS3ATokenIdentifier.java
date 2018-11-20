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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_TOKEN_KIND;

/**
 * IDB Token identifier: contains AWS credentials; knox token,
 * role policy and an expiry time of the knox token.
 */
public class IDBS3ATokenIdentifier extends AbstractS3ATokenIdentifier {

  /**
   * Knox token used.
   */
  private String accessToken;

  /**
   * Expiry time, seconds since the epoch.
   */
  private long expiryTime;

  /**
   * Session credentials: initially empty but non-null.
   */
  private MarshalledCredentials marshalledCredentials
      = new MarshalledCredentials();

  /** The role policy or an empty string */
  private String rolePolicy = "";

  /**
   * Constructor for service loader use.
   * Subclasses MUST NOT subclass this; they must provide their own
   * token kind.
   */
  public IDBS3ATokenIdentifier() {
    super(IDB_TOKEN_KIND);
  }

  /**
   * Constructor.
   * @param kind token kind.
   * @param owner token owner
   * @param uri filesystem URI.
   * @param accessToken knox token
   * @param expiryTime expiry in seconds since the epoch
   * @param marshalledCredentials credentials to marshall
   * @param encryptionSecrets encryption secrets
   * @param rolePolicy role policy to marshal.
   * @param origin origin text for diagnostics.
   */
  public IDBS3ATokenIdentifier(
      final Text kind,
      final Text owner,
      final URI uri,
      final String accessToken,
      final long expiryTime,
      final MarshalledCredentials marshalledCredentials,
      final EncryptionSecrets encryptionSecrets,
      final String rolePolicy,
      final String origin) {
    super(kind, uri, owner, origin, encryptionSecrets);
    this.marshalledCredentials = checkNotNull(marshalledCredentials);
    this.expiryTime = expiryTime;
    this.accessToken = checkNotNull(accessToken);
    this.rolePolicy = checkNotNull(rolePolicy);
  }

  @Override
  public void write(final DataOutput out) throws IOException {
    super.write(out);
    marshalledCredentials.write(out);
    out.writeLong(expiryTime);
    Text.writeString(out, accessToken);
    Text.writeString(out, rolePolicy);
  }

  @Override
  public void readFields(final DataInput in)
      throws IOException {
    super.readFields(in);
    marshalledCredentials.readFields(in);
    expiryTime = in.readLong();
    accessToken = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    rolePolicy = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBroker S3ATokenIdentifier{");
    sb.append(super.toString());

    sb.append("; knoxToken='").append(
        StringUtils.isNotEmpty(accessToken)
            ? (accessToken.substring(0, 8) + "...")
            : "(unset)")
        .append('\'');
    sb.append(", expiry Time=").append(expiryTime);
    sb.append(", expiry Date=").append(
        new Date(TimeUnit.SECONDS.toMillis(expiryTime)));
    sb.append(", AWS Credentials=").append(marshalledCredentials);
    sb.append("; ");
    sb.append('}');
    return sb.toString();
  }

  /**
   * Return the expiry time in seconds since 1970-01-01.
   * @return the time when the AWS session credentials expire.
   */
  @Override
  public long getExpiryTime() {
    return expiryTime;
  }

  /**
   * Get the session credentials.
   * @return session credentials.
   */
  public MarshalledCredentials getMarshalledCredentials() {
    return marshalledCredentials;
  }

  /**
   * Get the knox token in this identifier.
   * @return the knox token.
   */
  public String getAccessToken() {
    return accessToken;
  }

  public String getRolePolicy() {
    return rolePolicy;
  }
}
