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

import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IDBTokenPayload;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_TOKEN_KIND;

/**
 * IDB Token identifier: contains AWS credentials; knox token,
 * role policy and an expiry time of the knox token.
 * 
 * <i>Warning</i>: the class gets loaded in places such as the YARN Resource Manager;
 * for that to work it MUST NOT have dependencies on external libraries
 * which may not be on the classpath.
 * All the S3A classes deliberately avoid direct and indirect references to
 * AWS SDK classes for this very reason.
 */
public class IDBS3ATokenIdentifier extends AbstractS3ATokenIdentifier {

  private IDBTokenPayload payload  = new IDBTokenPayload();

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
   * @param issueTime Timestamp when the token was issued.
   * @param correlationId Correlation ID for logs
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
      final String origin,
      final long issueTime,
      final String correlationId) {
    super(kind, uri, owner, origin, encryptionSecrets);
    this.marshalledCredentials = checkNotNull(marshalledCredentials);
    this.payload = new IDBTokenPayload(accessToken, "", expiryTime, issueTime,
        correlationId);
    this.rolePolicy = checkNotNull(rolePolicy);
  }

  @Override
  public void write(final DataOutput out) throws IOException {
    super.write(out);
    payload.write(out);
    marshalledCredentials.write(out);
    Text.writeString(out, rolePolicy);
  }

  @Override
  public void readFields(final DataInput in)
      throws IOException {
    super.readFields(in);
    payload.readFields(in);
    marshalledCredentials.readFields(in);
    rolePolicy = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBroker S3ATokenIdentifier{");
    sb.append(super.toString());

    sb.append(payload);
    sb.append(", AWS Credentials=").append(marshalledCredentials);
    sb.append(", rolePolicy=").append(rolePolicy);
    sb.append('}');
    return sb.toString();
  }

  /**
   * Return the expiry time in seconds since 1970-01-01.
   * @return the time when the AWS session credentials expire.
   */
  @Override
  public long getExpiryTime() {
    return payload.getExpiryTime();
  }

  /**
   * Get the marshalled credentials, which may be empty.
   * @return marshalled credentials.
   */
  public MarshalledCredentials getMarshalledCredentials() {
    return marshalledCredentials;
  }

  /**
   * Does this identifier have a non-empty set of credentials.
   * @return true if the credentials are not considered empty.
   */
  public boolean hasMarshalledCredentials() {
    return !marshalledCredentials.isEmpty();
  }

  /**
   * Get the knox token in this identifier.
   * @return the knox token.
   */
  public String getAccessToken() {
    return payload.getAccessToken();
  }

  public String getRolePolicy() {
    return rolePolicy;
  }
}
