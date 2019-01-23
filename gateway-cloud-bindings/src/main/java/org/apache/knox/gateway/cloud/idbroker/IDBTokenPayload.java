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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Objects;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBClient.expiryDate;
import static org.apache.knox.gateway.cloud.idbroker.IDBClient.tokenToPrintableString;

/**
 * This is a payload for the IDB bindings, independent of the specific
 * filesystem token information.
 */
public class IDBTokenPayload implements Writable {

  /**
   * @param accessToken knox token
   * @param endpoint URL for retrieving the store tokens for this FS.
   * @param expiryTime expiry in seconds since the epoch
   * @param issueTime Timestamp when the token was issued.
   * @param correlationId Correlation ID for logs
   */
  public IDBTokenPayload(final String accessToken,
      final String endpoint,
      final long expiryTime,
      final long issueTime,
      final String correlationId) {
    this.accessToken = checkNotNull(accessToken);
    this.endpoint = checkNotNull(endpoint);
    this.expiryTime = expiryTime;
    this.issueTime = issueTime;
    this.correlationId = correlationId;
  }

  public IDBTokenPayload() {
    this("", "", 0, 0, "");
  }

  /**
   * Knox token used.
   */
  private String accessToken;

  /**
   * URL for retrieving the store tokens for this FS.
   */
  private String endpoint;

  /**
   * Timestamp when the token was issued.
   */
  private long issueTime;

  /**
   * Expiry time, seconds since the epoch.
   */
  private long expiryTime;

  /**
   * Correlation ID for logs.
   */
  private String correlationId;
  
  /**
   * Marshalled certificate data.
   */
  private BytesWritable certificate = new BytesWritable();
  
  @Override
  public void write(final DataOutput out) throws IOException {
    out.writeLong(issueTime);
    out.writeLong(expiryTime);
    Text.writeString(out, accessToken);
    Text.writeString(out, endpoint);
    Text.writeString(out, correlationId);
    certificate.write(out);
  }

  @Override
  public void readFields(final DataInput in) throws IOException {
    issueTime = in.readLong();
    expiryTime = in.readLong();
    accessToken = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    endpoint = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    correlationId = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    certificate.readFields(in);
  }

  public String getAccessToken() {
    return accessToken;
  }

  public void setAccessToken(final String accessToken) {
    this.accessToken = accessToken;
  }

  public long getExpiryTime() {
    return expiryTime;
  }

  public void setExpiryTime(final long expiryTime) {
    this.expiryTime = expiryTime;
  }

  public BytesWritable getCertificate() {
    return certificate;
  }

  public void setCertificate(final BytesWritable certificate) {
    this.certificate = certificate;
  }

  public String getEndpoint() {
    return endpoint;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBTokenPayload{");
    sb.append("accessToken='").append(tokenToPrintableString(accessToken))
        .append('\'');
    sb.append(", expiryTime=").append(expiryTime);
    sb.append(", expiry Date=").append(expiryDate(expiryTime));
    sb.append(", certificate=").append(certificate.getLength() == 0 ?
        "empty" : ("byte array of size " + certificate.getLength()));
    sb.append('}');
    return sb.toString();
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) { return true; }
    if (o == null || getClass() != o.getClass()) { return false; }
    final IDBTokenPayload payload = (IDBTokenPayload) o;
    return Objects.equals(accessToken, payload.accessToken) &&
        Objects.equals(correlationId, payload.correlationId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accessToken, correlationId);
  }
}
