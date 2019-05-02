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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.knox.gateway.cloud.idbroker.common.UTCClock;

import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;
import static org.apache.knox.gateway.cloud.idbroker.IDBClient.tokenToPrintableString;
import static org.apache.knox.gateway.cloud.idbroker.common.UTCClock.millisToDateTime;

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
   * @param endpointCertificate Public certificate for IDB endpoints
   */
  public IDBTokenPayload(final String accessToken,
                         final String endpoint,
                         final long expiryTime,
                         final long issueTime,
                         final String correlationId,
                         final String endpointCertificate) {

    this.accessToken = checkNotNull(accessToken);
    this.endpoint = checkNotNull(endpoint);
    this.expiryTime = expiryTime;
    this.issueTime = issueTime;
    this.correlationId = correlationId;
    this.certificate = endpointCertificate;
  }

  /**
   * Empty constructor: for use when unmarshalling the data.
   * The fields are non empty -this does not means that the 
   * payload is "valid" as far as {@link #validate(boolean)} is concerned.
   */
  public IDBTokenPayload() {
    this("", "", 0, 0, "", "");
  }

  /**
   * Knox token used.
   */
  private String accessToken;

  /**
   * URL for retrieving the store tokens for this FS.
   * For example: The cab-gcs, cab-aws URL. Not the endpoint
   * for retrieving IDB tokens, as that is already to have been pre-acquired.
   */
  private String endpoint;

  /**
   * Timestamp when the token was issued.
   */
  private long issueTime;

  /**
   * Expiry time, UTC seconds since the epoch.
   */
  private long expiryTime;

  /**
   * Correlation ID for logs.
   */
  private String correlationId;
  
  /**
   * Marshalled certificate data.
   */
  private String certificate;

  @Override
  public void write(final DataOutput out) throws IOException {
    out.writeLong(issueTime);
    out.writeLong(expiryTime);
    Text.writeString(out, accessToken);
    Text.writeString(out, endpoint);
    Text.writeString(out, correlationId);
    Text.writeString(out, certificate);
  }

  @Override
  public void readFields(final DataInput in) throws IOException {
    issueTime = in.readLong();
    expiryTime = in.readLong();
    accessToken = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    endpoint = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    correlationId = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
    certificate = Text.readString(in, IDBConstants.MAX_TEXT_LENGTH);
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

  /**
   * Get the expiry time as a datetime; empty if the expiry was 0.
   * @return the instant when the Knox token expires.
   */
  public Optional<OffsetDateTime> getExpiryDateTime() {
    return expiryTime == 0
        ? Optional.empty()
        : Optional.of(
            OffsetDateTime.ofInstant(
                new Date(
                    TimeUnit.SECONDS.toMillis(expiryTime)).toInstant(),
                ZoneOffset.UTC));
  }

  /**
   * Get the certificate in the delegation token.
   * In a validated payload this may be empty, but never null.
   * @return a certificate or empty string.
   */
  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(final String certificate) {
  this.certificate = certificate;
}

  /**
   * Return the endpoint of the IDB service.
   * @return the IDB token endpoint.
   */
  public String getEndpoint() {
    return endpoint;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBTokenPayload{");
    sb.append("accessToken='").append(tokenToPrintableString(accessToken))
        .append('\'');
    sb.append(", issued=")
        .append(UTCClock.timeToString(millisToDateTime(issueTime)));
    sb.append(", expiry=").append(UTCClock.secondsToString(expiryTime));
    sb.append(", expiryTime=").append(expiryTime);
    sb.append(", endpoint=").append(endpoint);
    sb.append(", certificate=").append(certificate.isEmpty() 
        ? "empty"
        : (certificate.substring(0, Math.min(8, certificate.length())) + "..."));
    sb.append('}');
    return sb.toString();
  }

  /**
   * Minimal string for error messages and exceptions.
   *
   * @param type  token type, used at start of string.
   * @return a description.
   */
  public String errorMessageString(String type) {
    final StringBuilder sb = new StringBuilder(type + " ");
    sb.append("issued=")
        .append(UTCClock.timeToString(millisToDateTime(issueTime)));
    sb.append(", expiry=").append(UTCClock.secondsToString(expiryTime));
    sb.append(", endpoint=").append(endpoint);
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

  /**
   * Validate the data throwing an IOE or any runtime exception
   * related to state checking.
   * 
   * What is required for a valid payload:
   * <ol>
   *   <li>Non-empty gateway access token</li>
   *   <li>Non-empty gateway endpoint</li>
   *   <li>always: non-null gateway certificate</li>
   *   <li>optionally: Non-empty gateway certificate</li>
   *   <li>Correlation ID is non-null; may be empty</li>
   * </ol>
   * There are no checks on timestamp validity.
   * @param requireCertificate is the certificate required to be non-empty?
   * @throws IOException IO failure.
   */
  public void validate(boolean requireCertificate) throws IOException {
    checkValid("accessToken", accessToken);
    checkValid("endpoint", endpoint);
    checkValid("correlationId", correlationId);
    checkNotNull(certificate, "Null certificate field");
    if (requireCertificate) {
      checkValid("certificate", certificate);
    }
  }
  
  private void checkValid(String fieldname, String field) {
    checkNotNull(field, "Null " + fieldname);
    checkState(!field.isEmpty(), "Empty " + fieldname);
  }
    
}
