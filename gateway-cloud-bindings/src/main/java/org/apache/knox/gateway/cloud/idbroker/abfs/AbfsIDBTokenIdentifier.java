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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.knox.gateway.cloud.idbroker.common.IDBTokenPayload;
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MAX_TEXT_LENGTH;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBConstants.IDB_TOKEN_KIND;

/**
 * Token identifier used in ABFS DT support.
 */
public class AbfsIDBTokenIdentifier extends DelegationTokenIdentifier {

  /** Canonical URI of the bucket. */
  private URI uri;

  /**
   * Timestamp of creation.
   * This is set to the current time; it will be overridden when
   * deserializing data.
   */
  private long created = System.currentTimeMillis();

  /**
   * An origin string for diagnostics.
   */
  private String origin = "";

  /**
   * This marshalled UUID can be used in testing to verify transmission,
   * and reuse; as it is printed you can see what is happening too.
   */
  private String uuid = UUID.randomUUID().toString();

  private IDBTokenPayload payload = new IDBTokenPayload();

  private OAuthPayload marshalledCredentials
      = new OAuthPayload();

  public AbfsIDBTokenIdentifier() {
    super(IDB_TOKEN_KIND);
  }

  public AbfsIDBTokenIdentifier(
      final URI uri,
      final Text owner,
      final Text renewer,
      final String origin,
      final String accessToken,
      final long expiryTime,
      final OAuthPayload marshalledCredentials,
      final long issueTime,
      final String correlationId,
      final String endpoint,
      final String endpointCertificate,
      final boolean managed) {

    super(IDB_TOKEN_KIND, owner, renewer, new Text());
    this.uri = requireNonNull(uri);
    this.origin = requireNonNull(origin);
    this.marshalledCredentials = requireNonNull(marshalledCredentials);
    this.payload = new IDBTokenPayload(accessToken, endpoint, expiryTime, issueTime,
        correlationId, endpointCertificate, managed);
  }

  /**
   * Get the knox token in this identifier.
   * @return the knox token.
   */
  public String getAccessToken() {
    return payload.getAccessToken();
  }

  /**
   * Return the expiry time in seconds since 1970-01-01.
   * @return the time when the AWS session credentials expire.
   */
  public long getExpiryTime() {
    return payload.getExpiryTime();
  }

  public URI getUri() {
    return uri;
  }

  public String getOrigin() {
    return origin;
  }

  public void setOrigin(final String origin) {
    this.origin = origin;
  }

  public long getCreated() {
    return created;
  }

  public String getUuid() {
    return uuid;
  }

  public IDBTokenPayload getPayload() {
    return payload;
  }

  public OAuthPayload getMarshalledCredentials() {
    return marshalledCredentials;
  }

  /**
   * Get the certificate in the delegation token.
   * In a validated token this may be empty, but never null.
   * @return a certificate or empty string.
   */
  public String getCertificate() {
    return payload.getCertificate();
  }

  /**
   * Return the endpoint of the IDB service.
   * @return the IDB token endpoint.
   */
  public String getEndpoint() {
    return payload.getEndpoint();
  }

  public boolean isManaged() {
    return payload.isManaged();
  }

  /*
  /**
   * Write state.
   * {@link org.apache.hadoop.io.Writable#write(DataOutput)}.
   * @param out destination
   * @throws IOException failure
   */
  @Override
  public void write(final DataOutput out) throws IOException {
    super.write(out);
    Text.writeString(out, uri.toString());
    Text.writeString(out, origin);
    Text.writeString(out, uuid);
    out.writeLong(created);
    payload.write(out);
    marshalledCredentials.write(out);
  }

  /**
   * Read state.
   * {@link org.apache.hadoop.io.Writable#readFields(DataInput)}.
   *
   * Note: this operation gets called in toString() operations on tokens, so
   * must either always succeed, or throw an IOException to trigger the
   * catch & downgrade. RuntimeExceptions (e.g. Preconditions checks) are
   * not to be used here for this reason.)
   *
   * @param in input stream
   * @throws IOException IO problems.
   */
  @Override
  public void readFields(final DataInput in)
      throws IOException {
    super.readFields(in);
    uri = URI.create(Text.readString(in, MAX_TEXT_LENGTH));
    origin = Text.readString(in, MAX_TEXT_LENGTH);
    uuid = Text.readString(in, MAX_TEXT_LENGTH);
    created = in.readLong();
    payload.readFields(in);
    marshalledCredentials.readFields(in);
  }

  @Override
  public String toString() {
    return "AbfsIDBTokenIdentifier{" + "uri=" + uri +
                    ", uuid='" + uuid + '\'' +
                    ", created='" + new Date(created) + '\'' +
                    ", origin='" + origin + '\'' +
                    ", payload=" + payload +
                    ", oathCredentials=" + marshalledCredentials +
                    '}';
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) { return true; }
    if (o == null || getClass() != o.getClass()) { return false; }
    if (!super.equals(o)) { return false; }
    final AbfsIDBTokenIdentifier that = (AbfsIDBTokenIdentifier) o;
    return uri.equals(that.uri) &&
        uuid.equals(that.uuid);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), uri, uuid);
  }

}
