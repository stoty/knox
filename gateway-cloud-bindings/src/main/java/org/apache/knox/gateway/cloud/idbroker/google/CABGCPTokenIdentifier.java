/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.cloud.idbroker.google;

import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.knox.gateway.cloud.idbroker.common.IDBTokenPayload;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;

public class CABGCPTokenIdentifier extends DelegationTokenIdentifier {

  /**
   * How long can any of the secrets, role policy be.
   * Knox DTs can be long, so set this to a big value: {@value}
   */
  protected static final int MAX_TEXT_LENGTH = 32768;

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
   * and reuse; as it is printed you can see what is happending too.
   */
  private String uuid = UUID.randomUUID().toString();


  /**
   * Knox token used.
   */
  private IDBTokenPayload payload = new IDBTokenPayload();

  private String tokenType = "BEARER";

  private GoogleTempCredentials marshalledCredentials = new GoogleTempCredentials();


  public CABGCPTokenIdentifier() {
    super(CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND);
  }

  protected CABGCPTokenIdentifier(Text kind) {
    super(kind);
  }

  protected CABGCPTokenIdentifier(Text kind, Text owner, Text renewer, Text realUser, URI uri, String origin) {
    super(kind, owner, renewer, realUser);
    this.uri = uri;
    this.origin = origin;
  }

  protected CABGCPTokenIdentifier(final Text kind,
                                  final Text owner,
                                  final URI uri,
                                  final String accessToken,
                                  final long expiryTime,
                                  final String tokenType,
                                  final String targetURL,
                                  final String origin) {
    this(kind, owner, uri, accessToken, expiryTime, tokenType, targetURL, null, null, origin);
  }

  protected CABGCPTokenIdentifier(final Text kind,
                                  final Text owner,
                                  final URI uri,
                                  final String accessToken,
                                  final long expiryTime,
                                  final String tokenType,
                                  final String targetURL,
                                  final String endpointCertificate,
                                  final GoogleTempCredentials marshalledCredentials,
                                  final String origin) {
    this(kind, owner, null, owner, uri, origin);

    this.payload = new IDBTokenPayload(accessToken,
                                       targetURL,
                                       expiryTime,
                                       0,
                                       "",
                                       endpointCertificate);
    if (tokenType != null) {
      this.tokenType = tokenType;
    }
    this.marshalledCredentials = marshalledCredentials;
  }

  public URI getUri() {
    return uri;
  }

  public String getOrigin() {
    return origin.toString();
  }

  public void setOrigin(final String origin) {
    this.origin = origin;
  }

  public long getCreated() {
    return created;
  }


  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    Text.writeString(out, uri.toString());
    Text.writeString(out, origin);
    Text.writeString(out, uuid);
    out.writeLong(created);
    payload.write(out);
    marshalledCredentials.write(out);
    Text.writeString(out, tokenType);
  }

  @Override
  public void readFields(DataInput in) throws DelegationTokenIOException, IOException {
    super.readFields(in);
    uri = URI.create(Text.readString(in, MAX_TEXT_LENGTH));
    origin = Text.readString(in, MAX_TEXT_LENGTH);
    uuid = Text.readString(in, MAX_TEXT_LENGTH);
    created = in.readLong();
    payload.readFields(in);
    marshalledCredentials.readFields(in);
    tokenType = Text.readString(in, MAX_TEXT_LENGTH);
  }

  /**
   * Validate the token by looking at its fields.
   * @throws IOException on failure.
   */
  public void validate() throws IOException {
    if (uri == null) {
      throw new DelegationTokenIOException("No URI in " + this);
    }
  }

  /**
   * Return the expiry time in seconds since 1970-01-01.
   * @return the time when the Knox token expires.
   */
  public long getExpiryTime() {
    return payload.getExpiryTime();
  }

  public String getTokenType() { return tokenType; }

  public String getTargetURL() {
    return payload.getEndpoint(); }

  public String getAccessToken() {
    return payload.getAccessToken();
  }

  public String getCertificate() {
    return payload.getCertificate();
  }

  public GoogleTempCredentials getMarshalledCredentials() {
    return marshalledCredentials;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("CloudAccessBroker GCPTokenIdentifier{");
    sb.append("GCPTokenIdentifier: ");
    sb.append(getKind());
    sb.append("; uri=").append(uri);
    sb.append("; timestamp=").append(created);
    sb.append("; uuid=").append(uuid);
    sb.append("; ").append(origin);
    sb.append(" ; ");
    sb.append(payload);
    sb.append("; GCP Credentials{").append(marshalledCredentials);
    sb.append("}; ");
    sb.append('}');
    return sb.toString();
  }

  /**
   * Get the UUID of this token identifier.
   * @return a UUID.
   */
  public String getUuid() {
    return uuid;
  }

  /**
   * Create the default origin text message with hostname and timestamp.
   * @return A string for token diagnostics.
   */
  public static String createDefaultOriginMessage() {
    return String.format("Created on %s at time %s.", NetUtils.getHostname(), java.time.Instant.now());
  }

  /**
   * Equality check is on superclass and URI only.
   * @param o other.
   * @return true if the base class considers them equal and the URIs match.
   */
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    final CABGCPTokenIdentifier that = (CABGCPTokenIdentifier) o;
    return Objects.equals(uuid, that.uuid) && Objects.equals(uri, that.uri);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), uri);
  }

}
