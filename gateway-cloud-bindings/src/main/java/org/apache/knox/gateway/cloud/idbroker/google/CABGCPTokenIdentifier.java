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

import com.google.cloud.hadoop.fs.gcs.auth.AbstractGCPTokenIdentifier;
import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.io.Text;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class CABGCPTokenIdentifier extends AbstractGCPTokenIdentifier {

  /**
   * Knox token used.
   */
  private String accessToken;

  private String tokenType = "BEARER";

  private String targetURL = null;

  /**
   * Expiry time, seconds since the epoch.
   */
  private long expiryTime;

  private GoogleTempCredentials marshalledCredentials = new GoogleTempCredentials();


  public CABGCPTokenIdentifier() {
    super(CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND);
  }

  protected CABGCPTokenIdentifier(final Text kind,
                                  final Text owner,
                                  final URI uri,
                                  final String accessToken,
                                  final long expiryTime,
                                  final String tokenType,
                                  final String targetURL,
                                  final String origin) {
    this(kind, owner, uri, accessToken, expiryTime, tokenType, targetURL, null, origin);
  }

  protected CABGCPTokenIdentifier(final Text kind,
                                  final Text owner,
                                  final URI uri,
                                  final String accessToken,
                                  final long expiryTime,
                                  final String tokenType,
                                  final String targetURL,
                                  final GoogleTempCredentials marshalledCredentials,
                                  final String origin) {
    super(kind, uri, owner, origin);
    this.accessToken = accessToken;
    this.expiryTime = expiryTime;
    this.targetURL = targetURL;
    if (tokenType != null) {
      this.tokenType = tokenType;
    }
    this.marshalledCredentials = marshalledCredentials;
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    marshalledCredentials.write(out);
    out.writeLong(expiryTime);
    Text.writeString(out, accessToken);
    Text.writeString(out, tokenType);
    Text.writeString(out, targetURL);
  }

  @Override
  public void readFields(DataInput in) throws DelegationTokenIOException, IOException {
    super.readFields(in);
    marshalledCredentials.readFields(in);
    expiryTime = in.readLong();
    accessToken = Text.readString(in, MAX_TEXT_LENGTH);
    tokenType = Text.readString(in, MAX_TEXT_LENGTH);
    targetURL = Text.readString(in, MAX_TEXT_LENGTH);
  }

  public long getExpiryTime() {
    return expiryTime;
  }

  public String getTokenType() { return tokenType; }

  public String getTargetURL() { return targetURL; }

  public String getAccessToken() {
    return accessToken;
  }

  public GoogleTempCredentials getMarshalledCredentials() {
    return marshalledCredentials;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("CloudAccessBroker GCPTokenIdentifier{");
    sb.append(super.toString());

    sb.append("; knoxToken='")
      .append(StringUtils.isNotEmpty(accessToken) ? (accessToken.substring(0, 8) + "...") : "(unset)")
      .append('\'');
    sb.append(", expiryTime=").append(expiryTime);
    sb.append(", expiryDate=").append(
        new Date(TimeUnit.SECONDS.toMillis(expiryTime)));
    sb.append(", GCP Credentials{").append(marshalledCredentials);
    sb.append("}; ");
    sb.append('}');
    return sb.toString();
  }

}
