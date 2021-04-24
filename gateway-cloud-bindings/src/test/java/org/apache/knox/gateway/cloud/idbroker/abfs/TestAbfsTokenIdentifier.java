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

import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.roundTrip;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBIntegration.buildADTokenFromOAuth;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBIntegration.buildOAuthPayloadFromADToken;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Unit tests of the abfs identifiers.
 */
public class TestAbfsTokenIdentifier {

  private static final Logger LOG = LoggerFactory.getLogger(TestAbfsTokenIdentifier.class);

  private static final URI FS_URI;

  static {
    try {
      FS_URI = new URI("abfs://canonical.fs.name/");
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  private static final Text OWNER = new Text("owner");

  private static final Text RENEWER = new Text("RENEWER");

  private static final String ACCESS_TOKEN = "accessToken";

  private static final String ORIGIN = "origin";

  private static final long ACCESS_TIME = System.currentTimeMillis() + 60_000;

  private static final long EXPIRATION = ACCESS_TIME;

  private static final long ISSUE_TIME = System.currentTimeMillis();

  private static final String CORRELATION_ID = "correlationId";

  public static final String OAUTH = "oauth";

  public static final OAuthPayload EMPTY_OAUTH
      = new OAuthPayload();

  @Test
  public void testCreateToString() throws Throwable {
    AbfsIDBTokenIdentifier id
        = new AbfsIDBTokenIdentifier();
    String ts = id.toString();
    LOG.info("Simple string {}", ts);
    String tss = id.toStringStable();
    LOG.info("Stable string {}", tss);
  }

  @Test
  public void testMarshallingNoPayloadOrOauth() throws Throwable {
    AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(
        FS_URI,
        OWNER,
        RENEWER,
        ORIGIN,
        ACCESS_TOKEN,
        ACCESS_TIME,
        EMPTY_OAUTH,
        ISSUE_TIME,
        CORRELATION_ID, "", "");
    final String ids = id.toString();
    assertNotNull("payload in " + ids, id.getPayload());
    assertNotNull("credentials", id.getMarshalledCredentials());

    AbfsIDBTokenIdentifier id2 = roundTrip(
        id, new Configuration());
    final String ids2 = id.toString();

    assertEquals("in " + ids2, OWNER, id2.getOwner());
    assertEquals("in " + ids2, ORIGIN, id2.getOrigin());
    assertEquals("in " + ids2, id.getUuid(), id2.getUuid());
    assertEquals("identifiers", id, id2);
    assertEquals("in " + ids2, id.hashCode(), id2.hashCode());
    assertNotNull("payload in " + ids2, id2.getPayload());
    assertNotNull("credentials in " + ids2, id2.getMarshalledCredentials());
  }

  @Test
  public void testMarshallingFullPayload() throws Throwable {
    OAuthPayload auth = new OAuthPayload(OAUTH, EXPIRATION);
    AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(
        FS_URI,
        OWNER,
        RENEWER,
        ORIGIN,
        ACCESS_TOKEN,
        ACCESS_TIME,
        auth,
        ISSUE_TIME,
        CORRELATION_ID, "", "");

    AbfsIDBTokenIdentifier id2 = roundTrip(id, new Configuration());
    assertEquals(id, id2);
    assertEquals(id.getPayload(), id2.getPayload());
    assertEquals(id.getUuid(), id2.getUuid());
    assertEquals("Marshalled credentials in " + id2,
        id.getMarshalledCredentials(), id2.getMarshalledCredentials());
  }

  /**
   * Test in isolation of the conversion of an OAuth payload to the ADToken
   * type.
   */
  @Test
  public void testOauthToADTokenRoundTrip() throws Throwable {
    OAuthPayload payload = new OAuthPayload(OAUTH, EXPIRATION);
    AzureADToken adToken = buildADTokenFromOAuth(payload);
    OAuthPayload roundTrip = buildOAuthPayloadFromADToken(adToken);
    assertEquals("Round tripped payload", payload, roundTrip);
  }
}
