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

package org.apache.knox.gateway.cloud.idbroker.messages;


import java.math.BigInteger;
import java.nio.charset.Charset;

import com.amazonaws.auth.BasicSessionCredentials;
import org.junit.Assert;
import org.junit.Test;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient;

import static org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage.BEARER_TOKEN;

/**
 * Test Parsing of IDB responses.
 */
public class TestResponseParsing extends Assert {


  public static final String EXPIRES_STR = "1540356764602";

  public static final String ACCESS_KEY = "ABCDEFGHIJKL";

  public static final String SECRET_ACCESS_KEY
      = "2vzXdfOba+AbCd+abcd134ABCDO/acd";

  public static final String SESSION_TOKEN
      = "FQoGZXIvYXdzANL//////////wABCDEFGHIJKL/ABCDEFGHIJKL/ABCDEFGHIJKL";

  /** End of record. */
  public static final String EOR = "\",";

  public static final String Q = "\"";

  /**
   * A valid response.
   * All strings have been edited other than the expiration date; the session
   * token is much shorter than in the original response.
   */
  public static final String VALID_AWS_RESPONSE
      = "{ \"AssumedRoleUser\":"
      + " { \"AssumedRole\": \"ABCDEFGHIJKLABCDEFGHIJKL:ABC-DEFGH-15000000011\","
      + "   \"Arn\":"
      + " \"arn:aws:sts::000000000000:assumed-role/stevel-s3guard/ABC-DEFGH-15000000011\" },"
      + "   \"Credentials\":"
      + "   { \"SessionToken\":" + Q + SESSION_TOKEN + EOR
      + " \"AccessKeyId\":" + Q + ACCESS_KEY + EOR
      + " \"SecretAccessKey\": "
      + Q + SECRET_ACCESS_KEY + EOR
      + " \"Expiration\": 1540228070000"
      + " }"
      + " }";

  public static final Charset UTF = Charset.forName("UTF-8");

  private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1Ni";

  public static final String VALID_DT_RESPONSE = " {"
      + "\"access_token\":\"" + ACCESS_TOKEN + EOR
      + "\"token_type\":\"Bearer\","
      + "\"expires_in\":" + EXPIRES_STR
      + "}\n";

  private static final BigInteger EXPIRES = new BigInteger(EXPIRES_STR);

  @Test
  public void testParseAWSResponse() throws Throwable {
    JsonSerialization<AuthResponseAWSMessage> authDeser
        = AuthResponseAWSMessage.serializer();
    AuthResponseAWSMessage responseAWSStruct = authDeser.fromBytes(
        VALID_AWS_RESPONSE.getBytes(UTF));

    IdentityBrokerClient idbClient = new IDBClient(new Configuration());
    MarshalledCredentials marshalled = idbClient.fromResponse(
        responseAWSStruct);
    String marshalledStr = marshalled.toString();
    assertEquals("access key in " + marshalledStr,
        ACCESS_KEY, marshalled.getAccessKey());
    assertEquals("secret key in " + marshalledStr,
        SECRET_ACCESS_KEY, marshalled.getSecretKey());
    assertEquals("session token in " + marshalledStr,
        SESSION_TOKEN, marshalled.getSessionToken());
    BasicSessionCredentials awsCreds = (BasicSessionCredentials)
        marshalled.getCredentials();
    assertEquals("access key in " + marshalledStr,
        ACCESS_KEY, awsCreds.getAWSAccessKeyId());
    assertEquals("secret key in " + marshalledStr,
        SECRET_ACCESS_KEY, awsCreds.getAWSSecretKey());
    assertEquals("session token in " + marshalledStr,
        SESSION_TOKEN, awsCreds.getSessionToken());
  }


  @Test
  public void testParseDTResponse() throws Throwable {
    JsonSerialization<RequestDTResponseMessage>
        serDeser = new JsonSerialization<>(
        RequestDTResponseMessage.class, false, true);
    RequestDTResponseMessage struct = serDeser.fromBytes(
        VALID_DT_RESPONSE.getBytes(UTF));
    struct.validate();
    assertEquals("access token",
        ACCESS_TOKEN, struct.access_token);
    assertEquals("token type",
        BEARER_TOKEN, struct.token_type);
    assertEquals("expires",
        EXPIRES, struct.expires_in);

  }
}
