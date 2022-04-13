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
package org.apache.knox.gateway.services.security.token.impl;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.knox.gateway.services.security.token.JWTokenAttributesBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

public class JWTTokenTest {
  private static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MTY5MjkxMDksImp0aSI6ImFhN2Y4ZDBhOTVjIiwic2NvcGVzIjpbInJlcG8iLCJwdWJsaWNfcmVwbyJdfQ.XCEwpBGvOLma4TCoh36FU7XhUbcskygS81HE1uHLf0E";
  private static final String HEADER = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

  private static RSAPublicKey publicKey;
  private static RSAPrivateKey privateKey;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);

    KeyPair kp = kpg.genKeyPair();
    publicKey = (RSAPublicKey) kp.getPublic();
    privateKey = (RSAPrivateKey) kp.getPrivate();
  }

  @Test
  public void testTokenParsing() throws Exception {
    JWTToken token = JWTToken.parseToken(JWT_TOKEN);
    assertEquals(token.getHeader(), HEADER);
    assertEquals(token.getClaim("jti"), "aa7f8d0a95c");
  }

  @Test
  public void testTokenCreation() throws Exception {
    final String KID = "E0LDZulQ0XE_otJ5aoQtQu-RnXv8hU-M9U4dD7vDioA";
    final String JKU = "https://localhost:8443/gateway/token/knoxtoken/api/v1/jwks.json";
    final String ALGO = "RS256";
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(singletonList("https://login.example.com")).setKid(KID).setUserName("john.doe@example.com").setJku(JKU).setAlgorithm(ALGO).build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());

    assertTrue("Missing KID claim in JWT header", token.getHeader().contains(KID));
    assertTrue("Missing JKU claim in JWT header", token.getHeader().contains("jwks.json"));
    assertTrue("Missing ALG claim in JWT header", token.getHeader().contains(ALGO));
  }

  @Test
  public void testPrivateUUIDClaim() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(singletonList("https://login.example.com")).setUserName("john.doe@example.com").setAlgorithm("RS256").build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());

    String uuidString = token.getClaim(JWTToken.KNOX_ID_CLAIM);
    assertNotNull(uuidString);
    UUID uuid = UUID.fromString(uuidString);
    assertNotNull(uuid);
  }

  @Test
  public void testTokenCreationWithAudienceListSingle() throws Exception {
    List<String> audiences = new ArrayList<>();
    audiences.add("https://login.example.com");

    JWT token = new JWTToken(new JWTokenAttributesBuilder().setUserName("john.doe@example.com").setAudiences(audiences).setAlgorithm("RS256").setManaged(false).build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());
    assertEquals(1, token.getAudienceClaims().length);
  }

  @Test
  public void testTokenCreationWithAudienceListMultiple() throws Exception {
    List<String> audiences = new ArrayList<>();
    audiences.add("https://login.example.com");
    audiences.add("KNOXSSO");

    JWT token = new JWTToken(new JWTokenAttributesBuilder().setUserName("john.doe@example.com").setAudiences(audiences).setManaged(false).setAlgorithm("RS256").build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());
    assertEquals(2, token.getAudienceClaims().length);
  }

  @Test
  public void testTokenCreationWithAudienceListCombined() throws Exception {
    JWTToken token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(asList("https://login.example.com", "KNOXSSO", "LJM")).setUserName("john.doe@example.com").setManaged(false).setAlgorithm("RS256").build());
    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());
    assertEquals(3, token.getAudienceClaims().length);
  }

  @Test
  public void testTokenCreationWithNullAudienceList() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setUserName("john.doe@example.com").setAudiences((List<String>)null).setAlgorithm("RS256").setManaged(false).build());
    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertNull(token.getAudience());
    assertArrayEquals(null, token.getAudienceClaims());
  }

  @Test
  public void testTokenCreationRS512() throws Exception {
    JWTToken token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(singletonList("https://login.example.com")).setUserName("john.doe@example.com").setAlgorithm(JWSAlgorithm.RS512.getName()).build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());
    assertTrue(token.getHeader().contains(JWSAlgorithm.RS512.getName()));
  }

  @Test
  public void testTokenSignature() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(singletonList("https://login.example.com")).setUserName("john.doe@example.com").setAlgorithm("RS256").build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());

    // Sign the token
    JWSSigner signer = new RSASSASigner(privateKey);
    token.sign(signer);
    assertTrue(token.getSignaturePayload().length > 0);

    // Verify the signature
    JWSVerifier verifier = new RSASSAVerifier(publicKey);
    assertTrue(token.verify(verifier));
  }

  @Test
  public void testTokenSignatureRS512() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAudiences(singletonList("https://login.example.com")).setUserName("john.doe@example.com").setAlgorithm(JWSAlgorithm.RS512.getName()).build());

    assertEquals("KNOXSSO", token.getIssuer());
    assertEquals("john.doe@example.com", token.getSubject());
    assertEquals("https://login.example.com", token.getAudience());
    assertTrue(token.getHeader().contains(JWSAlgorithm.RS512.getName()));

    // Sign the token
    JWSSigner signer = new RSASSASigner(privateKey);
    token.sign(signer);
    assertTrue(token.getSignaturePayload().length > 0);

    // Verify the signature
    JWSVerifier verifier = new RSASSAVerifier(publicKey);
    assertTrue(token.verify(verifier));
  }

  @Test
  public void testTokenExpiry() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAlgorithm("RS256").build());

    assertNotNull(token.getExpires());
    assertNotNull(token.getExpiresDate());
    assertEquals(token.getExpiresDate(), new Date(Long.valueOf(token.getExpires())));
  }

  @Test
  public void testUnsignedToken() throws Exception {
    String unsignedToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImp0aSI6ImY2YmNj"
                               + "MDVjLWI4MTktNGM0Mi1iMGMyLWJlYmY1MDE4YWFiZiJ9.";

    try {
      new JWTToken(unsignedToken);
      fail("Failure expected on an unsigned token");
    } catch (ParseException ex) {
      // expected
      assertEquals("Invalid JWS header: The algorithm \"alg\" header parameter must be for signatures",
          ex.getMessage());
    }
  }

  @Test
  public void testTokenType() throws Exception {
    JWT token = new JWTToken(new JWTokenAttributesBuilder().setAlgorithm("RS256").build());
    assertNull(token.getType());

    final String tokenType = "at+jwt";
    token = new JWTToken(new JWTokenAttributesBuilder().setAlgorithm("RS256").setType(tokenType).build());
    assertEquals(token.getType(), new JOSEObjectType(tokenType));
  }
}
