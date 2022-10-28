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
package org.apache.knox.gateway.services.token.impl;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.AbstractAliasService;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.TokenStateService;
import org.apache.knox.gateway.services.security.token.impl.JWTToken;
import org.apache.knox.gateway.services.token.state.JournalEntry;
import org.apache.knox.gateway.services.token.state.TokenStateJournal;
import org.apache.knox.gateway.services.token.impl.state.TokenStateJournalFactory;
import org.easymock.EasyMock;
import org.junit.Ignore;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AliasBasedTokenStateServiceTest extends DefaultTokenStateServiceTest {

  private Long tokenStatePersistenceInterval = TimeUnit.SECONDS.toMillis(15);

  @Override
  protected long getTokenStatePersistenceInterval() {
    return (tokenStatePersistenceInterval != null) ? tokenStatePersistenceInterval : super.getTokenStatePersistenceInterval();
  }

  /**
   * KNOX-2375
   */
  @Test
  public void testBulkTokenStateEviction() throws Exception {
    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < 10 ; i++) {
      testTokens.add(createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60)));
    }

    List<String> testTokenStateAliases = new ArrayList<>();
    for (JWTToken token : testTokens) {
      String tokenId = token.getClaim(JWTToken.KNOX_ID_CLAIM);
      testTokenStateAliases.add(tokenId);
      testTokenStateAliases.add(tokenId + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX);
    }

    // Create a mock AliasService so we can verify that the expected bulk removal method is invoked when the token state
    // reaper runs.
    AliasService aliasService = EasyMock.createNiceMock(AliasService.class);
    EasyMock.expect(aliasService.getPasswordFromAliasForCluster(anyString(), anyString()))
            .andReturn(String.valueOf(System.currentTimeMillis()).toCharArray())
            .anyTimes();
    EasyMock.expect(aliasService.getAliasesForCluster(AliasService.NO_CLUSTER_NAME)).andReturn(testTokenStateAliases).anyTimes();
    // Expecting the bulk alias removal method to be invoked only once, rather than the individual alias removal method
    // invoked twice for every expired token.
    aliasService.removeAliasesForCluster(anyString(), anyObject());
    EasyMock.expectLastCall().andVoid().once();

    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();

    EasyMock.replay(aliasService);

    AliasBasedTokenStateService tss = new AliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                     System.currentTimeMillis(),
                     token.getExpiresDate().getTime(),
                     maxTokenLifetime);
        assertTrue("Expected the token to have expired.", tss.isExpired(token));
      }

      // Sleep to allow the eviction evaluation to be performed
      Thread.sleep(evictionInterval + (evictionInterval / 2));
    } finally {
      tss.stop();
    }

    // Verify that the expected method was invoked
    EasyMock.verify(aliasService);
  }

  @Ignore("This is a flaky test: while it runs perfectly for me in my local ENV, it fails a lot in Gerrit. Ignoring until it's fixed; see CDPD-46152")
  @Test
  public void testAddAndRemoveTokenIncludesCache() throws Exception {
    final int TOKEN_COUNT = 10;
    tokenStatePersistenceInterval = 3L;

    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < TOKEN_COUNT ; i++) {
      testTokens.add(createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60)));
    }

    Set<String> testTokenStateAliases = new HashSet<>();
    for (JWTToken token : testTokens) {
      String tokenId = token.getClaim(JWTToken.KNOX_ID_CLAIM);
      testTokenStateAliases.add(tokenId);
      testTokenStateAliases.add(tokenId + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX);
      testTokenStateAliases.add(tokenId + AliasBasedTokenStateService.TOKEN_META_POSTFIX);
      testTokenStateAliases.add(tokenId + AliasBasedTokenStateService.TOKEN_ISSUE_TIME_POSTFIX);
    }

    // Create a mock AliasService so we can verify that the expected bulk removal method is invoked (and that the
    // individual removal method is NOT invoked) when the token state reaper runs.
    AliasService aliasService = EasyMock.createMock(AliasService.class);
    EasyMock.expect(aliasService.getAliasesForCluster(AliasService.NO_CLUSTER_NAME)).andReturn(new ArrayList<>(testTokenStateAliases)).anyTimes();
    // Expecting the bulk alias removal method to be invoked only once, rather than the individual alias removal method
    // invoked twice for every expired token.
    aliasService.removeAliasesForCluster((EasyMock.eq(AliasService.NO_CLUSTER_NAME)), EasyMock.eq(testTokenStateAliases));
    EasyMock.expectLastCall().andVoid().once();

    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();

    EasyMock.replay(aliasService);

    AliasBasedTokenStateService tss = new AliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    Map<String, Long> tokenExpirations = getTokenExpirationsField(tss, 2);
    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss, 2);
    Map<String, Map<String, TokenMetadata>> metadata = getMetadataMapField(tss, 2);
    Map<String, Long> tokenIssueTimes = getTokenIssueTimesField(tss, 2);

    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                     System.currentTimeMillis(),
                     token.getExpiresDate().getTime(),
                     maxTokenLifetime);
        tss.addMetadata(token.getClaim(JWTToken.KNOX_ID_CLAIM), new TokenMetadata("alice"));
      }

      assertEquals("Expected the tokens to have been added in the base class cache.", TOKEN_COUNT, tokenExpirations.size());
      assertEquals("Expected the tokens lifetimes to have been added in the base class cache.", TOKEN_COUNT, maxTokenLifetimes.size());
      assertEquals("Expected the token metadata to have been added in the base class cache.", TOKEN_COUNT, metadata.size());
      assertEquals("Expected the token issue times to have been added in the base class cache.", TOKEN_COUNT, tokenIssueTimes.size());

      // Sleep to allow the eviction evaluation to be performed
      Thread.sleep(evictionInterval + (evictionInterval / 4));

    } finally {
      tokenStatePersistenceInterval = null;
      tss.stop();
    }

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);

    assertEquals("Expected the tokens to have been removed from the base class cache as a result of eviction.",
                 0,
                 tokenExpirations.size());
    assertEquals("Expected the tokens lifetimes to have been removed from the base class cache as a result of eviction.",
                 0,
                 maxTokenLifetimes.size());
    assertEquals("Expected the token metadata to have been removed from the base class cache as a result of eviction.",
                 0,
                 metadata.size());
    assertEquals("Expected the token issue times to have been removed from the base class cache as a result of eviction.",
                 0,
                 tokenIssueTimes.size());
  }

  /**
   * Verify that the token state reaper includes token state which has not been cached, so it's not left in the keystore
   * forever.
   */
  @Ignore("I'm not sure if this is a valid use case since we have everything in the cache when eviction takes place")
  @Test()
  public void testTokenEvictionIncludesUncachedAliases() throws Exception {
    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < 10 ; i++) {
      testTokens.add(createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60)));
    }

    List<String> testTokenStateAliases = new ArrayList<>();
    for (JWTToken token : testTokens) {
      testTokenStateAliases.add(token.getClaim(JWTToken.KNOX_ID_CLAIM));
      testTokenStateAliases.add(token.getClaim(JWTToken.KNOX_ID_CLAIM) + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX);
    }

    // Add aliases for an uncached test token
    final JWTToken uncachedToken = createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60));
    final String uncachedTokenId = uncachedToken.getClaim(JWTToken.KNOX_ID_CLAIM);
    testTokenStateAliases.add(uncachedTokenId);
    testTokenStateAliases.add(uncachedTokenId + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX);
    final long uncachedTokenExpiration = System.currentTimeMillis();
    System.out.println("Uncached token ID: " + uncachedTokenId);

    final Set<String> expectedTokensToEvict = new HashSet<>();
    expectedTokensToEvict.addAll(testTokenStateAliases);
    expectedTokensToEvict.add(uncachedTokenId);
    expectedTokensToEvict.add(uncachedTokenId + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX);

    // Create a mock AliasService so we can verify that the expected bulk removal method is invoked (and that the
    // individual removal method is NOT invoked) when the token state reaper runs.
    AliasService aliasService = EasyMock.createMock(AliasService.class);
    EasyMock.expect(aliasService.getAliasesForCluster(AliasService.NO_CLUSTER_NAME)).andReturn(testTokenStateAliases).anyTimes();
    // Expecting the bulk alias removal method to be invoked only once, rather than the individual alias removal method
    // invoked twice for every expired token.
    aliasService.removeAliasesForCluster(anyString(), EasyMock.eq(expectedTokensToEvict));
    EasyMock.expectLastCall().andVoid().once();
    aliasService.getPasswordFromAliasForCluster(AliasService.NO_CLUSTER_NAME, uncachedTokenId);
    EasyMock.expectLastCall().andReturn(String.valueOf(uncachedTokenExpiration).toCharArray()).once();
    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();

    EasyMock.replay(aliasService);

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    Map<String, Long> tokenExpirations = getTokenExpirationsField(tss);
    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss);

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                     System.currentTimeMillis(),
                     token.getExpiresDate().getTime(),
                     maxTokenLifetime);
      }

      assertEquals("Expected the tokens to have been added in the base class cache.", 10, tokenExpirations.size());
      assertEquals("Expected the tokens lifetimes to have been added in the base class cache.", 10, maxTokenLifetimes.size());

      // Sleep to allow the eviction evaluation to be performed, but only one iteration
      Thread.sleep(evictionInterval + (evictionInterval / 4));
    } finally {
      tss.stop();
    }

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);

    assertEquals("Expected the tokens to have been removed from the base class cache as a result of eviction.", 0, tokenExpirations.size());
    assertEquals("Expected the tokens lifetimes to have been removed from the base class cache as a result of eviction.", 0, maxTokenLifetimes.size());
  }

  @Test
  public void testGetMaxLifetimeUsesCache() throws Exception {
    tokenStatePersistenceInterval = 3L;
    AliasService aliasService = EasyMock.createMock(AliasService.class);
    aliasService.addAliasesForCluster(anyString(), anyObject());
    EasyMock.expectLastCall().once(); // Expecting this during shutdown

    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();

    EasyMock.replay(aliasService);

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss);

    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < 10 ; i++) {
      testTokens.add(createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60)));
    }

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                System.currentTimeMillis(),
                token.getExpiresDate().getTime(),
                maxTokenLifetime);

      }

      assertEquals("Expected the tokens lifetimes to have been added in the base class cache.",
                   10,
                   maxTokenLifetimes.size());

      // Set the cache values to be different from the underlying alias value
      final long updatedMaxLifetime = evictionInterval * 5;
      for (Map.Entry<String, Long> entry : maxTokenLifetimes.entrySet()) {
        entry.setValue(updatedMaxLifetime);
      }

      // Verify that we get the cache value back
      for (String tokenId : maxTokenLifetimes.keySet()) {
        assertEquals("Expected the cached max lifetime, rather than the alias value",
                     updatedMaxLifetime,
                     tss.getMaxLifetime(tokenId));
      }

      Thread.sleep(evictionInterval + (evictionInterval / 4));
    } finally {
      tss.stop();
      tokenStatePersistenceInterval = null;
    }

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);
  }

  @Test
  public void testUpdateExpirationUsesCache() throws Exception {
    final AliasService aliasService = EasyMock.createMock(AliasService.class);
    // Neither addAliasForCluster nor removeAliasForCluster should be called because updating expiration should happen in memory and let the
    // background persistence job done its job
    aliasService.addAliasesForCluster(anyString(), anyObject());
    EasyMock.expectLastCall().andVoid().atLeastOnce(); // Expecting this during shutdown

    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();
    EasyMock.replay(aliasService);

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    Map<String, Long> tokenExpirations = getTokenExpirationsField(tss);

    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < 10 ; i++) {
      testTokens.add(createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60)));
    }

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                     System.currentTimeMillis(),
                     token.getExpiresDate().getTime(),
                     maxTokenLifetime);
      }

      assertEquals("Expected the tokens expirations to have been added in the base class cache.",
                   10,
                   tokenExpirations.size());

      // Set the cache values to be different from the underlying alias value
      final long updatedExpiration = System.currentTimeMillis();
      for (String tokenId : tokenExpirations.keySet()) {
        tss.updateExpiration(tokenId, updatedExpiration);
      }

      // Invoking with true/false validation flags as it should not affect if values are coming from the cache
      int count = 0;
      for (String tokenId : tokenExpirations.keySet()) {
        assertEquals("Expected the cached expiration to have been updated.", updatedExpiration, tss.getTokenExpiration(tokenId, count++ % 2 == 0));
      }

    } finally {
      tss.stop();
    }

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);
  }

  @Test
  public void testTokenStateJournaling() throws Exception {
    AliasService aliasService = EasyMock.createMock(AliasService.class);
    aliasService.getAliasesForCluster(anyString());
    EasyMock.expectLastCall().andReturn(Collections.emptyList()).anyTimes();
    aliasService.addAliasesForCluster(anyString(), anyObject());
    EasyMock.expectLastCall().once();

    //expecting this call when loading credentials from the keystore on startup
    EasyMock.expect(aliasService.getPasswordsForGateway()).andReturn(Collections.emptyMap()).anyTimes();

    EasyMock.replay(aliasService);

    tokenStatePersistenceInterval = 1L; // Override the persistence interval for this test

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);
    initTokenStateService(tss);

    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss);

    Path journalDir = Paths.get(getGatewaySecurityDir(), "token-state");

    final long evictionInterval = TimeUnit.SECONDS.toMillis(3);
    final long maxTokenLifetime = evictionInterval * 3;

    final List<String> tokenIds = new ArrayList<>();
    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < 10 ; i++) {
      JWTToken token = createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60));
      testTokens.add(token);
      tokenIds.add(token.getClaim(JWTToken.KNOX_ID_CLAIM));
    }

    try {
      tss.start();

      // Add the expired tokens
      for (JWTToken token : testTokens) {
        tss.addToken(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                     System.currentTimeMillis(),
                     token.getExpiresDate().getTime(),
                     maxTokenLifetime);
      }

      assertEquals("Expected the tokens lifetimes to have been added in the base class cache.",
                   10,
                   maxTokenLifetimes.size());

      // Check for the expected number of files corresponding to journal entries
      List<Path> listing = Files.list(journalDir).collect(Collectors.toList());
      assertFalse(listing.isEmpty());
      assertEquals(10, listing.size());

      // Validate the journal entry file names
      for (Path p : listing) {
        Path filename = p.getFileName();
        String filenameString = filename.toString();
        assertTrue(filenameString.endsWith(".ts"));
        String tokenId = filenameString.substring(0, filenameString.length() - 3);
        assertTrue(tokenIds.contains(tokenId));
      }

      // Sleep to allow the persistence to be performed
      Thread.sleep(TimeUnit.SECONDS.toMillis(tokenStatePersistenceInterval) * 2);

    } finally {
      tss.stop();
      tokenStatePersistenceInterval = null;
    }

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);

    // Verify that the journal entries were removed when the aliases were created
    List<Path> listing = Files.list(journalDir).collect(Collectors.toList());
    assertTrue(listing.isEmpty());
  }

  @Test
  public void testLoadTokenStateJournalDuringInit() throws Exception {
    final int TOKEN_COUNT = 10;

    AliasService aliasService = EasyMock.createMock(AliasService.class);
    aliasService.getAliasesForCluster(anyString());
    EasyMock.expectLastCall().andReturn(Collections.emptyList()).anyTimes();
    EasyMock.replay(aliasService);

    // Create some test tokens
    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < TOKEN_COUNT ; i++) {
      JWTToken token = createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60));
      testTokens.add(token);
    }

    // Persist the token state journal entries before initializing the TokenStateService
    TokenStateJournal journal = TokenStateJournalFactory.create(createMockGatewayConfig(false));
    for (JWTToken token : testTokens) {
      journal.add(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                  System.currentTimeMillis(),
                  token.getExpiresDate().getTime(),
                  System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24),
                  null);
    }

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);

    // Initialize the service, and presumably load the previously-persisted journal entries
    initTokenStateService(tss);

    Map<String, Long> tokenExpirations = getTokenExpirationsField(tss);
    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss);
    Map<String, Long> tokenIssueTimes = getTokenIssueTimesField(tss, 3);

    Set<AliasBasedTokenStateService.TokenState> unpersistedState = getUnpersistedStateField(tss);

    assertEquals("Expected the tokens expirations to have been added in the base class cache.",
                 TOKEN_COUNT,
                 tokenExpirations.size());

    assertEquals("Expected the tokens lifetimes to have been added in the base class cache.",
                 TOKEN_COUNT,
                 maxTokenLifetimes.size());

    assertEquals("Expected the tokens issue times to have been added in the base class cache.",
                 TOKEN_COUNT,
                 tokenIssueTimes.size());

    assertEquals("Expected the unpersisted state to have been added.",
                 (TOKEN_COUNT * 3), // Two TokenState entries per token (expiration, max lifetime, issue time)
                 unpersistedState.size());

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);
  }

  @Test
  public void testLoadTokenStateJournalDuringInitWithInvalidEntries() throws Exception {
    final int TOKEN_COUNT = 5;

    AliasService aliasService = EasyMock.createMock(AliasService.class);
    aliasService.getAliasesForCluster(anyString());
    EasyMock.expectLastCall().andReturn(Collections.emptyList()).anyTimes();
    EasyMock.replay(aliasService);

    // Create some test tokens
    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < TOKEN_COUNT ; i++) {
      JWTToken token = createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60));
      testTokens.add(token);
    }

    // Persist the token state journal entries before initializing the TokenStateService
    TokenStateJournal journal = TokenStateJournalFactory.create(createMockGatewayConfig(false));
    for (JWTToken token : testTokens) {
      journal.add(token.getClaim(JWTToken.KNOX_ID_CLAIM),
                  System.currentTimeMillis(),
                  token.getExpiresDate().getTime(),
                  System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24),
                  null);
    }

    // Add an entry with an invalid token identifier
    journal.add("   ",
                System.currentTimeMillis(),
                System.currentTimeMillis(),
                System.currentTimeMillis(),
                null);

    // Add an entry with an invalid issue time
    journal.add(new TestJournalEntry(UUID.randomUUID().toString(),
                "invalidLongValue",
                String.valueOf(System.currentTimeMillis()),
                String.valueOf(System.currentTimeMillis()),
                new TokenMetadata("testUser")));

    // Add an entry with an invalid expiration time
    journal.add(new TestJournalEntry(UUID.randomUUID().toString(),
                String.valueOf(System.currentTimeMillis()),
                "invalidLongValue",
                String.valueOf(System.currentTimeMillis()),
                new TokenMetadata("testUser")));

    // Add an entry with an invalid max lifetime
    journal.add(new TestJournalEntry(UUID.randomUUID().toString(),
                                     String.valueOf(System.currentTimeMillis()),
                                     String.valueOf(System.currentTimeMillis()),
                                     "invalidLongValue",
                                     new TokenMetadata("testUser")));

    AliasBasedTokenStateService tss = new NoEvictionAliasBasedTokenStateService();
    tss.setAliasService(aliasService);

    // Initialize the service, and presumably load the previously-persisted journal entries
    initTokenStateService(tss);

    Map<String, Long> tokenExpirations = getTokenExpirationsField(tss);
    Map<String, Long> maxTokenLifetimes = getMaxTokenLifetimesField(tss);
    Map<String, Long> tokenIssueTimes = getTokenIssueTimesField(tss, 3);

    Set<AliasBasedTokenStateService.TokenState> unpersistedState = getUnpersistedStateField(tss);

    assertEquals("Expected the tokens expirations to have been added in the base class cache.",
                 TOKEN_COUNT,
                 tokenExpirations.size());

    assertEquals("Expected the tokens lifetimes to have been added in the base class cache.",
                 TOKEN_COUNT,
                 maxTokenLifetimes.size());

    assertEquals("Expected the tokens issue times to have been added in the base class cache.",
                 TOKEN_COUNT,
                 tokenIssueTimes.size());

    assertEquals("Expected the unpersisted state to have been added.",
                 (TOKEN_COUNT * 3), // Two TokenState entries per token (expiration, max lifetime, issue time)
                 unpersistedState.size());

    // Verify that the expected methods were invoked
    EasyMock.verify(aliasService);
  }

  @Test
  public void ensureAliases() throws Exception {
    final int tokenCount = 1000;
    final Set<JWTToken> testTokens = new HashSet<>();
    for (int i = 0; i < tokenCount ; i++) {
      JWTToken token = createMockToken(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(60));
      testTokens.add(token);
    }

    final AliasBasedTokenStateService tss = (AliasBasedTokenStateService) createTokenStateService();
    final long issueTime = System.currentTimeMillis();
    for (JWTToken token : testTokens) {
      tss.addToken(token, issueTime);
      tss.renewToken(token);
    }

    final List<AliasBasedTokenStateService.TokenState> unpersistedTokenStates = new ArrayList<>(getUnpersistedStateField(tss, 0));
    final int expectedAliasCount = 3 * tokenCount; //expiration + max + issue time for each token
    assertEquals(expectedAliasCount, unpersistedTokenStates.size());
    for (JWTToken token : testTokens) {
      String tokenId = token.getClaim(JWTToken.KNOX_ID_CLAIM);
      assertTrue(containsAlias(unpersistedTokenStates, tokenId));
      assertTrue(containsAlias(unpersistedTokenStates, tokenId + AliasBasedTokenStateService.TOKEN_MAX_LIFETIME_POSTFIX));
    }
  }

  private boolean containsAlias(List<AliasBasedTokenStateService.TokenState> unpersistedTokenStates, String expectedAlias) {
    for(AliasBasedTokenStateService.TokenState tokenState : unpersistedTokenStates) {
      if (tokenState.getAlias().equals(expectedAlias)) {
        return true;
      }
    }
    return false;
  }

  @Override
  protected TokenStateService createTokenStateService() throws Exception {
    AliasBasedTokenStateService tss = new AliasBasedTokenStateService();
    tss.setAliasService(new TestAliasService());
    initTokenStateService(tss);
    return tss;
  }

  /**
   * A dumbed-down AliasService implementation for testing purposes only.
   */
  private static final class TestAliasService extends AbstractAliasService {

    private final Map<String, Map<String, String>> clusterAliases= new HashMap<>();


    @Override
    public List<String> getAliasesForCluster(String clusterName) throws AliasServiceException {
      List<String> aliases = new ArrayList<>();

      if (clusterAliases.containsKey(clusterName)) {
          aliases.addAll(clusterAliases.get(clusterName).keySet());
      }
      return aliases;
    }

    @Override
    public void addAliasForCluster(String clusterName, String alias, String value) throws AliasServiceException {
      Map<String, String> aliases = null;
      if (clusterAliases.containsKey(clusterName)) {
        aliases = clusterAliases.get(clusterName);
      } else {
        aliases = new HashMap<>();
        clusterAliases.put(clusterName, aliases);
      }
      aliases.put(alias, value);
    }

    @Override
    public void addAliasesForCluster(String clusterName, Map<String, String> credentials) throws AliasServiceException {
      for (Map.Entry<String, String> credential : credentials.entrySet()) {
        addAliasForCluster(clusterName, credential.getKey(), credential.getValue());
      }
    }

    @Override
    public void removeAliasForCluster(String clusterName, String alias) throws AliasServiceException {
      if (clusterAliases.containsKey(clusterName)) {
        clusterAliases.get(clusterName).remove(alias);
      }
    }

    @Override
    public void removeAliasesForCluster(String clusterName, Set<String> aliases) throws AliasServiceException {
      for (String alias : aliases) {
        removeAliasForCluster(clusterName, alias);
      }
    }

    @Override
    public char[] getPasswordFromAliasForCluster(String clusterName, String alias) throws AliasServiceException {
      char[] value = null;
      if (clusterAliases.containsKey(clusterName)) {
        String valString = clusterAliases.get(clusterName).get(alias);
        if (valString != null) {
          value = valString.toCharArray();
        }
      }
      return value;
    }

    @Override
    public char[] getPasswordFromAliasForCluster(String clusterName, String alias, boolean generate) throws AliasServiceException {
      return new char[0];
    }

    @Override
    public void generateAliasForCluster(String clusterName, String alias) throws AliasServiceException {
    }

    @Override
    public char[] getPasswordFromAliasForGateway(String alias) throws AliasServiceException {
      return getPasswordFromAliasForCluster(AliasService.NO_CLUSTER_NAME, alias);
    }

    @Override
    public char[] getGatewayIdentityPassphrase() throws AliasServiceException {
      return new char[0];
    }

    @Override
    public char[] getGatewayIdentityKeystorePassword() throws AliasServiceException {
      return new char[0];
    }

    @Override
    public char[] getSigningKeyPassphrase() throws AliasServiceException {
      return new char[0];
    }

    @Override
    public char[] getSigningKeystorePassword() throws AliasServiceException {
      return new char[0];
    }

    @Override
    public void generateAliasForGateway(String alias) throws AliasServiceException {
    }

    @Override
    public Certificate getCertificateForGateway(String alias) throws AliasServiceException {
      return null;
    }

    @Override
    public void init(GatewayConfig config, Map<String, String> options) throws ServiceLifecycleException {
    }

    @Override
    public void start() throws ServiceLifecycleException {
    }

    @Override
    public void stop() throws ServiceLifecycleException {
    }
  }

  @Override
  protected void addToken(TokenStateService tss, String tokenId, long issueTime, long expiration, long maxLifetime) {
    super.addToken(tss, tokenId, issueTime, expiration, maxLifetime);

    // Persist any unpersisted token state aliases
    triggerAliasPersistence(tss);
  }

  @Override
  protected void addToken(TokenStateService tss, JWTToken token, long issueTime) {
    super.addToken(tss, token, issueTime);

    // Persist any unpersisted token state aliases
    triggerAliasPersistence(tss);
  }

  private void triggerAliasPersistence(TokenStateService tss) {
    if (tss instanceof AliasBasedTokenStateService) {
      try {
        Method m = tss.getClass().getDeclaredMethod("persistTokenState");
        m.setAccessible(true);
        m.invoke(tss);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  private static Map<String, Long> getTokenExpirationsField(TokenStateService tss) throws Exception {
    return getTokenExpirationsField(tss, 3);
  }

  private static Map<String, Long> getTokenExpirationsField(TokenStateService tss, int level) throws Exception {
    return (Map<String, Long>) getField(tss, level, "tokenExpirations");
  }

  private static Object getField(TokenStateService tss, int level, String fieldName) throws Exception {
    final Field field = getParentClass(tss, level).getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(tss);
  }

  private static Class<TokenStateService> getParentClass(TokenStateService tss, int level) {
    Class<TokenStateService> clazz = (Class<TokenStateService>) tss.getClass();
    for (int i = 1; i <= level; i++) {
      clazz = (Class<TokenStateService>) clazz.getSuperclass();
    }
    return clazz;
  }

  private static Map<String, Long> getMaxTokenLifetimesField(TokenStateService tss) throws Exception {
    return getMaxTokenLifetimesField(tss, 3);
  }

  private static Map<String, Long> getMaxTokenLifetimesField(TokenStateService tss, int level) throws Exception {
    return (Map<String, Long>) getField(tss, level, "maxTokenLifetimes");
  }

  private static Map<String, Long> getTokenIssueTimesField(TokenStateService tss, int level) throws Exception {
    return (Map<String, Long>) getField(tss, level, "tokenIssueTimes");
  }

  private static Map<String, Map<String, TokenMetadata>> getMetadataMapField(TokenStateService tss, int level) throws Exception {
    return (Map<String, Map<String, TokenMetadata>>) getField(tss, level, "metadataMap");
  }

  private static Set<AliasBasedTokenStateService.TokenState> getUnpersistedStateField(TokenStateService tss) throws Exception {
    return getUnpersistedStateField(tss, 1);
  }

  private static Set<AliasBasedTokenStateService.TokenState> getUnpersistedStateField(TokenStateService tss, int level) throws Exception {
    return (Set<AliasBasedTokenStateService.TokenState>) getField(tss, level, "unpersistedState");
  }

  private static class TestJournalEntry implements JournalEntry {

    private String tokenId;
    private String issueTime;
    private String expiration;
    private String maxLifetime;
    private TokenMetadata tokenMetadata;

    TestJournalEntry(String tokenId, String issueTime, String expiration, String maxLifetime, TokenMetadata tokenMetadata) {
      this.tokenId     = tokenId;
      this.issueTime   = issueTime;
      this.expiration  = expiration;
      this.maxLifetime = maxLifetime;
      this.tokenMetadata = tokenMetadata;
    }

    @Override
    public String getTokenId() {
      return tokenId;
    }

    @Override
    public String getIssueTime() {
      return issueTime;
    }

    @Override
    public String getExpiration() {
      return expiration;
    }

    @Override
    public String getMaxLifetime() {
      return maxLifetime;
    }

    @Override
    public TokenMetadata getTokenMetadata() {
      return tokenMetadata;
    }

    @Override
    public String toString() {
      return tokenId + "," + issueTime + "," + expiration + "," + maxLifetime;
    }
  }

  private static class NoEvictionAliasBasedTokenStateService extends AliasBasedTokenStateService {

    @Override
    protected boolean readyForEviction() {
      return false;
    }

  }

}
