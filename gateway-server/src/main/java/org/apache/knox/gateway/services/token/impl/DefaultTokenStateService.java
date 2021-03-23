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

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.management.InstanceAlreadyExistsException;
import javax.management.MBeanRegistrationException;
import javax.management.MalformedObjectNameException;
import javax.management.NotCompliantMBeanException;
import javax.management.ObjectName;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.TokenStateService;
import org.apache.knox.gateway.services.security.token.TokenUtils;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;
import org.apache.knox.gateway.services.security.token.impl.JWT;
import org.apache.knox.gateway.services.security.token.impl.JWTToken;
import org.apache.knox.gateway.services.token.TokenStateServiceStatistics;

/**
 * In-Memory authentication token state management implementation.
 */
public class DefaultTokenStateService implements TokenStateService {

  protected static final long DEFAULT_RENEWAL_INTERVAL = TimeUnit.HOURS.toMillis(24);

  protected static final int MAX_RENEWALS = 7;

  protected static final long DEFAULT_MAX_LIFETIME = MAX_RENEWALS * DEFAULT_RENEWAL_INTERVAL; // 7 days

  protected static final TokenStateServiceMessages log = MessagesFactory.get(TokenStateServiceMessages.class);

  private final Map<String, Long> tokenExpirations = new ConcurrentHashMap<>();

  private final Map<String, Long> maxTokenLifetimes = new ConcurrentHashMap<>();

  private final Set<String> unusedTokens = ConcurrentHashMap.newKeySet();

  private final Map<String, TokenMetadata> metadataMap = new ConcurrentHashMap<>();

  // Token eviction interval (in seconds)
  private long tokenEvictionInterval;

  // Grace period (in seconds) after which an expired token should be evicted
  private long tokenEvictionGracePeriod;

  // Knox token validation permissiveness
  protected boolean permissiveValidationEnabled;

  private final ScheduledExecutorService evictionScheduler = Executors.newScheduledThreadPool(1);

  //token state MBean to store statistics (only initialized and used if JMX reporting is enabled)
  protected TokenStateServiceStatistics tokenStateServiceStatistics;


  @Override
  public void init(final GatewayConfig config, final Map<String, String> options) throws ServiceLifecycleException {
    tokenEvictionInterval = config.getKnoxTokenEvictionInterval();
    tokenEvictionGracePeriod = config.getKnoxTokenEvictionGracePeriod();
    permissiveValidationEnabled = config.isKnoxTokenPermissiveValidationEnabled();
    if (config.isMetricsEnabled() && config.isJmxMetricsReportingEnabled()) {
      try {
        tokenStateServiceStatistics = new TokenStateServiceStatistics();
        final ObjectName objectName = ObjectName.getInstance("metrics:type=Statistics,name=TokenStateService");
        ManagementFactory.getPlatformMBeanServer().registerMBean(tokenStateServiceStatistics, objectName);
      } catch (MalformedObjectNameException | InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException e) {
        throw new ServiceLifecycleException("Could not register token state service MBean", e);
      }
    }
  }

  @Override
  public void start() throws ServiceLifecycleException {
    if (tokenEvictionInterval > 0) {
      // Run token eviction task at configured interval
      evictionScheduler.scheduleAtFixedRate(this::evictExpiredTokens, tokenEvictionInterval, tokenEvictionInterval, TimeUnit.SECONDS);
    }
  }

  @Override
  public void stop() throws ServiceLifecycleException {
    evictionScheduler.shutdown();
  }

  @Override
  public long getDefaultRenewInterval() {
    return DEFAULT_RENEWAL_INTERVAL;
  }

  @Override
  public long getDefaultMaxLifetimeDuration() {
    return DEFAULT_MAX_LIFETIME;
  }

  @Override
  public void addToken(final JWTToken token, long issueTime) {
    if (token == null) {
      throw new IllegalArgumentException("Token cannot be null.");
    }
    addToken(TokenUtils.getTokenId(token), issueTime, token.getExpiresDate().getTime());
  }

  @Override
  public void addToken(final String tokenId, long issueTime, long expiration) {
    addToken(tokenId, issueTime, expiration, getDefaultMaxLifetimeDuration());
  }

  @Override
  public void addToken(final String tokenId,
                             long   issueTime,
                             long   expiration,
                             long   maxLifetimeDuration) {
    validateTokenIdentifier(tokenId);
    tokenExpirations.put(tokenId, expiration);
    setMaxLifetime(tokenId, issueTime, maxLifetimeDuration);
    log.addedToken(tokenId, getTimestampDisplay(expiration));
    if (tokenStateServiceStatistics != null) {
      tokenStateServiceStatistics.addToken();
    }
  }

  @Override
  public long getTokenExpiration(final JWT token) throws UnknownTokenException {
    long expiration = -1;

    try {
      expiration = getTokenExpiration(TokenUtils.getTokenId(token));
    } catch (UnknownTokenException e) {
      if (permissiveValidationEnabled) {
        String exp = token.getExpires();
        if (exp != null) {
          log.permissiveTokenHandling(TokenUtils.getTokenId(token), e.getMessage());
          expiration = Long.parseLong(exp);
        }
      }

      if (expiration == -1) {
        throw e;
      }
    }

    return expiration;
  }

  @Override
  public long getTokenExpiration(final String tokenId) throws UnknownTokenException {
    return getTokenExpiration(tokenId, true);
  }

  @Override
  public long getTokenExpiration(String tokenId, boolean validate) throws UnknownTokenException {
    if (validate) {
      validateToken(tokenId);
    }

    final Long expiration = tokenExpirations.get(tokenId);
    if (expiration == null) {
      throw new UnknownTokenException(tokenId);
    }
    return expiration.longValue();
  }

  @Override
  public long renewToken(final JWTToken token) throws UnknownTokenException {
    return renewToken(token, DEFAULT_RENEWAL_INTERVAL);
  }

  @Override
  public long renewToken(final JWTToken token, long renewInterval) throws UnknownTokenException {
    if (token == null) {
      throw new IllegalArgumentException("Token cannot be null.");
    }
    return renewToken(TokenUtils.getTokenId(token), renewInterval);
  }

  @Override
  public long renewToken(final String tokenId) throws UnknownTokenException {
    return renewToken(tokenId, DEFAULT_RENEWAL_INTERVAL);
  }

  @Override
  public long renewToken(final String tokenId, long renewInterval) throws UnknownTokenException {
    long expiration;

    validateToken(tokenId);

    // Make sure the maximum lifetime has not been (and will not be) exceeded
    if (hasRemainingRenewals(tokenId, renewInterval)) {
      expiration = System.currentTimeMillis() + renewInterval;
      updateExpiration(tokenId, expiration);
      log.renewedToken(tokenId, getTimestampDisplay(expiration));
      if (tokenStateServiceStatistics != null) {
        tokenStateServiceStatistics.renewToken();
      }
    } else {
      log.renewalLimitExceeded(tokenId);
      throw new IllegalArgumentException("The renewal limit for the token has been exceeded");
    }

    return expiration;
  }

  @Override
  public boolean revokeToken(final JWTToken token) throws UnknownTokenException {
    if (token == null) {
      throw new IllegalArgumentException("Token cannot be null.");
    }

    return revokeToken(TokenUtils.getTokenId(token));
  }

  @Override
  public boolean revokeToken(final String tokenId) throws UnknownTokenException {
    /* no reason to keep revoked tokens around unless they are unused*/
    if (isUsed(tokenId)) {
      removeToken(tokenId);
      log.revokedToken(tokenId);
      return true;
    } else {
      log.skipRevokeUnusedToken(tokenId);
      return false;
    }
  }

  @Override
  public boolean isExpired(final JWTToken token) throws UnknownTokenException {
    return getTokenExpiration(token) <= System.currentTimeMillis();
  }

  @Override
  public void markTokenUnused(JWT token) throws UnknownTokenException {
    final String tokenId = TokenUtils.getTokenId(token);
    validateToken(tokenId);
    markTokenUnused(tokenId);
  }

  protected void markTokenUnused(String tokenId) {
    unusedTokens.add(tokenId);
    log.markedTokenUnused(tokenId);
  }

  protected boolean isUsed(String tokenId) {
    return !unusedTokens.contains(tokenId);
  }

  protected void setMaxLifetime(final String token, long parsedMaxLifeTime) {
    maxTokenLifetimes.put(token, parsedMaxLifeTime);
  }

  protected void setMaxLifetime(final String token, long issueTime, long maxLifetimeDuration) {
    maxTokenLifetimes.put(token, issueTime + maxLifetimeDuration);
  }

  /**
   * @param token
   * @return false, if the service has previously stored the specified token; Otherwise, true.
   */
  protected boolean isUnknown(final String token) {
    return !tokenExpirations.containsKey(token);
  }

  protected void updateExpiration(final String tokenId, long expiration) {
    tokenExpirations.put(tokenId, expiration);
  }

  protected void removeToken(final String tokenId) throws UnknownTokenException {
    validateToken(tokenId);
    removeTokens(Collections.singleton(tokenId));
  }

  /**
   * Bulk removal of the specified tokens.
   *
   * @param tokenIds The unique identifiers of the tokens whose state should be removed.
   */
  protected void removeTokens(final Set<String> tokenIds) {
    removeTokenState(tokenIds);
  }

  private void removeTokenState(final Set<String> tokenIds) {
    tokenExpirations.keySet().removeAll(tokenIds);
    maxTokenLifetimes.keySet().removeAll(tokenIds);
    unusedTokens.removeAll(tokenIds);
    metadataMap.keySet().removeAll(tokenIds);
    log.removedTokenState(String.join(", ", tokenIds));
  }

  protected boolean hasRemainingRenewals(final String tokenId, long renewInterval) {
    // If the current time + buffer + the renewal interval is less than the max lifetime for the token?
    return ((System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30) + renewInterval) < getMaxLifetime(tokenId));
  }

  protected long getMaxLifetime(final String tokenId) {
    return maxTokenLifetimes.getOrDefault(tokenId, 0L);
  }

  private void validateTokenIdentifier(final String tokenId) {
    if (tokenId == null || tokenId.isEmpty()) {
      throw new IllegalArgumentException("Token identifier cannot be null or empty.");
    }
  }

  /**
   * Validate the specified token identifier.
   *
   * @param tokenId The token identifier to validate.
   *
   * @throws IllegalArgumentException if the specified token in invalid.
   * @throws UnknownTokenException if the specified token in valid, but not known to the service.
   */
  protected void validateToken(final String tokenId) throws IllegalArgumentException, UnknownTokenException {
    validateTokenIdentifier(tokenId);

    // First, make sure the token is one we know about
    if (isUnknown(tokenId)) {
      log.unknownToken(tokenId);
      throw new UnknownTokenException(tokenId);
    }
  }

  private String getTimestampDisplay(long timestamp) {
    return Instant.ofEpochMilli(timestamp).toString();
  }

  /**
   * Method that deletes expired tokens based on the token timestamp.
   */
  protected void evictExpiredTokens() {
    if (readyForEviction()) {
      final Set<String> tokensToEvict = new HashSet<>();

      for (final String tokenId : getTokenIds()) {
        try {
          if (needsEviction(tokenId)) {
            log.evictToken(tokenId);
            tokensToEvict.add(tokenId); // Add the token to the set of tokens to evict
          }
        } catch (final Exception e) {
          log.failedExpiredTokenEviction(tokenId, e);
        }
      }

      if (!tokensToEvict.isEmpty()) {
        removeTokens(tokensToEvict);
      }
    } else {
      log.skipEviction();
    }
  }

  protected boolean readyForEviction() {
    return true;
  }

  /**
   * Method that checks if a token's state is a candidate for eviction.
   *
   * @param tokenId A unique token identifier
   * @throws UnknownTokenException if token state is not found.
   *
   * @return true, if the associated token state can be evicted; Otherwise, false.
   */
  protected boolean needsEviction(final String tokenId) throws UnknownTokenException {
    // If the expiration time(+ grace period) has already passed, it should be considered expired
    long expirationWithGrace = getTokenExpiration(tokenId, false) + TimeUnit.SECONDS.toMillis(tokenEvictionGracePeriod);
    return (expirationWithGrace <= System.currentTimeMillis());
  }

  /**
   * Get a list of tokens
   *
   * @return
   */
  protected List<String> getTokenIds() {
    return tokenExpirations.keySet().stream().collect(Collectors.toList());
  }

  @Override
  public void addMetadata(String tokenId, TokenMetadata metadata) {
    metadataMap.put(tokenId, metadata);
  }

  @Override
  public TokenMetadata getTokenMetadata(String tokenId) {
    return metadataMap.get(tokenId);
  }
}
