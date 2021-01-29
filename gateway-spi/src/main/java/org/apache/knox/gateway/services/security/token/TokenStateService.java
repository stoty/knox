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
package org.apache.knox.gateway.services.security.token;

import org.apache.knox.gateway.services.Service;
import org.apache.knox.gateway.services.security.token.impl.JWT;
import org.apache.knox.gateway.services.security.token.impl.JWTToken;


/**
 * Service providing authentication token state management.
 */
public interface TokenStateService extends Service {

  String CONFIG_SERVER_MANAGED = "knox.token.exp.server-managed";

  /**
   * @return The default duration (in milliseconds) for which a token's life will be extended when it is renewed.
   */
  long getDefaultRenewInterval();

  /**
   * @return The default maximum lifetime duration (in milliseconds) of a token.
   */
  long getDefaultMaxLifetimeDuration();

  /**
   * Add state for the specified token.
   *
   * @param token     The token.
   * @param issueTime The time the token was issued.
   */
  void addToken(JWTToken token, long issueTime);

  /**
   * Add state for the specified token.
   *
   * @param tokenId    The token unique identifier.
   * @param issueTime  The time the token was issued.
   * @param expiration The token expiration time.
   */
  void addToken(String tokenId, long issueTime, long expiration);

  /**
   * Add state for the specified token.
   *
   * @param tokenId             The token unique identifier.
   * @param issueTime           The time the token was issued.
   * @param expiration          The token expiration time.
   * @param maxLifetimeDuration The maximum allowed lifetime for the token.
   */
  void addToken(String tokenId, long issueTime, long expiration, long maxLifetimeDuration);

  /**
   *
   * @param token The token.
   *
   * @return true, if the token has expired; Otherwise, false.
   */
  boolean isExpired(JWTToken token) throws UnknownTokenException;

  /**
   * Disable any subsequent use of the specified token.
   *
   * @param token The token.
   */
  boolean revokeToken(JWTToken token) throws UnknownTokenException;

  /**
   * Disable any subsequent use of the specified token.
   *
   * @param tokenId The token unique identifier.
   */
  boolean revokeToken(String tokenId) throws UnknownTokenException;

  /**
   * Extend the lifetime of the specified token by the default amount of time.
   *
   * @param token The token.
   *
   * @return The token's updated expiration time in milliseconds.
   */
  long renewToken(JWTToken token) throws UnknownTokenException;

  /**
   * Extend the lifetime of the specified token by the specified amount of time.
   *
   * @param token The token.
   * @param renewInterval The amount of time that should be added to the token's lifetime.
   *
   * @return The token's updated expiration time in milliseconds.
   */
  long renewToken(JWTToken token, long renewInterval) throws UnknownTokenException;

  /**
   * Extend the lifetime of the specified token by the default amount of time.
   *
   * @param tokenId The token unique identifier.
   *
   * @return The token's updated expiration time in milliseconds.
   */
  long renewToken(String tokenId) throws UnknownTokenException;

  /**
   * Extend the lifetime of the specified token by the specified amount of time.
   *
   * @param tokenId The token unique identifier.
   * @param renewInterval The amount of time that should be added to the token's lifetime.
   *
   * @return The token's updated expiration time in milliseconds.
   */
  long renewToken(String tokenId, long renewInterval) throws UnknownTokenException;

  /**
   *
   * @param token The token.
   *
   * @return The token's expiration time in milliseconds.
   */
  long getTokenExpiration(JWT token) throws UnknownTokenException;

  /**
   *
   * @param tokenId The token unique identifier.
   *
   * @return The token's expiration time in milliseconds.
   */
  long getTokenExpiration(String tokenId) throws UnknownTokenException;

  /**
   * Get the expiration for the specified token, optionally validating the token prior to accessing its expiration.
   * In some cases, the token has already been validated, and skipping an additional unnecessary validation improves
   * performance.
   *
   * @param tokenId  The token unique identifier.
   * @param validate Flag indicating whether the token needs to be validated.
   *
   * @return The token's expiration time in milliseconds.
   */
  long getTokenExpiration(String tokenId, boolean validate) throws UnknownTokenException;

  /**
   * Marks the given token unused. An unused token then will not be revoked even
   * if a revocation request is received. The reaper thread will take care of
   * cleaning it up.
   *
   * @param token
   *          the token to me marked unused
   * @throws UnknownTokenException
   *           if the given token is unknown
   */
  void markTokenUnused(JWT token) throws UnknownTokenException;

}
