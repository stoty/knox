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

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;
import org.apache.knox.gateway.i18n.messages.StackTrace;

@Messages(logger = "org.apache.knox.gateway.services.token.state")
public interface TokenStateServiceMessages {

  @Message(level = MessageLevel.DEBUG, text = "Added token {0}, expiration {1}")
  void addedToken(String tokenId, String expiration);

  @Message(level = MessageLevel.DEBUG, text = "Renewed token {0}, expiration {1}")
  void renewedToken(String tokenId, String expiration);

  @Message(level = MessageLevel.DEBUG, text = "Revoked token {0}")
  void revokedToken(String tokenId);

  @Message(level = MessageLevel.DEBUG, text = "Skipped revoking unused token {0}")
  void skipRevokeUnusedToken(String tokenId);

  @Message(level = MessageLevel.DEBUG, text = "Marked token {0} unused")
  void markedTokenUnused(String tokenId);

  @Message(level = MessageLevel.DEBUG, text = "Removed state for tokens {0}")
  void removedTokenState(String tokenIds);

  @Message(level = MessageLevel.ERROR, text = "Unknown token {0}")
  void unknownToken(String tokenId);

  @Message(level = MessageLevel.ERROR, text = "The renewal limit for the token ({0}) has been exceeded.")
  void renewalLimitExceeded(String tokenId);

  @Message(level = MessageLevel.ERROR, text = "Failed to save state for token {0} : {1}")
  void failedToSaveTokenState(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Error accessing token state : {0}")
  void errorAccessingTokenState(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Error accessing state for token {0} : {1}")
  void errorAccessingTokenState(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.INFO,
           text = "Referencing the expiration in the token ({0}) because no state could not be found: {1}")
  void permissiveTokenHandling(String tokenId, String errorMessage);

  @Message(level = MessageLevel.ERROR, text = "Failed to update expiration for token {0} : {1}")
  void failedToUpdateTokenExpiration(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to create token state aliases : {0}")
  void failedToCreateTokenStateAliases(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to remove state for token {0} : {1}")
  void failedToRemoveTokenStateAliases(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to remove token state aliases : {0}")
  void failedToRemoveTokenStateAliases(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.DEBUG, text = "Skipping expired token eviction")
  void skipEviction();

  @Message(level = MessageLevel.ERROR, text = "Failed to evict expired token {0} : {1}")
  void failedExpiredTokenEviction(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to evict expired tokens : {0}")
  void failedExpiredTokenEviction(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.INFO, text = "Evicting expired token {0}")
  void evictToken(String tokenId);

  @Message(level = MessageLevel.ERROR, text = "Error occurred evicting token {0}")
  void errorEvictingTokens(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.INFO, text = "Creating token state aliases")
  void creatingTokenStateAliases();

  @Message(level = MessageLevel.DEBUG, text = "Creating token state aliases for {0}")
  void creatingTokenStateAliases(String tokenId);

  @Message(level = MessageLevel.INFO, text = "Created token state aliases for {0}")
  void createdTokenStateAliases(String tokenId);

  @Message(level = MessageLevel.INFO, text = "Removing token state aliases")
  void removingTokenStateAliases();

  @Message(level = MessageLevel.DEBUG, text = "Removing token state aliases for {0}")
  void removingTokenStateAliases(String tokenId);

  @Message(level = MessageLevel.INFO, text = "Removed token state aliases for {0}")
  void removedTokenStateAliases(String tokenIds);

  @Message(level = MessageLevel.DEBUG, text = "Loading peristed token state journal entries")
  void loadingPersistedJournalEntries();

  @Message(level = MessageLevel.DEBUG, text = "Loaded peristed token state journal entry for {0}")
  void loadedPersistedJournalEntry(String tokenId);

  @Message(level = MessageLevel.ERROR, text = "The peristed token state journal entry {0} is empty")
  void emptyJournalEntry(String journalEntryName);

  @Message(level = MessageLevel.DEBUG, text = "Added token state journal entry for {0}")
  void addedJournalEntry(String tokenId);

  @Message(level = MessageLevel.DEBUG, text = "Removed token state journal entry for {0}")
  void removedJournalEntry(String tokenId);

  @Message(level = MessageLevel.INFO, text = "Token state journal entry not found for {0}")
  void journalEntryNotFound(String tokenId);

  @Message(level = MessageLevel.DEBUG, text = "Persisting token state journal entry as {0}")
  void persistingJournalEntry(String journalEntryFilename);

  @Message(level = MessageLevel.ERROR, text = "Failed to load persisted token state journal entry for {0} : {1}")
  void failedToLoadJournalEntry(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to load persisted token state journal entry : {0}")
  void failedToLoadJournalEntry(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to persisting token state journal entry for {0} : {1}")
  void failedToPersistJournalEntry(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to add a token state journal entry for {0} : {1}")
  void failedToAddJournalEntry(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to remove the token state journal entry for {0} : {1}")
  void failedToRemoveJournalEntry(String tokenId, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.ERROR, text = "Failed to remove the token state journal entries : {0}")
  void failedToRemoveJournalEntries(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.INFO, text = "Loading Gateway credentials on startup...")
  void loadingGatewayCredentialsOnStartup();

  @Message(level = MessageLevel.INFO, text = "Loaded {0} Gateway credentials in {1} milliseonds")
  void loadedGatewayCredentialsOnStartup(int count, long duration);

  @Message(level = MessageLevel.ERROR, text = "Error while loading Gateway credentials on startup: {0}")
  void errorWhileLoadingGatewayCredentialsOnStartup(String errorMessage, @StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.INFO, text = "Trying to fetch value for {0} from Zookeeper...")
  void retryZkFetchAlias(String alias);

  @Message(level = MessageLevel.ERROR, text = "Error while fetching value for {0} from Zookeeper: {1}")
  void failedRetryZkFetchAlias(String alias, String errorMessage, @StackTrace(level = MessageLevel.DEBUG) Exception e);
}
