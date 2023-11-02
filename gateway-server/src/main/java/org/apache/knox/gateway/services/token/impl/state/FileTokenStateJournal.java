/*
 *
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
 *
 */
package org.apache.knox.gateway.services.token.impl.state;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.services.token.state.JournalEntry;
import org.apache.knox.gateway.services.token.state.TokenStateJournal;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.token.impl.TokenStateServiceMessages;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Base class for TokenStateJournal implementations that employ files for persistence.
 */
public abstract class FileTokenStateJournal implements TokenStateJournal {

    protected static final int INDEX_TOKEN_ID     = 0;
    protected static final int INDEX_ISSUE_TIME   = 1;
    protected static final int INDEX_EXPIRATION   = 2;
    protected static final int INDEX_MAX_LIFETIME = 3;
    protected static final int INDEX_ENABLED      = 4;
    protected static final int INDEX_USERNAME     = 5;
    protected static final int INDEX_COMMENT      = 6;

    protected static final TokenStateServiceMessages log = MessagesFactory.get(TokenStateServiceMessages.class);

    // The name of the journal directory
    protected static final String JOURNAL_DIR_NAME = "token-state";

    /**
     * The journal directory path
     */
    protected final Path journalDir;

    protected FileTokenStateJournal(GatewayConfig config) throws IOException {
        journalDir = Paths.get(config.getGatewaySecurityDir(), JOURNAL_DIR_NAME);
        if (!Files.exists(journalDir)) {
            Files.createDirectories(journalDir);
        }
    }

    @Override
    public abstract void add(String tokenId, long issueTime, long expiration, long maxLifetime, TokenMetadata tokenMetadata) throws IOException;

    @Override
    public void add(JournalEntry entry) throws IOException {
        add(Collections.singletonList(entry));
    }

    @Override
    public abstract void add(List<JournalEntry> entries) throws IOException;

    @Override
    public List<JournalEntry> get() throws IOException {
        return loadJournal();
    }

    @Override
    public abstract JournalEntry get(String tokenId) throws IOException;

    @Override
    public void remove(final String tokenId) throws IOException {
        remove(Collections.singleton(tokenId));
    }

    @Override
    public abstract void remove(Collection<String> tokenIds) throws IOException;

    @Override
    public void remove(final JournalEntry entry) throws IOException {
        remove(entry.getTokenId());
    }

    protected abstract List<JournalEntry> loadJournal() throws IOException;

    protected List<FileJournalEntry> loadJournal(FileChannel channel) throws IOException {
        List<FileJournalEntry> entries = new ArrayList<>();

        try (InputStream input = Channels.newInputStream(channel)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    entries.add(FileJournalEntry.parse(line));
                } catch (Exception e) {
                    log.failedToLoadJournalEntry(e);
                }
            }
        }

        return entries;
    }

    /**
     * Parse the String representation of an entry.
     *
     * @param entry A journal file entry line
     *
     * @return A FileJournalEntry object created from the specified entry.
     */
    protected FileJournalEntry parse(final String entry) {
        return FileJournalEntry.parse(entry);
    }

    /**
     * A JournalEntry implementation for File-based TokenStateJournal implementations
     */
    public static final class FileJournalEntry implements JournalEntry {
        private final String tokenId;
        private final String issueTime;
        private final String expiration;
        private final String maxLifetime;
        private final TokenMetadata tokenMetadata;

        FileJournalEntry(final String tokenId, long issueTime, long expiration, long maxLifetime) {
          this(tokenId, String.valueOf(issueTime), String.valueOf(expiration), String.valueOf(maxLifetime), null);
        }

        FileJournalEntry(final String tokenId, long issueTime, long expiration, long maxLifetime, TokenMetadata tokenMetadata) {
            this(tokenId, String.valueOf(issueTime), String.valueOf(expiration), String.valueOf(maxLifetime), tokenMetadata);
        }

        public FileJournalEntry(final String tokenId,
                         final String issueTime,
                         final String expiration,
                         final String maxLifetime,
                         final TokenMetadata tokenMetadata) {
            this.tokenId = tokenId;
            this.issueTime = issueTime;
            this.expiration = expiration;
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
            String[] elements = new String[7];

            elements[INDEX_TOKEN_ID] = getTokenId();

            String issueTime = getIssueTime();
            elements[INDEX_ISSUE_TIME] = (issueTime != null) ? issueTime : "";

            String expiration = getExpiration();
            elements[INDEX_EXPIRATION] = (expiration != null) ? expiration : "";

            String maxLifetime = getMaxLifetime();
            elements[INDEX_MAX_LIFETIME] = (maxLifetime != null) ? maxLifetime : "";

            String enabled = getTokenMetadata() == null ? "" : String.valueOf(getTokenMetadata().isEnabled());
            elements[INDEX_ENABLED] = enabled;

            String userName = getTokenMetadata() == null ? "" : (getTokenMetadata().getUserName() == null ? "" : getTokenMetadata().getUserName());
            elements[INDEX_USERNAME] = userName;

            String comment = getTokenMetadata() == null ? "" : (getTokenMetadata().getComment() == null ? "" : getTokenMetadata().getComment());
            elements[INDEX_COMMENT] = comment;

            return String.format(Locale.ROOT,
                                 "%s,%s,%s,%s,%s,%s,%s",
                                 elements[INDEX_TOKEN_ID],
                                 elements[INDEX_ISSUE_TIME],
                                 elements[INDEX_EXPIRATION],
                                 elements[INDEX_MAX_LIFETIME],
                                 elements[INDEX_ENABLED],
                                 elements[INDEX_USERNAME],
                                 elements[INDEX_COMMENT]);
        }

        /**
          * Parse the String representation of an entry.
          *
          * @param entry A journal file entry line
          *
          * @return A FileJournalEntry object created from the specified entry.
          */
        static FileJournalEntry parse(final String entry) {
            String[] elements = entry.split(",", -1);
            if (elements.length < 7) {
                throw new IllegalArgumentException("Invalid journal entry: " + entry);
            }

            String tokenId     = elements[INDEX_TOKEN_ID].trim();
            String issueTime   = elements[INDEX_ISSUE_TIME].trim();
            String expiration  = elements[INDEX_EXPIRATION].trim();
            String maxLifetime = elements[INDEX_MAX_LIFETIME].trim();
            String enabled     = elements[INDEX_ENABLED].trim();
            String userName    = elements[INDEX_USERNAME].trim();
            String comment     = elements[INDEX_COMMENT].trim();

            return new FileJournalEntry(tokenId.isEmpty() ? null : tokenId,
                                        issueTime.isEmpty() ? null : issueTime,
                                        expiration.isEmpty() ? null : expiration,
                                        maxLifetime.isEmpty() ? null : maxLifetime,
                                        new TokenMetadata(userName.isEmpty() ? null : userName, comment.isEmpty() ? null : comment, Boolean.parseBoolean(enabled)));
        }

    }

}
