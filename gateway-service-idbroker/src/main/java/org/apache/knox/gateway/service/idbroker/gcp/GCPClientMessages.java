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
package org.apache.knox.gateway.service.idbroker.gcp;

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;
import org.apache.knox.gateway.i18n.messages.StackTrace;

@Messages(logger = "org.apache.knox.gateway.service.idbroker.gcp")
public interface GCPClientMessages {

  @Message(level = MessageLevel.ERROR, text = "GCP credentials client error : {0}")
  void logException(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.DEBUG, text = "Using serviceAccount {0} for the cloud access broker role.")
  void configuredServiceAccount(String serviceAccount);

  @Message(level = MessageLevel.DEBUG, text = "Attempting to authenticate the Cloud Access Broker with the cloud platform.")
  void authenticateCAB();

  @Message(level = MessageLevel.DEBUG, text = "Cloud Access Broker has been authenticated.")
  void cabAuthenticated();

  @Message(level = MessageLevel.ERROR, text = "Failed to acquire token for the Cloud Access Broker.")
  void failedToAcquireAuthTokenForCAB();

  @Message(level = MessageLevel.ERROR, text = "Error fetching credentials for role {0} from cache reason: {1}")
  void cacheException(final String role, final String error);

}
