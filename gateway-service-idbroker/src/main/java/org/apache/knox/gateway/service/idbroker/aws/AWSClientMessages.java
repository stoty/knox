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
package org.apache.knox.gateway.service.idbroker.aws;

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;
import org.apache.knox.gateway.i18n.messages.StackTrace;

@Messages(logger = "org.apache.knox.gateway.service.idbroker.aws")
public interface AWSClientMessages {

  @Message(level = MessageLevel.ERROR, text = "AWS credentials client error : {0}")
  void logException(@StackTrace(level = MessageLevel.DEBUG) Exception e);

  @Message(level = MessageLevel.WARN, text = "Missing alias {0} for Cloud Access Broker.")
  void aliasConfigurationError(String alias);

  @Message(level = MessageLevel.ERROR, text = "Cloud Access Broker configuration error: {0}")
  void cabConfigurationError(String error);

  @Message(level = MessageLevel.ERROR, text = "Cloud Access Broker ({0}) is not permitted to assume the specified role {1} : {2}")
  void assumeRoleDisallowed(String idBrokerRole, String role, String error);

  @Message(level = MessageLevel.ERROR, text = "Error fetching credentials for role {0} from cache reason: {1}")
  void cacheException(String role, String error);

}