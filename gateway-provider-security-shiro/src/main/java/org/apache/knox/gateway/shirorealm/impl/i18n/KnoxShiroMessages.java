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

package org.apache.knox.gateway.shirorealm.impl.i18n;

import org.apache.knox.gateway.i18n.messages.Message;
import org.apache.knox.gateway.i18n.messages.MessageLevel;
import org.apache.knox.gateway.i18n.messages.Messages;

import org.apache.knox.gateway.i18n.messages.StackTrace;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

@Messages(logger = "org.apache.knox.gateway")
public interface KnoxShiroMessages {

  @Message(level = MessageLevel.ERROR, text = "Shiro unable to login: {0}")
  void failedLoginAttempt(Throwable e);

  @Message(level = MessageLevel.INFO, text = "Could not login: {0}")
  void failedLoginInfo(AuthenticationToken token);

  @Message( level = MessageLevel.DEBUG, text = "Failed to Authenticate with LDAP server: {0}" )
  void failedLoginStackTrace( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message(level = MessageLevel.INFO, text = "Successfully logged in: {0}, {1}")
  void successfulLoginAttempt(Subject subject, AuthenticationToken authToken);

}
