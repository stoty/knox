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

package org.apache.knox.gateway.cloud.idbroker.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * KnoxTokenMonitor is used to help monitor a {@link KnoxToken} and trigger calls to renew it when the
 * KnoxToken is within some time of being expired.
 * <p>
 * Upon creating a KnoxMonitor, an {@link java.util.concurrent.ExecutorService} implementation is
 * instantiated to manage a thread used to poll the specified KnoxToken and ensure it does not time out.
 * A thread is started upon setting the KnoxToken to be monitor using the {@link #monitorKnoxToken(KnoxToken, long, GetKnoxTokenCommand)}
 * method. The {@link GetKnoxTokenCommand} is provided by the caller to provide a sink to receive the
 * notification that the KnoxToken is to be renewed.
 */
public class KnoxTokenMonitor {

  protected static final Logger LOG = LoggerFactory.getLogger(KnoxTokenMonitor.class);

  /**
   * The thread executor.  Ensure that the scheduled thread is a daemon thread so that it does not
   * prevent the application from exiting.  For example:
   * <p>
   * <pre>
   *   hdfs fetchdt --webservice fs://path... /tmp/token.txt
   * </pre>
   */
  private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
    Thread thread = Executors.defaultThreadFactory().newThread(runnable);
    thread.setDaemon(true);
    return thread;
  });

  private ScheduledFuture<?> scheduledMonitor = null;

  public void monitorKnoxToken(KnoxToken knoxToken, long knoxTokenExpirationOffsetSeconds, GetKnoxTokenCommand command) {
    if (scheduledMonitor != null) {
      LOG.debug("Stopping previously scheduled KnoxTokenMonitor");
      scheduledMonitor.cancel(false);
    }

    if (knoxToken != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Token expires in {} seconds:" +
                "\n\tNow: {}" +
                "\n\tExpiry: {}",
            knoxToken.getExpiry() - Instant.now().getEpochSecond(),
            Instant.now().toString(),
            Instant.ofEpochSecond(knoxToken.getExpiry()).toString());
      }

      long delaySeconds = knoxToken.getExpiry() - Instant.now().getEpochSecond() - knoxTokenExpirationOffsetSeconds;
      if (delaySeconds < 0) {
        delaySeconds = 0;
      }

      LOG.debug("Starting KnoxTokenMonitor in {} seconds and running every {} seconds after", delaySeconds, knoxTokenExpirationOffsetSeconds);

      scheduledMonitor = executor.scheduleAtFixedRate(new Monitor(knoxToken, knoxTokenExpirationOffsetSeconds, command), delaySeconds, knoxTokenExpirationOffsetSeconds, TimeUnit.SECONDS);
    }
  }

  public void shutdown() {
    LOG.debug("Shutting down KnoxTokenMonitor");
    executor.shutdown();

    try {
      executor.awaitTermination(20, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      LOG.warn("Failed to properly shutdown executor", e);
    }

    if (executor.isShutdown()) {
      LOG.debug("KnoxTokenMonitor has been shutdown.");
    }
  }

  /**
   * Monitor is a {@link Runnable} implementation triggered as scheduled by the {@link ScheduledExecutorService},
   * which is initiated in {@link #monitorKnoxToken(KnoxToken, long, GetKnoxTokenCommand)}.
   */
  private class Monitor implements Runnable {
    private final KnoxToken knoxToken;
    private final long knoxTokenExpirationOffsetSeconds;
    private final GetKnoxTokenCommand command;

    Monitor(KnoxToken knoxToken, long knoxTokenExpirationOffsetSeconds, GetKnoxTokenCommand command) {
      this.knoxToken = knoxToken;
      this.knoxTokenExpirationOffsetSeconds = knoxTokenExpirationOffsetSeconds;
      this.command = command;
    }

    @Override
    public void run() {
      LOG.debug("Renewing the Knox delegation token, if necessary...");

      if (command == null) {
        LOG.warn("Cannot renew the Knox delegation token, the GetKnoxTokenCommand has not been set.");
      } else if ((knoxToken != null) && knoxToken.isAboutToExpire(knoxTokenExpirationOffsetSeconds)) {
        try {
          LOG.debug("The Knox delegation token is expired or is close to expiration. Renewing....");
          command.execute(knoxToken);
        } catch (Exception e) {
          LOG.error("Failed to renew the Knox delegation token", e);
        }
      }
    }
  }

  public interface GetKnoxTokenCommand {
    void execute(KnoxToken knoxToken) throws IOException;
  }
}
