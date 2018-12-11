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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import java.net.URL;
import java.util.Map;
import java.util.TreeMap;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AFileSystem;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;

/**
 * These tests are very related to tracking down IDE classpath
 * issues: S3A wasn't loading because fs.s3a.impl wasn't in the configuration,
 * though it was in maven tests.
 * 
 * some restarts of IDE and cache rebuilds made this go away, but it seems
 * useful to hang onto these (inexpensive, low-maintenance) tests for safety.
 */
public class TestClasspathSetup {

  protected static final Logger LOG =
      LoggerFactory.getLogger(TestClasspathSetup.class);
  @Test
  public void testS3AFSLoad() throws Throwable {
    new S3AFileSystem().close();
  }

  @Test
  public void testCoreDefaultOnCP() throws Throwable {
    Configuration conf = new Configuration();
    URL coredefault = checkNotNull(
        this.getClass()
        .getClassLoader()
        .getResource("core-default.xml"),
        "core-default");
    LOG.info("core-default is at {}", coredefault);
  }
  
  @Test
  public void testS3SFSRegistered() throws Throwable {
    Configuration conf = new Configuration();
    assertEquals("value of \"fs.s3a.impl\"",
        "org.apache.hadoop.fs.s3a.S3AFileSystem",
    conf.get("fs.s3a.impl"));
  }

  @Test
  public void testDumpS3AValues() throws Throwable {
    Configuration conf = new Configuration();
    String prefix = "fs.s3a";
    Map<String, String> props = new TreeMap<>(
        conf.getPropsWithPrefix(prefix));
    for (Map.Entry<String, String> entry : props.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (key.contains(".key")) {
        value = "*****";
      }
      LOG.info("{}{}: {}", prefix, key, value);
    }
  }
  
}
