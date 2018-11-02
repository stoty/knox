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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import java.util.Arrays;
import java.util.Collection;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.examples.WordCount;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapreduce.JobStatus;
import org.apache.hadoop.mapreduce.MockJobForTesting;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.v2.MiniMRYarnCluster;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.MiniIDBHadoopCluster;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.deployService;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.disableFilesystemCaching;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.terminateService;
import static org.apache.knox.gateway.cloud.idbroker.MiniIDBHadoopCluster.closeUserFileSystems;

/**
 * Submit a job with S3 delegation tokens.
 *
 * YARN will not collect DTs unless it is running secure, and turning
 * security on complicates test setup "significantly".
 * Specifically: buts of MR refuse to work on a local FS unless the
 * native libraries are loaded and it can use lower level POSIX APIs
 * for creating files and directories with specific permissions.
 * In production, this is a good thing. In tests, this is not.
 *
 * To address this, Job to YARN communications are mocked.
 * The client-side job submission is as normal, but the implementation
 * of org.apache.hadoop.mapreduce.protocol.ClientProtocol is mock.
 *
 */
@RunWith(Parameterized.class)
public class ITestIDBMRJob extends AbstractStoreDelegationIT {

  private static final Logger LOG =
      LoggerFactory.getLogger(ITestIDBMRJob.class);

  /**
   * Created in static {@link #setupCluster()} call.
   */
  @SuppressWarnings("StaticNonFinalField")
  private static MiniIDBHadoopCluster cluster;

  private final String name;

  private final String tokenBinding;

  private final Text tokenKind;

  /**
   * Default path for the multi MB test file: {@value}.
   */
  String DEFAULT_CSVTEST_FILE = "s3a://landsat-pds/scene_list.gz";

  /**
   * Created in test setup.
   */
  private MiniMRYarnCluster yarn;

  private Path destPath;

  public ITestIDBMRJob(String name, String tokenBinding, Text tokenKind) {
    this.name = name;
    this.tokenBinding = tokenBinding;
    this.tokenKind = tokenKind;
  }

  /**
   * Test array for parameterized test runs.
   * @return a list of parameter tuples.
   */
  @Parameterized.Parameters
  public static Collection<Object[]> params() {
    return Arrays.asList(new Object[][]{
        {
            "idb",
            IDBConstants.DELEGATION_TOKEN_IDB_BINDING,
            IDBConstants.IDB_TOKEN_KIND
        },
    });
  }

  /***
   * Set up the clusters.
   */
  @BeforeClass
  public static void setupCluster() throws Exception {
    JobConf conf = new JobConf();
    disableFilesystemCaching(conf);
    cluster = deployService(conf, new MiniIDBHadoopCluster());
  }

  /**
   * Tear down the cluster.
   */
  @AfterClass
  public static void teardownCluster() throws Exception {
    cluster = terminateService(cluster);
  }

  @Override
  protected YarnConfiguration createConfiguration() {
    Configuration parent = super.createConfiguration();
    YarnConfiguration conf = new YarnConfiguration(parent);
    cluster.patchConfigWithYARNBindings(conf);

    // fail fairly fast
    conf.setInt(YarnConfiguration.RESOURCEMANAGER_CONNECT_MAX_WAIT_MS,
        100);
    conf.setInt(YarnConfiguration.RESOURCEMANAGER_CONNECT_RETRY_INTERVAL_MS,
        10_000);

    // set up DTs
    enableDelegationTokens(conf, tokenBinding);
    return conf;
  }

  @Override
  public void setup() throws Exception {
    cluster.loginPrincipal();
    super.setup();
    Configuration conf = getConfiguration();

    // filesystems are cached across the test so that
    // instrumentation fields can be asserted on

    UserGroupInformation.setConfiguration(conf);

    LOG.info("Starting MiniMRCluster");
    yarn = deployService(conf,
        new MiniMRYarnCluster("ITestDelegatedMRJob", 1));

  }

  @Override
  public void teardown() throws Exception {
    describe("Teardown operations");
    S3AFileSystem fs = getFileSystem();
    if (fs != null && destPath != null) {
      fs.delete(destPath, true);
    }
    yarn = terminateService(yarn);
    super.teardown();
    closeUserFileSystems(UserGroupInformation.getCurrentUser());
  }

  @Override
  protected YarnConfiguration getConfiguration() {
    return (YarnConfiguration) super.getConfiguration();
  }

  @Test
  public void testJobSubmissionCollectsTokens() throws Exception {
    describe("Mock Job test");
    JobConf conf = new JobConf(getConfiguration());

    // the input here is the landsat file; which lets
    // us differentiate source URI from dest URI
    Path input = new Path(DEFAULT_CSVTEST_FILE);
    final FileSystem sourceFS = input.getFileSystem(conf);


    // output is in the writable test FS.
    final S3AFileSystem fs = getFileSystem();

    destPath = path(getMethodName());
    fs.delete(destPath, true);
    fs.mkdirs(destPath);
    Path output = new Path(destPath, "output/");
    output = output.makeQualified(fs.getUri(), fs.getWorkingDirectory());

    MockJobForTesting job = new MockJobForTesting(conf, "word count");
    job.setJarByClass(WordCount.class);
    job.setMapperClass(WordCount.TokenizerMapper.class);
    job.setCombinerClass(WordCount.IntSumReducer.class);
    job.setReducerClass(WordCount.IntSumReducer.class);
    job.setOutputKeyClass(Text.class);
    job.setOutputValueClass(IntWritable.class);
    FileInputFormat.addInputPath(job, input);
    FileOutputFormat.setOutputPath(job, output);
    job.setMaxMapAttempts(1);
    job.setMaxReduceAttempts(1);

    describe("Executing Mock Job Submission to %s", output);

    job.submit();
    final JobStatus status = job.getStatus();
    assertEquals("not a mock job",
        MockJobForTesting.NAME, status.getSchedulingInfo());
    assertEquals("Job State",
        JobStatus.State.RUNNING, status.getState());

    final Credentials submittedCredentials =
        checkNotNull(job.getSubmittedCredentials(),
            "job submitted credentials");
    final Collection<Token<? extends TokenIdentifier>> tokens
        = submittedCredentials.getAllTokens();

    // log all the tokens for debugging failed test runs
    LOG.info("Token Count = {}", tokens.size());
    for (Token<? extends TokenIdentifier> token : tokens) {
      LOG.info("{}", token);
    }

    // verify the source token exists
    lookupToken(submittedCredentials, sourceFS.getUri(), tokenKind);
    // look up the destination token
    lookupToken(submittedCredentials, fs.getUri(), tokenKind);
  }

}
