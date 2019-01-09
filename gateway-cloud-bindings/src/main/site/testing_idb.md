<!---
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
   http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License. See accompanying LICENSE file.
-->

# Testing gateway cloud bindings


The test process here follows roughly the same configuration and execution process
as for [Testing the Hadoop S3A client](https://hadoop.apache.org/docs/current/hadoop-aws/tools/hadoop-aws/testing.html).

1. Separate Unit tests from Integration Tests —the latter use cloud credentials
to work with object stores.
1. Unless Jenkins/Gerritt is granted cloud credentials, only the unit tests
will be executed in automated patch reviews.
1. It is up to the patch submitter to run all integration tests before submitting
their patch.
1. No declaration of Integration Tests: no review/merge. *We cannot rely on the automation tooling*. Sorry.
1. Cloud integration tests pick up their credentials from: environment variables,
or values in `gateway-cloud-bindings/src/test/resources/auth-keys.xml`.
1. The latter is a git-ignored file imported in 
`gateway-cloud-bindings/src/test/resources/core-site.xml`; if present it will
be loaded in `new Configuration()`.
1. You can use another layer of XInclude
[to keep all your secrets out of the source tree](http://steveloughran.blogspot.com/2016/04/testing-against-s3-and-object-stores.html) 


## Unit Tests

Unit tests have the prefix or suffix "Test", and are declared in the UnitTests
category:

```java
@Category(UnitTests.class)
```


These do not require any object store
credentials, and can be safely run in public jenkins tests.

```bash
mvn test -Pcloud

mvn test -Pcloud -Dtest=TestTransitiveDependencies
```

New Unit tests *must not* require cloud access. If they do, that's
an integration test.


## Integration Tests

Integration tests have the prefix "ITest". These require cloud credentials,
and the test system to be online.

```java
@Category(VerifyTest.class)
```


We may also need to require Kerberos, if a mini KDC is not enough.

```bash
mvn verify -Pcloud

mvn verify -Pcloud -Dtest=none -DfailIfNoTests=false -Dit.test=ITestIDBClient
```

ITests should use `Assume` to check for the specific credentials
for that store. Why? 

* stops lack of credentials being mistaken for actual test failures.
* allows you to focus on testing one specific store by removing the 
credentials.


## Test endpoints

Test Filesystems are needed. These are only used for reading, so the public
endpoints can be used.

| Key | example |  meaning  |
|-----|---------|---------|
| `test.gs.filesystem` | `gs://gcp-public-data-landsat/` | GS URL |
| `test.s3a.filesystem` | `s3a://lansdat-pds/` | S3A URL |
| `` | `` | `` |


## Configuring GCS Tests

The GCS Tests support configuration through environment variables
as well as `auth-keys.xml` settings. 

| Key | Env var | Default |
|-----|---------|---------|
| `fs.gs.ext.cab.address` | `fs_gs_ext_cab_address` | `https://localhost:8443/gateway` |
| `test.gcp.project` | `CAB_INTEGRATION_TEST_GCP_PROJECT` | `` |
| `test.gs.filesystem` | `CAB_INTEGRATION_TEST_GCP_BUCKET` | `` |
| `fs.gs.ext.cab.username` | `CLOUD_ACCESS_BROKER_USERNAME` | `admin` |
| `fs.gs.ext.cab.pass` | `CLOUD_ACCESS_BROKER_PASS` | `admin-password` |
| `fs.gs.ext.cab.truststore.pass` | `CAB_TRUSTSTORE_PASS` | `` |
| `` | `HADOOP_SECURITY_CREDENTIAL_PROVIDER_PATH` | `` |
| `` | `` | `` |



## Example `auth-keys.xml` file.
