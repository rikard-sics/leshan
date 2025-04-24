#!/bin/bash

# Set up the code for development work in Eclipse
# Note: Do not commit the local pom.xml files used when developing

cp leshan/leshan-server-redis/pom.dev leshan/leshan-server-redis/pom.xml
cp leshan/leshan-server-core/pom.dev leshan/leshan-server-core/pom.xml
cp leshan/pom.dev leshan/pom.xml
cp leshan/leshan-integration-tests/pom.dev leshan/leshan-integration-tests/pom.xml
cp leshan/leshan-server-cf/pom.dev leshan/leshan-server-cf/pom.xml
cp leshan/leshan-bsserver-demo/pom.dev leshan/leshan-bsserver-demo/pom.xml
cp leshan/leshan-client-core/pom.dev leshan/leshan-client-core/pom.xml
cp leshan/leshan-client-demo/pom.dev leshan/leshan-client-demo/pom.xml
cp leshan/leshan-client-cf/pom.dev leshan/leshan-client-cf/pom.xml
cp leshan/leshan-core/pom.dev leshan/leshan-core/pom.xml
cp leshan/leshan-core-cf/pom.dev leshan/leshan-core-cf/pom.xml
cp leshan/leshan-server-demo/pom.dev leshan/leshan-server-demo/pom.xml

cd californium
mvn eclipse:eclipse

cd ..
cd leshan
mvn eclipse:eclipse
cd ..
