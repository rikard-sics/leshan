#!/bin/bash

# Build standalone Jar files for Leshan applications:
# Server, Bootstrap Server, and Client

# Fail script with error if any command fails
set -e

# Set properties files with current version
VERSION=$(cat VERSION)
echo "version=$VERSION" > leshan/leshan-server-demo/src/main/resources/version.properties
echo "version=$VERSION" > leshan/leshan-client-demo/src/main/resources/version.properties
echo "version=$VERSION" > leshan/leshan-bsserver-demo/src/main/resources/version.properties

# Build Californium (if needed)
FILE1=californium/cf-oscore/target/cf-oscore-3.11.0-SNAPSHOT.jar
FILE2=californium/californium-core/target/californium-core-3.11.0-SNAPSHOT.jar
FILE3=californium/scandium-core/target/scandium-3.11.0-SNAPSHOT.jar
FILE4=californium/element-connector/target/element-connector-3.11.0-SNAPSHOT.jar
FILE5=californium/cf-edhoc/target/cf-edhoc-3.11.0-SNAPSHOT.jar

if [[ -f "$FILE1" ]] && [[ -f "$FILE2" ]] && [[ -f "$FILE3" ]] && [[ -f "$FILE4" ]] && [[ -f "$FILE5" ]]; then
    echo "Dependencies from Californium exist."
else 
    echo "Dependencies from Californium missing. Building Californium..."
    cd californium
    mvn -DskipTests clean install
    cd ..
fi

mkdir leshan/local-maven-repo

# Prepare dependencies from Californium
mvn install:install-file -Dfile=californium/cf-oscore/target/cf-oscore-3.11.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=cf-oscore \
                         -Dversion=3.11.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=leshan/local-maven-repo

mvn install:install-file -Dfile=californium/californium-core/target/californium-core-3.11.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=californium-core \
                         -Dversion=3.11.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=leshan/local-maven-repo

mvn install:install-file -Dfile=californium/scandium-core/target/scandium-3.11.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=scandium \
                         -Dversion=3.11.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=leshan/local-maven-repo

mvn install:install-file -Dfile=californium/element-connector/target/element-connector-3.11.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=element-connector \
                         -Dversion=3.11.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=leshan/local-maven-repo

mvn install:install-file -Dfile=californium/cf-edhoc/target/cf-edhoc-3.11.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=cf-edhoc \
                         -Dversion=3.11.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=leshan/local-maven-repo

# Build standalone Leshan Jar files
cd leshan
echo "*** Building Leshan Applications ***"
mkdir -p lib

# Build jars (can be simplified?)
mvn clean package -DskipTests -Dfully.qualified.main.class="org.eclipse.leshan.client.demo.LeshanClientDemo" -DjarName="LeshanClientDemo"
mv leshan-client-demo/target/leshan-client-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar ./leshan-client-demo.jar

mvn clean package -DskipTests -Dfully.qualified.main.class="org.eclipse.leshan.server.demo.LeshanServerDemo" -DjarName="LeshanServerDemo"
mv leshan-server-demo/target/leshan-server-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar ./leshan-server-demo.jar

mvn clean package -DskipTests -Dfully.qualified.main.class="org.eclipse.leshan.server.bootstrap.demo.LeshanBootstrapServerDemo" -DjarName="LeshanBootstrapServerDemo"
mv leshan-bsserver-demo/target/leshan-bsserver-demo-2.0.0-SNAPSHOT-jar-with-dependencies.jar ./leshan-bsserver-demo.jar

rm -rf local-maven-repo

echo "Jar files containing Leshan Applications built under leshan/. Execute them with lib in the same folder."


