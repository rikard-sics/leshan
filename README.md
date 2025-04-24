# Repository contents

Code integrating Californium with EDHOC support together with the Leshan LwM2M framework

## Pre-compiled Jar files

Ready-made Jar files can be found and downloaded under the Releases-section of the repository

## Setting up the project for development

(Skip if development or changing the code is not desired)

1. Run "mvn eclipse:eclipse" in the leshan and californium subfolders  
(Maven version 3.9.9 or higher is recommended)

3. Start Eclipse, then import the following projects:
- californium
- leshan

4. To all the individual projects in leshan, add the following folders to the build path:
- californium-core
- cf-oscore
- cf-edhoc
- element-connector
- scandium

To add dependencies:  
Right click project->Properties->Java Build Path->Projects->Add...

4. Change the following projects to use Java 11:
- leshan-client-demo
- leshan-server-demo
- leshan-bsserver-demo  
(In some situations this may be needed for all individual Leshan projects)

To change Java version:  
Right click project->Properties->Java Build Path->Libraries->Edit...  
Change the JRE System Library to be minimum Java 11.

## Starting the applications

In general start the applications using  
_java -jar X.jar_

Bootstrap Server with  
-lh 127.0.0.3 -slh 127.0.0.3 -wh 127.0.0.3

Leshan Server with  
-lh 127.0.0.2 -slh 127.0.0.2 -wh 127.0.0.2

Leshan Client with  
-b -n Test -msec AAAA -sid BB -rid CC -u 127.0.0.3

## Configuration in applications

Navigate to 127.0.0.2:8080 and 127.0.0.3:8080 in a browser.

Set the EDHOC config custom or using the pre-defined configs by pressing the special buttons.
