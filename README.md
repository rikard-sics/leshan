# Repository contents

Code integrating Californium with EDHOC support together with the Leshan LwM2M framework

## Pre-compiled Jar files

Ready-made Jar files can be found and downloaded under the Releases-section of the repository

## Setting up the project for development

(Skip if development or changing the code is not desired)

1. Run the script "setup-dev.sh"  
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
`-lh 127.0.0.3 -slh 127.0.0.3 -wh 127.0.0.3`

Leshan Server with  
`-lh 127.0.0.2 -slh 127.0.0.2 -wh 127.0.0.2`

Leshan Client OSCORE bootstrap with  
`-b -n Test -msec AAAA -sid BB -rid CC -u 127.0.0.3`

Leshan Client EDHOC bootstrap with  
`-n Test -b -u localhost:5683 -eckid 2b -ecpub a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8 -ecpriv fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b -ecpkid 09 -ecppub a20262303908a101a5010202410920012158206f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f225820c8d33274c71c9b3ee57d842bbf2238b8283cb410eca216fb72a78ea7a870f800 -ecpm 3 -ecpcs 2`    

## Overriding EDHOC config received from the Bootstrap Server

It is possible to specify the Client Key Identifier, Client Public Key and (Client) Private Key to be used by the Client when running EDHOC with the Device Manager as command line arguments. This configuration will take precedence over any of the same parameters received from the Bootstap Server. The arguments are the following:

-eckid: Client Key Identifier  
-ecpub: Client Public Key  
-ecpriv: Client Private Key  

Example Client invocation:  
`-b -n Test -msec AAAA -sid BB -rid CC -eckid 2b -ecpub a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8 -ecpriv fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b -u 127.0.0.3`

## Configuration in applications

Navigate to 127.0.0.2:8080 and 127.0.0.3:8080 in a browser.

Set the EDHOC config custom or using the pre-defined configs by pressing the special buttons. Using the fill buttons in the GUI configuration for using EDHOC between the Client and Device Manager and/or the Bootstrap Server can be set up.  

## Possible isuses with newer Java versions
  
If the following error is encountered:  
*java.lang.reflect.InaccessibleObjectException: Unable to make private java.util.Collections$EmptyMap() accessible: module java.base does not "opens java.util" to unnamed module @25c3d16*  
  
Ensure that reflection is properly enabled (it was limited in later Java versions). To do this add the following as argument to the *java* command (before *-jar*):  
*--add-opens java.base/java.util=ALL-UNNAMED*

## Note on persistence of configurations

The following describes what configuration is persisted with regards to EDHOC and OSCORE across reboots for the Client, Bootstrap Server and Management Server.

- Client: The Client needs to be restarted with the same cmd line arguments or configuration file as input.
- Bootstrap Server: All configuration is persisted.
- Management Server: All configuration is persisted.
