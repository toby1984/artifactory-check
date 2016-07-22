# artifactory-check
This is a tiny, multi-thread Java program I created to quickly check the integrity of artifacts in a Artifactory system export. I don't know if this is even necessary (maybe the export feature in Artifactory already performs such a check upon export) but I couldn't get any response from their mailing-list.

=Requirements=

Maven 3.x (building & running)
JDK 1.8 (running)

=Building=

Just run

```mvn clean package```

to create a self-executable JAR in target/artifactorycheck.jar

=Running=

Just do

```java -jar target/artifactorycheck.jar [-t <thread count>] [-v] <export folder>```

By default the thread count is set to be 10 threads. You can pass the '-v' option to get *very* verbose output. By default just  the broken artifacts will be printed plus a short summary at the end.
