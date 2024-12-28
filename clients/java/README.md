# Tiny java client project for testing purpose

This is JAVA application to consume specific topic to test kafka connectivity using TLS with jks files.

1. you must add kafka-client.jks files in this folder to run it properly.
2. you must change the props consumer configuration such as, truststore/keystore password
3. you must change broker hostname
4. you must change topic name to be subcribed

## HOW TO RUN

Use Maven (mvn) java tool to build and run it

Folder structure


```bash
.
├── README.md
├── pom.xml
└── src
    └── main
        └── java
            └── com
                └── example
                    └── KafkaSSLConsumer.java
```

* Build Project

```bash
mvn exec:java -Dexec.mainClass="com.example.KafkaSSLConsumer"
```

