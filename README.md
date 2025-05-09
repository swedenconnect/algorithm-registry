![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# algorithm-registry

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://img.shields.io/maven-central/v/se.swedenconnect.security/algorithm-registry.svg)](https://central.sonatype.com/artifact/se.swedenconnect.security/algorithm-registry)

Java library for a central algorithm registry.

---

## About

This repository contains a simple algorithm registry that can be used for keeping track
of supported and blacklisted algorithms in an application. 

The algorithm registry can either be configured and instantiated as a bean, or a static
singleton can be used, see [AlgorithmRegistrySingleton](https://github.com/swedenconnect/algorithm-registry/blob/main/src/main/java/se/swedenconnect/security/algorithms/AlgorithmRegistrySingleton.java).

A static implementation, [StaticAlgorithmRegistry](https://github.com/swedenconnect/algorithm-registry/blob/main/src/main/java/se/swedenconnect/security/algorithms/impl/StaticAlgorithmRegistry.java), with defaults borrowed from the [Apache xmlsec](https://santuario.apache.org) library is also provided.


## Maven

The `se.swedenconnect.security:algorithm-registry` artifact is published to Maven central. In order to include a dependency to it, include the following in your POM:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>algorithm-registry</artifactId>
  <version>${alg-reg.version}</version>
</dependency>
```

## API Documentation

Go to https://docs.swedenconnect.se/algorithm-registry for the Java API documentation for the module.

---

Copyright &copy; 2022-2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
