![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# algorithm-registry

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Java library for using a central algorithm registry.

---

## About

This repository contains a simple algorithm registry that can be used for keeping track
of supported and blacklisted algorithms in an application. 

The algorithm registry can either be configured and instantiated as a bean, or a static
singleton can be used. See XXX.


## Maven

The `se.swedenconnect.security:algorithm-registry` artefact is published to Maven central. In order to include a dependency to it, include the following in your POM:

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

Copyright &copy; 2022, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
