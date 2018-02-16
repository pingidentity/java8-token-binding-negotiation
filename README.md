## Token Binding Protocol Negotiation TLS Extension support for Java 8


### Versions
The Token Binding negotiation implementation relies on modifications to a few OpenJDK classes and needs to be updated to stay in sync when there are changes to those OpenJDK classes in a Java update. As such, the java8-token-binding-negotiation jar version matching the JRE version needs to be used. The following provides the version mappings.

| Java Version  | java8-token-binding-negotiation Version
| ------------- |-------------
| 1.8.0_161 | [1.0.0.v2]
| 1.8.0_152 | [1.0.0.v1]
| 1.8.0_151 | [1.0.0.v1]
| 1.8.0_144 | [1.0.0.v1]
| 1.8.0_141 | [1.0.0.v1]
| 1.8.0_131 & prior | unsupported

[1.0.0.v2]:https://github.com/pingidentity/java8-token-binding-negotiation/releases/tag/1.0.0.v2

[1.0.0.v1]:https://github.com/pingidentity/java8-token-binding-negotiation/releases/tag/java8-token-binding-negotiation-1.0.0.v1
