## Token Binding Protocol Negotiation TLS Extension support for Java 8

### Introduction
Token Binding over HTTP [[I-D.ietf-tokbind-https]] provides a mechanism
that enables HTTP servers to cryptographically bind cookies and other
security tokens to a key held by the browser or other HTTP client,
possession of which is proven on the TLS connections over
which the tokens are used.  When Token Binding is negotiated in the
TLS handshake [[I-D.ietf-tokbind-negotiation]] the client sends an
encoded Token Binding Message [[I-D.ietf-tokbind-protocol]] as a header
in each HTTP request, which proves possession of one or more private
keys held by the client.  The public portion of the keys are
represented in the Token Binding IDs of the Token Binding Message and
for each one there is a signature over some data, which includes the
exported keying material [[RFC 5705]] of the TLS connection.  An HTTP
server issuing cookies or other security tokens can associate them
with the Token Binding ID, which ensures those tokens cannot be used
successfully over a different TLS connection or by a different client
than the one to which they were issued.

This project provides an implementation of the TLS Extension for Token Binding Protocol Negotiation as well as TLS Keying Material Exporters (also TLS Extended Master Secret Extension [[RFC 7627]] in some older versions) for Java 8. An an open source library for consuming or producing Token Binding message structures, which applications do after negotiation, can be found with the [token-binding-java] project.  

### Usage 
This implementation relies on modifications of a few JDK classes in the `sun.security.ssl` package. The JVM needs to be told to use those modified classes in place of those in JSSE jar of the JRE. And your application needs to interact with the API of some of those classes, likely through reflection and dynamic method invocation. 

#### Starting the JVM 
To use the functionality of this project, the JVM needs to be started using the `-Xbootclasspath/p` option as follows:

```
java -Xbootclasspath/p:<path-to-java8-token-binding-negotiation-jar> ...
```

Where path-to-java8-token-binding-negotiation-jar is the path on the file system for this project's jar file. This prepends the jar file to the default bootstrap classpath so that its classes will be used in place of the default JRE classes. Be certain to use the jar version which corresponds to the version of the JRE being used (see [Versions](#versions) below).

##### API
A few new methods have been added to the OpenJDK implementations of `SSLEngine` and `SSLSocket` to facilitate an application doing Token Binding using the functionality provided by this project.   

##### Supported Key Parameters for Negotiation   
In order to negotiate the use of Token Binding, before handshaking begins, the list of identifiers of the supported key parameters needs to be indicated to the connection. For a client this is the list that will be offered in the Client Hello Extension. For a server this is the list of key parameter types that it is willing to successfully negotiate. In all cases the list indicates the Token Binding key parameters supported in descending order of preference. This can be accomplished by calling the following method on `SSLEngine` or `SSLSocket` before the handshaking process begins.  

```java 
public void setSupportedTokenBindingKeyParams(byte[] supportedTokenBindingKeyParams)
```   

The `supportedTokenBindingKeyParams` byte array argument is the list of supported key parameters type identifiers (i.e. from [I-D.ietf-tokbind-protocol] `rsa2048_pkcs1.5(0), rsa2048_pss(1), ecdsap256(2)`). So, for example, the following would set up an `SSLEngine` to accept or offer `ecdsap256` and `rsa2048_pkcs1.5` (in that order of preference) during the handshake.  

```java
Class<? extends SSLEngine> engineClass = engine.getClass();
Method supportedKeyParamsMethod = engineClass.getMethod("setSupportedTokenBindingKeyParams", byte[].class);
Object supported = new byte[] {2, 0};
supportedKeyParamsMethod.invoke(engine, supported);
```

Alternately, the system properties `unbearable.server.defaultSupportedKeyParams` and `unbearable.client.defaultSupportedKeyParams` may be used to indicate the supported key parameters type identifiers for all connections  when acting as the server or client respectively. The value is a comma seperated list of key parameters type identifiers. For example, adding the following argument when starting the JVM would say that TLS connections as the server will successfully negotiate Token Binding with `ecdsap256(2)` or `rsa2048_pkcs1.5(0)` when offered by the client.    

```
  -Dunbearable.server.defaultSupportedKeyParams=2,0
```

##### After Negotiation 
If the use of the Token Binding is successfully negotiated with HTTP, the client includes an encoded token binding message in each request via the `Sec-Token-Binding` header and the server validates the message. In order to produce or consume a Token Binding message, an application needs to know what key parameters type was negotiated and get the exported keying material (EKM) from the TLS connection.  That data can be obtained using the following methods on `SSLEngine` or `SSLSocket` where `getNegotiatedTokenBindingKeyParams()` will give the the identifier of the negotiated key parameters (or `null`, if Token Binding was not negotiated) and `exportKeyingMaterial("EXPORTER-Token-Binding", 32)` will return the EKM.


```java 
public Byte getNegotiatedTokenBindingKeyParams()

public byte[] exportKeyingMaterial(String label, int length)
```

The following, for example, could be used to access the negotiated key parameters type and the EKM from an `SSLEngine`.

```java
Class<? extends SSLEngine> engineClass = engine.getClass();
Method tbKeyParamsMethod = engineClass.getMethod("getNegotiatedTokenBindingKeyParams");
Method ekmMethod = engineClass.getMethod("exportKeyingMaterial", String.class, int.class);
Byte negotiatedKeyParamsId = (Byte) tbKeyParamsMethod.invoke(object);
byte[] ekm = (byte[]) ekmMethod.invoke(object, "EXPORTER-Token-Binding", 32);

```

With the EKM and the negotiated key parameters type, a library like [token-binding-java] can be used to consume or create Token Binding messages. 

### <a name="versions"></a> Versions
The Token Binding negotiation implementation relies on modifications to a few OpenJDK classes so needs to be updated to stay in sync when there are changes to those OpenJDK classes in a Java update. As such, the java8-token-binding-negotiation jar version matching the JRE version needs to be used. The following provides the version mappings.

| Java 8 Version  | java8-token-binding-negotiation Version
| ------------- |-------------
| 1.8.0_162 | [1.0.0.v3]
| 1.8.0_161 | [1.0.0.v2]
| 1.8.0_152 | [1.0.0.v1]
| 1.8.0_151 | [1.0.0.v1]
| 1.8.0_144 | [1.0.0.v1]
| 1.8.0_141 | [1.0.0.v1]
| 1.8.0_131 & prior | unsupported

### License
The modified OpenJDK classes are released under the same GPLv2 + Classpath Exception license of OpenJDK.

[1.0.0.v3]:https://github.com/pingidentity/java8-token-binding-negotiation/releases/tag/java8-token-binding-negotiation-1.0.0.v3
[1.0.0.v2]:https://github.com/pingidentity/java8-token-binding-negotiation/releases/tag/java8-token-binding-negotiation-1.0.0.v2
[1.0.0.v1]:https://github.com/pingidentity/java8-token-binding-negotiation/releases/tag/java8-token-binding-negotiation-1.0.0.v1

[token-binding-java]:https://github.com/pingidentity/token-binding-java

[I-D.ietf-tokbind-https]:https://tools.ietf.org/html/draft-ietf-tokbind-https
[I-D.ietf-tokbind-protocol]:https://tools.ietf.org/html/draft-ietf-tokbind-protocol
[I-D.ietf-tokbind-negotiation]:https://tools.ietf.org/html/draft-ietf-tokbind-negotiation

[RFC 5705]:https://tools.ietf.org/html/rfc5705
[RFC 7627]:https://tools.ietf.org/html/rfc7627