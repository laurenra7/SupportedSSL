# SupportedSSL
Show supported HTTPS protocols (SSL, TLS) and their associated cipher suites for the Java client to help with troubleshooting HTTPS issues. Running it with no options will show all the default protocols supported and their associated cipher suites.

When using the -c or -p options to check multiple cipher suites or protocols, use a comma to separate them (but no spaces).

### Build

Build with [Maven](https://maven.apache.org/).

```
mvn clean install
```

Produces an executable .jar file

```
/target/SupportedSSL.jar
```


### Run

```
java -jar SupportedSSL.jar
```


### Options

```
usage: java -jar SupportedSSL.jar [-c <ciphers>] [-h] [-o <filename>] [-p <protocols>] [-v]

Show supported SSL/TLS protocols and ciphers for Java client.

 -c,--ciphers <ciphers>       check if cipher(s) are available (comma-separated list)
 -h,--help                    Show this help
 -o,--output <filename>       output file
 -p,--protocols <protocols>   check if protocol(s) are available (comma-separated list)
 -v,--verbose                 show processing messages

Examples:

  java -jar SupportedSSL.jar -p SSLv3,TLSv1.2

  java -jar SupportedSSL.jar -c TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256

  java -jar SupportedSSL.jar -o TLS_RSA_WITH_AES_128_GCM_SHA256

  java -jar SupportedSSL.jar -v TLS_RSA_WITH_AES_128_GCM_SHA256
```
