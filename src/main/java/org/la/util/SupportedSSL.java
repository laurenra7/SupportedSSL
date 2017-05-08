package org.la.util;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;

/**
 * Created by laurenra on 5/31/16.
 */
public class SupportedSSL {

    private static boolean modeVerbose;

    public static void main(String[] args) throws Exception {

        int exitStatus = 0;
        modeVerbose = false;

        // Build command line options
        Options clOptions = new Options();
        clOptions.addOption(Option.builder("h")
                .longOpt("help")
                .desc("Show this help")
                .build());
        clOptions.addOption(Option.builder("o")
                .longOpt("output")
                .desc("output file")
                .hasArg()
                .argName("filename")
                .build());
        clOptions.addOption(Option.builder("p")
                .longOpt("protocols")
                .desc("check if protocol(s) are available (comma-separated list)")
                .hasArg()
                .argName("protocols")
                .build());
        clOptions.addOption(Option.builder("c")
                .longOpt("ciphers")
                .desc("check if cipher(s) are available (comma-separated list)")
                .hasArg()
                .argName("ciphers")
                .build());
        clOptions.addOption(Option.builder("v")
                .longOpt("verbose")
                .desc("show processing messages")
                .build());

        exitStatus = processCommandLine(args, clOptions);

        System.exit(exitStatus);
    }


    private static int processCommandLine(String[] args, Options clOptions) {
        int executeStatus = 0;
        boolean optionsProcessed = false;

        CommandLineParser clParser = new DefaultParser();


        try {
            CommandLine line = clParser.parse(clOptions, args);

            if (line.hasOption("help")) {
                showCommandHelp(clOptions);
            }
            else {
                if (line.hasOption("verbose")) {
                    modeVerbose = true;
                }

                if (line.hasOption("protocols")) {
                    optionsProcessed = true;
                    List<String> protocolsList = Arrays.asList(line.getOptionValue("protocols").split("\\s*,\\s*"));
                    if (modeVerbose) {
                        System.out.println("check protocols: " + protocolsList);
                    }
                    System.out.println("Valid protocols:\t" + validProtocols(protocolsList));
                }

                if (line.hasOption("ciphers")) {
                    optionsProcessed = true;
                    List<String> ciphersList = Arrays.asList(line.getOptionValue("ciphers").split("\\s*,\\s*"));
                    if (modeVerbose) {
                        System.out.println("check cipher suites: " + ciphersList);
                    }

                    List<String> protocolsList = null;
                    if (line.hasOption("protocols")) {
                        protocolsList = Arrays.asList(line.getOptionValue("protocols").split("\\s*,\\s*"));
                    }
                    System.out.println(validCipherSuites(protocolsList, ciphersList));
                }

                // Remaining command line arguments, if any
                if (!optionsProcessed) {
                    String supportedStuff = clientSupportedProtocolsAndCiphers();
                    if (line.hasOption("output")) {
                        executeStatus = writeStringToFile(line.getOptionValue("output"), supportedStuff);
                    }
                    else {
                        System.out.print(supportedStuff);
                    }
                }
            }
        }
        catch (ParseException e) {
            System.err.println("Command line parsing failed. Error: " + e.getMessage() + "\n");
            showCommandHelp(clOptions);
            executeStatus = 1;
        }

        return executeStatus;
    }


    private static String httpComponentsGet(String url) {
        String result = "";

        if (modeVerbose) {
            System.out.println("Http GET from URL: " + url);
        }

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader("Accept","text/plain");
        httpGet.addHeader("Accept-Charset", "utf-8");

        try {
            HttpResponse httpResponse = httpClient.execute(httpGet);
            int responseCode = httpResponse.getStatusLine().getStatusCode();

            if (modeVerbose) {
                result = result + "HTTP response code: " + httpResponse.getStatusLine().getStatusCode() + "\n";
            }

            if (responseCode == HttpStatus.SC_OK) {
                if (modeVerbose) {
                    result = result + "---------- Request Header ----------\n";
                    org.apache.http.Header[] requestHeaders = httpGet.getAllHeaders();
                    for (org.apache.http.Header reqHeader : requestHeaders) {
                        result = result + reqHeader.getName() + ": " + reqHeader.getValue() + "\n";
                    }

                    result = result + "---------- Response Header ----------\n";
                    org.apache.http.Header[] responseHeaders = httpResponse.getAllHeaders();
                    for (org.apache.http.Header respHeader : responseHeaders) {
                        result = result + respHeader.getName() + ": " + respHeader.getValue() + "\n";
                    }
                }

                try (BufferedReader bufferedReader =
                             new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()))) {

                    StringBuffer responseBody = new StringBuffer();
                    String line = "";
                    while ((line = bufferedReader.readLine()) != null) {
                        responseBody.append(line);
                    }

                    if (modeVerbose) {
                        result = result + "---------- Response Body ----------\n";
                    }

                    result = result + responseBody;
                }

            }
            else {
                System.out.println("Problem with request. HTTP status code: " + responseCode);
            }

        }
        catch (IOException e) {
            System.out.println("Error fetching request: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }


    private static String clientSupportedProtocolsAndCiphers() {
        String result = "Java client version:\t" + System.getProperty("java.version") + "\n";

        ArrayList<String> supportedProtocols = clientSupportedProtocols();
        result = result + "Supported protocols:\t";
        for (String protocol : supportedProtocols) {
            result = result + protocol + ", ";
        }

        result = result.replaceAll(", $", "") + "\n";

        for (String protocol : supportedProtocols) {
            result = result + "\nSupported cipher suites for protocol " + protocol + "\n";
            for (String cipherSuite : clientSupportedCipherSuites(protocol)) {
                result = result + cipherSuite + "\n";
            }
        }

        return result;
    }


    private static ArrayList<String> clientSupportedProtocols() {
        // Auto-detect protocols
        ArrayList<String> protocols = new ArrayList<String>();

        // TODO: Allow the specification of a specific provider (or set?)
        for(Provider provider : Security.getProviders())
        {
            for(Object prop : provider.keySet())
            {
                String key = (String)prop;
                if(key.startsWith("SSLContext.")
                        && !key.equals("SSLContext.Default")
                        && key.matches(".*[0-9].*"))
                    protocols.add(key.substring("SSLContext.".length()));
                else if(key.startsWith("Alg.Alias.SSLContext.")
                        && key.matches(".*[0-9].*"))
                    protocols.add(key.substring("Alg.Alias.SSLContext.".length()));
            }
        }
        Collections.sort(protocols); // Should give us a nice sort-order by default
        ArrayList<String> supportedProtocols = protocols;

        return protocols;
    }


    private static String validProtocols(List<String> protocols) {
        String result = "";

        ArrayList<String> validProtocols = new ArrayList<String>(protocols);
        validProtocols.retainAll(clientSupportedProtocols());

        for (String validProtocol : validProtocols) {
            result = result + validProtocol + ", ";
        }

        result = result.replaceAll(", $", "");

        return result;
    }


    private static List<String> clientSupportedCipherSuites(String protocol) {
        List<String> supportedCipherSuites = new ArrayList<String>();
        SSLContext sslContext;

        try {
            sslContext = SSLContext.getInstance(protocol);
            sslContext.init(null, null, new SecureRandom());

            supportedCipherSuites = Arrays.asList(sslContext.getSocketFactory().getSupportedCipherSuites());
            Collections.sort(supportedCipherSuites);
        }
        catch (KeyManagementException e) {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(protocol + " is not supported by client.");
            if(modeVerbose) {
                System.out.print(e);
            }
        }

        return supportedCipherSuites;
    }


    private static String validCipherSuites(List<String> protocols, List<String> cipherSuites) {
        String result = "";
        ArrayList<String> supportedProtocols;

        if (protocols == null) {
            supportedProtocols = clientSupportedProtocols();
        }
        else {
            supportedProtocols = new ArrayList<String>(protocols);
            supportedProtocols.retainAll(clientSupportedProtocols());
        }

        for (String protocol : supportedProtocols) {
            result = result + "\nSupported cipher suites for protocol " + protocol + "\n";
            ArrayList<String> supportedCipherSuites = new ArrayList<String>(clientSupportedCipherSuites(protocol));
            supportedCipherSuites.retainAll(new HashSet<String>(cipherSuites));
            for (String cipherSuite : supportedCipherSuites) {
                result = result + cipherSuite + "\n";
            }
        }

        return result;
    }


    private static int writeStringToFile(String outputFilename, String outputString) {
        int status = 0;
        BufferedWriter bufferedWriter = null;
        FileWriter fileWriter = null;

        if (modeVerbose) {
            System.out.println("Output file: " + outputFilename);
        }

        try {
            fileWriter = new FileWriter(outputFilename);
            bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write(outputString);

        }
        catch (IOException e) {
            System.out.println("Problem writing to file. Error: " + e.getMessage());
            status = 1;
        }
        finally {
            try {
                if (bufferedWriter != null) {
                    bufferedWriter.close();
                }
                if (fileWriter != null) {
                    fileWriter.close();
                }
            }
            catch (IOException ioErr) {
                System.out.println("Problem closing file. Error: " + ioErr.getMessage());
                status = 1;
            }
        }

        return status;
    }


    private static void showCommandHelp(Options options) {
        String commandHelpHeader = "\nShow supported SSL/TLS protocols and ciphers for Java client.\n\n";
        String commandHelpFooter = "\nExamples:\n\n" +
                "  java -jar SupportedSSL.jar -p SSLv3,TLSv1.2\n\n" +
                "  java -jar SupportedSSL.jar -c TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256\n\n" +
                "  java -jar SupportedSSL.jar -o TLS_RSA_WITH_AES_128_GCM_SHA256\n\n" +
                "  java -jar SupportedSSL.jar -v TLS_RSA_WITH_AES_128_GCM_SHA256\n\n";

        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp(101,"java -jar SupportedSSL.jar", commandHelpHeader, options, commandHelpFooter, true);
    }


}
