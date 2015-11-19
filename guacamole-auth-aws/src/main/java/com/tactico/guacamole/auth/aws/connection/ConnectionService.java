
package com.tactico.guacamole.auth.aws.connection;

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Filter;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.Tag;
import com.google.inject.Inject;
import com.tactico.guacamole.auth.aws.AWSAuthenticationProvider;
import com.tactico.guacamole.auth.aws.AWSGuacamoleProperties;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for querying the connections available to a particular Guacamole
 * user according to AWS.
 *
 * @author Michael Jumper
 */
public class ConnectionService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(ConnectionService.class);

    /**
     * The key of the Amazon EC2 instance tag used to store the name of the
     * instance.
     */
    private static final String INSTANCE_TAG_NAME = "Name";

    /**
     * The prefix which will occur at the beginning of any Amazon EC2 instance
     * tag used to store a GuacamoleConfiguration parameter, where the name of
     * that parameter is the remainder of the key.
     */
    private static final String INSTANCE_TAG_CONFIG_PARAMETER_PREFIX = "guac_";

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * Given an Amazon EC2 instance, generates an appropriate identifier for
     * the Guacamole connection to that instance. If the instance has an
     * associated name, this will be "RDP NAME", where NAME is the name of the
     * instance. If no name is associated with the instance, the identifier
     * will be simply the private IP address of the instance.
     *
     * @param inst
     *     The Amazon EC2 instance for which an identifier should be
     *     generated.
     *
     * @return
     *     An appropriate Guacamole connection identifier generated
     *     specifically for the given Amazon EC2 instance.
     */
    private String generateIdentifier(Instance inst) {

        // Use the instance name, if it exists
        for (Tag tag: inst.getTags()) {
            if (tag.getKey().equals(INSTANCE_TAG_NAME))
                return tag.getValue();
        }

        // Otherwise, default to IP address
        return inst.getPrivateIpAddress();

    }

    /**
     * Given an Amazon EC2 instance, generates a GuacamoleConfiguration which
     * connects to that instance. An appropriate configuration will be
     * generated using default connection parameter values, but additional
     * parameters may be provided using instance tags of the form "guac_NAME",
     * where NAME is the name of the connection parameter being set. For a
     * full list of available connection parameters, see:
     *
     * http://guac-dev.org/doc/gug/configuring-guacamole.html#connection-configuration
     *
     * @param inst
     *     The Amazon EC2 instance that the generated GuacamoleConfiguration
     *     should connect to.
     *
     * @return
     *     A GuacamoleConfiguration which connects to the given Amazon EC2
     *     instance.
     */
    private GuacamoleConfiguration generateConfiguration(Instance inst) {

        // Create initial default RDP config
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter("hostname", inst.getPrivateIpAddress());
        config.setParameter("port", "3389");

        // Add any GuacamoleConfiguration parameters stored within tags
        for (Tag tag: inst.getTags()) {

            String key = tag.getKey();

            // If the tag contains GuacamoleConfiguration parameter data, add
            // that data as a parameter within the new GuacamoleConfiguration
            if (key.startsWith(INSTANCE_TAG_CONFIG_PARAMETER_PREFIX)) {
                config.setParameter(
                    key.substring(INSTANCE_TAG_CONFIG_PARAMETER_PREFIX.length()),
                    tag.getValue()
                );
            }

        }

        return config;

    }

    /**
     * Given a set of credentials associated with a particular user, returns a
     * mapping of connection identifiers to corresponding connections for which
     * that user is authorized. If the given credentials are not valid, or the
     * user is not authorized for any connections , null is returned.
     *
     * @param credentials
     *     The credentials to use when authenticating the given user.
     *
     * @return
     *     A mapping of connection identifiers to corresponding connections, or
     *     null if authentication fails or the user is not authorized for any
     *     connections.
     * @throws GuacamoleException 
     */
    public Map<String, Connection> getConnections(Credentials credentials) throws GuacamoleException {

    	logger.info("Authenticate");
        // Flag shared across all returned connections, indicating whether
        // those connections are invalid (no longer usable)
        AtomicBoolean invalid = new AtomicBoolean();

        // Initially assume the user is unauthorized
        Map<String, Connection> connections = null;

        
        // Get username and password
        String username = credentials.getUsername();
        String password = credentials.getPassword();

    	String encryptionKey = environment.getProperty(AWSGuacamoleProperties.ENCRYPTION_KEY);
    	String encrypted = null;
        try
        {
        	for (Cookie cookie : credentials.getRequest().getCookies())
        	{
        		if (cookie.getName().equals("GUAC_UP"))
        			encrypted = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
        	}
        	if (username == null && password == null && encrypted != null && encryptionKey != null)
        	{
                logger.info("Try decrypt " + encrypted);
        		String iv 	= "0000000000000000";
                IvParameterSpec initialVector = new IvParameterSpec(iv.getBytes());
                SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
	        	String encryptionAlgorithm = "AES/CBC/PKCS5Padding";

        	
	        	Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
	            cipher.init(Cipher.DECRYPT_MODE, secretKey, initialVector);
	            String[] decrypted = new String(cipher.doFinal(Base64.decodeBase64(encrypted))).split(":");
                logger.info("decrypted " + decrypted);
	            credentials.setUsername(username = decrypted[0]);
	            credentials.setPassword(password = decrypted[1]);
        	}            
        }
        catch (Exception e)
        {
            logger.error("Problem with encryption. " + e);
        }
        // If no credentials provided, definitely not authorized
        if (username == null || password == null)
            return null;

        // Create new EC2 client
        AmazonEC2 ec2 = new AmazonEC2Client();

        // Set endpoint, if specified
        try {
            String endpoint = environment.getProperty(AWSGuacamoleProperties.AWS_ENDPOINT);
            ec2.setEndpoint(endpoint);
        }

        // Log failure to set endpoint
        catch (IllegalArgumentException e) {
            logger.error("XX Invalid AWS endpoint specified. Using default.");
        }
        // Log failure to parse property
        catch (GuacamoleException e) {
            logger.error("Unable to parse AWS endpoint. Using AWS SDK default.");
            logger.debug("Error parsing AWS endpoint.", e);
        }

        try {
        	String adminUsername = environment.getProperty(AWSGuacamoleProperties.ADMIN_USER);
        	String adminPassword = environment.getProperty(AWSGuacamoleProperties.ADMIN_PASSWORD);
        	DescribeInstancesRequest describeRequest = new DescribeInstancesRequest();
        	describeRequest.withFilters(new Filter("instance-state-code", Arrays.asList(new String[] {"0", "16"})));
        	if (adminUsername.equals(credentials.getUsername()) && adminPassword.equals(credentials.getPassword()))
        	{
        		logger.info("AWSAuthenticationProvider Detect Admin");
                if (connections == null)
                    connections = new HashMap<String, Connection>();

                DescribeInstancesResult instanceDescriptions = ec2.describeInstances(describeRequest);
    			for (Reservation res:instanceDescriptions.getReservations())
    				for (Instance inst: res.getInstances()){
//    					if (inst.getPlatform() != null && (inst.getPlatform().equals("windows") || inst.getPlatform().equals("ubuntu")))
    	                String identifier = "RDP " + generateIdentifier(inst);
    	                GuacamoleConfiguration config = generateConfiguration(inst);
  					  	config.setProtocol("rdp");
  					  	config.setParameter("hostname", inst.getPrivateIpAddress());
  					  	config.setParameter("port", "3389");
    	                Connection connection = new SessionInvalidatingConnection(identifier, config, invalid);
    	                connection.setParentIdentifier(AWSAuthenticationProvider.ROOT_CONNECTION_GROUP);
    	                connections.put(identifier, connection);
    	                logger.info("Added connection \"{}\" for user \"{}\": {}",
    	                        identifier, username, config.getParameters().toString());

    	                identifier = "VNC " + generateIdentifier(inst);
    					config = new GuacamoleConfiguration();
    					config.setProtocol("vnc");
    					config.setParameter("hostname", inst.getPrivateIpAddress());
    					config.setParameter("port", "5900");
    	                connection = new SessionInvalidatingConnection(identifier, config, invalid);
    	                connection.setParentIdentifier(AWSAuthenticationProvider.ROOT_CONNECTION_GROUP);
    	                connections.put(identifier, connection);
    	                logger.info("Added connection \"{}\" for user \"{}\": {}",
    	                        identifier, username, config.getParameters().toString());
    					  
    	                identifier = "SSH " + generateIdentifier(inst);
    					config = new GuacamoleConfiguration();
    					config.setProtocol("ssh");
    					config.setParameter("hostname", inst.getPrivateIpAddress());
    					config.setParameter("port", "22");
    						  
    	                connection = new SessionInvalidatingConnection(identifier, config, invalid);
    	                connection.setParentIdentifier(AWSAuthenticationProvider.ROOT_CONNECTION_GROUP);
    	                connections.put(identifier, connection);
    	                logger.info("Added connection \"{}\" for user \"{}\": {}",
    	                        identifier, username, config.getParameters().toString());
    				}
    	        return connections;
    		}
        	
        }

        // Log failure to set endpoint
        catch (IllegalArgumentException e) {
            logger.error("Invalid AWS admin credentials.");
        }
        // Log failure to parse property
        catch (GuacamoleException e) {
            logger.error("Invalid AWS admin credentials.");
        }

        // Pull Amazon EC2 instances for which the user is authorized, if any
        DescribeInstancesResult instanceDescriptions = ec2.describeInstances(
            new DescribeInstancesRequest().withFilters(
                new Filter(
                    "tag:guac",
                    Collections.singletonList(username + ":" + password)
                )
            )
        );

        // Add one connection for each available instance
        for (Reservation res : instanceDescriptions.getReservations()) {
            for (Instance inst : res.getInstances()){

                // Create map if it does not yet exist
                if (connections == null)
                    connections = new HashMap<String, Connection>();

                // Generate identifier and GuacamoleConfiguration from instance data
                String identifier = generateIdentifier(inst);
                GuacamoleConfiguration config = generateConfiguration(inst);

                // Create connection within root group
                Connection connection = new SessionInvalidatingConnection(identifier, config, invalid);
                connection.setParentIdentifier(AWSAuthenticationProvider.ROOT_CONNECTION_GROUP);

                // Add identifier/connection pair
                connections.put(identifier, connection);

                logger.info("Added connection \"{}\" for user \"{}\": {}",
                        identifier, username, config.getParameters().toString());

            }
        }

        if (connections == null && encrypted != null)
        	throw new GuacamoleException("Reservation No Longer Valid");
        
        // Return authorized connections, which may be null if the user is not
        // authorized
        return connections;

    }

}
