
package com.tactico.guacamole.auth.aws;

import org.glyptodon.guacamole.properties.StringGuacamoleProperty;


/**
 * Provides properties required for use of the LDAP authentication provider.
 * These properties will be read from guacamole.properties when the LDAP
 * authentication provider is used.
 *
 * @author Michael Jumper
 */
public class AWSGuacamoleProperties {

    /**
     * This class should not be instantiated.
     */
    private AWSGuacamoleProperties() {}

    /**
     * The hostname of the AWS endpoint to query for EC2 instances. If omitted,
     * the AWS SDK's default of "ec2.us-east-1.amazonaws.com" will be used.
     */
    public static final StringGuacamoleProperty AWS_ENDPOINT = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "aws-endpoint"; }

    };

    /**
     * The administrator ussername
     */
    public static final StringGuacamoleProperty ADMIN_USER = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "admin-user"; }

    };

    /**
     * The Administrator password
     */
    public static final StringGuacamoleProperty ADMIN_PASSWORD = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "admin-password"; }

    };

    /**
     * The administrator ussername
     */
    public static final StringGuacamoleProperty ENCRYPTION_KEY = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "encryption-key"; }

    };

}
