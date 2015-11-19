
package com.tactico.guacamole.auth.aws.user;

import com.google.inject.Inject;
import java.util.Map;
import org.glyptodon.guacamole.net.auth.AbstractAuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.Credentials;

/**
 * A Tactico-specific implementation of AuthenticatedUser, associating a
 * particular set of credentials with the AWS authentication provider.
 *
 * @author Michael Jumper
 */
public class AuthenticatedUser extends AbstractAuthenticatedUser {

    /**
     * Reference to the authentication provider associated with this
     * authenticated user.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * The credentials provided when this user was authenticated.
     */
    private Credentials credentials;

    /**
     * All connections to which this user has access.
     */
    private Map<String, Connection> connections;

    /**
     * Initializes this AuthenticatedUser using the given credentials and map
     * of connections.
     *
     * @param credentials
     *     The credentials provided when this user was authenticated.
     *
     * @param connections
     *     The connections that this user should have access to.
     */
    public void init(Credentials credentials, Map<String, Connection> connections) {
        this.credentials = credentials;
        this.connections = connections;
        setIdentifier(credentials.getUsername());
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * Returns a map containing all connections to which this user has access.
     * Each connection is stored within the map under its identifier.
     *
     * @return
     *     A map of all connections to which this user has access.
     */
    public Map<String, Connection> getConnections() {
        return connections;
    }

}
