
package com.tactico.guacamole.auth.aws;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.tactico.guacamole.auth.aws.connection.ConnectionService;
import com.tactico.guacamole.auth.aws.user.AuthenticatedUser;
import com.tactico.guacamole.auth.aws.user.UserContext;
import java.util.Map;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.credentials.CredentialsInfo;
import org.glyptodon.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;

/**
 * Service providing convenience functions for the AWS AuthenticationProvider
 * implementation.
 *
 * @author Michael Jumper
 */
public class AuthenticationProviderService {

    /**
     * Provider for AuthenticatedUser objects.
     */
    @Inject
    private Provider<AuthenticatedUser> authenticatedUserProvider;

    /**
     * Service which provides connections to AWS instances.
     */
    @Inject
    private ConnectionService connectionService;

    /**
     * Provider for UserContext objects.
     */
    @Inject
    private Provider<UserContext> userContextProvider;

    /**
     * Returns an AuthenticatedUser representing the user authenticated by the
     * given credentials.
     *
     * @param credentials
     *     The credentials to use for authentication.
     *
     * @return
     *     An AuthenticatedUser representing the user authenticated by the
     *     given credentials.
     *
     * @throws GuacamoleException
     *     If an error occurs while authenticating the user, or if access is
     *     denied.
     */
    public AuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        // Validate login
        Map<String, Connection> connections = connectionService.getConnections(credentials);
        if (connections == null)
            throw new GuacamoleInvalidCredentialsException("Invalid login.", CredentialsInfo.USERNAME_PASSWORD);

        // Return AuthenticatedUser if login succeeds, caching retrieved connections
        AuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
        authenticatedUser.init(credentials, connections);
        return authenticatedUser;

    }

    /**
     * Returns a UserContext object initialized with data accessible to the
     * given AuthenticatedUser.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser to retrieve data for.
     *
     * @return
     *     A UserContext object initialized with data accessible to the given
     *     AuthenticatedUser.
     *
     * @throws GuacamoleException
     *     If the UserContext cannot be created due to an error.
     */
    public UserContext getUserContext(org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        Map<String, Connection> connections;

        // Pull connections from authenticated user if they came from the AWS auth provider
        if (authenticatedUser instanceof AuthenticatedUser)
            connections = ((AuthenticatedUser) authenticatedUser).getConnections();

        // Otherwise, pull connections from AWS directly
        else
            connections = connectionService.getConnections(authenticatedUser.getCredentials());

        // Do not generate a user context if this user has no data
        if (connections == null)
            return null;

        // Return UserContext which provides access to the given connections
        UserContext userContext = userContextProvider.get();
        userContext.init(authenticatedUser, connections);
        return userContext;

    }

}
