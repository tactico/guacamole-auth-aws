
package com.tactico.guacamole.auth.aws.user;

import com.google.inject.Inject;
import com.tactico.guacamole.auth.aws.AWSAuthenticationProvider;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.form.Form;
import org.glyptodon.guacamole.net.auth.ActiveConnection;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.ConnectionRecordSet;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.User;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroupDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionRecordSet;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleUser;
import org.glyptodon.guacamole.net.auth.simple.SimpleUserDirectory;

/**
 * An Tactico-specific implementation of UserContext which queries all
 * Guacamole connections from AWS.
 *
 * @author Michael Jumper
 */
public class UserContext implements org.glyptodon.guacamole.net.auth.UserContext {

    /**
     * Reference to the AuthenticationProvider associated with this
     * UserContext.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * Reference to a User object representing the user whose access level
     * dictates the users and connections visible through this UserContext.
     */
    private User self;

    /**
     * Directory containing all User objects accessible to the user associated
     * with this UserContext.
     */
    private Directory<User> userDirectory;

    /**
     * Directory containing all Connection objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<Connection> connectionDirectory;

    /**
     * Directory containing all ConnectionGroup objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<ConnectionGroup> connectionGroupDirectory;

    /**
     * Reference to the root connection group.
     */
    private ConnectionGroup rootGroup;

    /**
     * Initializes this UserContext using the provided AuthenticatedUser and
     * Map of Connections.
     *
     * @param user
     *     The AuthenticatedUser representing the user that authenticated. This
     *     user may have been authenticated by a different authentication
     *     provider.
     *
     * @param connections
     *     The Map of Connections that this UserContext should provide access
     *     to.
     */
    public void init(AuthenticatedUser user,
            Map<String, Connection> connections) {

        // Init self with basic permissions
        self = new SimpleUser(
            user.getIdentifier(),
            Collections.singleton(user.getIdentifier()),
            connections.keySet(),
            Collections.singleton(AWSAuthenticationProvider.ROOT_CONNECTION_GROUP)
        );

        // Add all accessible connections
        connectionDirectory = new SimpleDirectory<Connection>(connections);

        // Root group contains only the provided connections
        rootGroup = new SimpleConnectionGroup(
            AWSAuthenticationProvider.ROOT_CONNECTION_GROUP,
            AWSAuthenticationProvider.ROOT_CONNECTION_GROUP,
            connections.keySet(),
            Collections.<String>emptyList()
        );

        // Expose only the root group in the connection group directory
        connectionGroupDirectory = new SimpleConnectionGroupDirectory(Collections.singleton(rootGroup));

        // The user directory contains only the current user
        userDirectory = new SimpleUserDirectory(self);

    }

    @Override
    public User self() {
        return self;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {
        return userDirectory;
    }

    @Override
    public Directory<Connection> getConnectionDirectory()
            throws GuacamoleException {
        return connectionDirectory;
    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory()
            throws GuacamoleException {
        return connectionGroupDirectory;
    }

    @Override
    public ConnectionGroup getRootConnectionGroup() throws GuacamoleException {
        return rootGroup;
    }

    @Override
    public Directory<ActiveConnection> getActiveConnectionDirectory()
            throws GuacamoleException {
        return new SimpleDirectory<ActiveConnection>();
    }

    @Override
    public ConnectionRecordSet getConnectionHistory()
            throws GuacamoleException {
        return new SimpleConnectionRecordSet();
    }

    @Override
    public Collection<Form> getUserAttributes() {
        return Collections.<Form>emptyList();
    }

    @Override
    public Collection<Form> getConnectionAttributes() {
        return Collections.<Form>emptyList();
    }

    @Override
    public Collection<Form> getConnectionGroupAttributes() {
        return Collections.<Form>emptyList();
    }

}
