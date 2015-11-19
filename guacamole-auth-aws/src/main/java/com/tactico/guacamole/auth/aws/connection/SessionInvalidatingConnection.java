
package com.tactico.guacamole.auth.aws.connection;

import java.util.concurrent.atomic.AtomicBoolean;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleSecurityException;
import org.glyptodon.guacamole.GuacamoleUnauthorizedException;
import org.glyptodon.guacamole.net.DelegatingGuacamoleTunnel;
import org.glyptodon.guacamole.net.GuacamoleTunnel;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.protocol.GuacamoleClientInformation;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

/**
 * A Tactico-specific implementation of Connection which automatically
 * invalidates the user's session upon disconnect.
 *
 * @author Michael Jumper
 */
public class SessionInvalidatingConnection extends SimpleConnection {

    /**
     * Whether this (or any) connection has already been used, and is thus
     * invalid.
     */
    private final AtomicBoolean invalid;

    /**
     * Creates a new connection which automatically invalidates the user's
     * session once the connection is complete.
     *
     * @param identifier
     *     The identifier of the connection. This will also be stored as the
     *     human-readable connection name.
     *
     * @param config
     *     The GuacamoleConfiguration describing the connection parameters and
     *     protocol associated with this connection.
     *
     * @param invalid
     *     An AtomicBoolean which indicates whether connections in general are
     *     invalid. Once set, no further connections should be allowed.
     */
    public SessionInvalidatingConnection(String identifier,
            GuacamoleConfiguration config, AtomicBoolean invalid) {
        super(identifier, identifier, config);
        this.invalid = invalid;
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {

        // Do not allow further connections if any connection has been used
        if (!invalid.compareAndSet(false, true))
            throw new GuacamoleSecurityException("Connection already used.");

        // Return tunnel which automatically invalidates the session upon disconnect
        return new DelegatingGuacamoleTunnel(super.connect(info)) {

            @Override
            public void close() throws GuacamoleException {

                // Close connection
                super.close();

                // Implicitly invalidate session
                throw new GuacamoleUnauthorizedException("Session invalidated.");

            }

        };

    }

}
