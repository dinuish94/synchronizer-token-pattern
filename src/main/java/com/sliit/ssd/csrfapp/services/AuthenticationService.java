package com.sliit.ssd.csrfapp.services;

import com.sliit.ssd.csrfapp.models.Credentials;
import com.sliit.ssd.csrfapp.models.SessionStore;
import com.sliit.ssd.csrfapp.models.UserCredentialsStore;
import com.sliit.ssd.csrfapp.utils.ApplicationConfiguration;
import com.sliit.ssd.csrfapp.utils.EncryptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Handles authentication related tasks
 *
 * Created by dinukshakandasamanage on 9/5/18.
 */

@Service
public class AuthenticationService {

    private Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    @Autowired
    private ApplicationConfiguration applicationConfiguration;

    UserCredentialsStore userCredentialsStore = UserCredentialsStore.getUserCredentialsStore();

    /**
     * Authenticates user using username and password
     *
     * @param username
     * @param password
     * @return
     */
    public boolean isUserAuthenticated(String username, String password){
        try {
            logger.debug("Authenticating user...");
            return (username.equalsIgnoreCase( applicationConfiguration.getUsername())
                    && EncryptionUtils.getHashValue(password).equalsIgnoreCase(applicationConfiguration.getPassword()));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to authenticate user", e);
            return false;
        }
    }

    /**
     * Authenticates user using cookies
     *
     * @param cookies
     * @return
     */
    public boolean isAuthenticated(Cookie[] cookies){
        String session = "";
        String username = "";

        if (null != cookies && cookies.length > 0){
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("sessionID")){
                    session = cookie.getValue();
                } else if (cookie.getName().equals("username")){
                    username = cookie.getValue();
                }
            }
        }

        return (isUserSessionValid(username, session));
    }

    /**
     * Retrieves the session ID from cookies
     *
     * @param cookies
     * @return
     */
    public String sessionIdFromCookies(Cookie[] cookies){
        if (null != cookies && cookies.length > 0){
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("sessionID")){
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Checks if the sessionID is valid for the user
     *
     * @param username
     * @param sessionId
     * @return
     */
    public boolean isUserSessionValid(String username, String sessionId){
        if (UserCredentialsStore.getUserCredentialsStore().findCredentials(username) != null){
            logger.debug("Validating user session...");
            return sessionId.equals(userCredentialsStore
                    .findCredentials(username)
                    .getSessionID());
        }
        return false;
    }

    /**
     * Generates a new session ID
     *
     * @param username
     * @return
     */
    public String generateSessionId(String username){

        logger.debug("Generating user session...");

        // Generate new sessionID for user
        String sessionId = UUID.randomUUID().toString();

        // Store sessionID in UserCredentialsStore
        Credentials credentials = userCredentialsStore.findCredentials(username);
        credentials.setSessionID(sessionId);
        logger.debug("Generating anti-csrf token...");
        generateToken(sessionId);
        userCredentialsStore.saveCredentials(username, credentials);

        logger.debug("Storing user session...");

        return sessionId;
    }

    /**
     * Generates a new anti-CSRF token
     *
     * @param session
     * @return
     */
    public String generateToken(String session){
        logger.debug("Generating user anti-CSRF token...");

        // Generate new token for user -> SessionID + timestamp
        String token = session + System.currentTimeMillis();

        // Store sessionID in SessionStore
        SessionStore.getUserCredentialsStore().addSessionToken(session, token);

        logger.debug("User session store...");

        return token;
    }

    /**
     * Validates if the CSRF token is valid
     *
     * @param sessionID
     * @param token
     * @return
     */
    public boolean validateCSRFToken(String sessionID, String token){
        return token.equals(SessionStore.getUserCredentialsStore().getTokenFromSession(sessionID));
    }

}
