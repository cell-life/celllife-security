package org.celllife.security.domain;

import java.io.Serializable;

/**
 * Interface that must be implemented by an entity that wishes to be used to authenticate users
 */
public interface SecurityUser extends Serializable {
    
    /**
     * Retrieve the unique identifier this user uses for authentication. This can be a username
     * or msisdn or some kind of code.
     *  
     * @return String login name
     */
    String getLogin();

    /**
     * Retrieve the stored encrypted password for this user
     * 
     * @return String encrypted password
     */
    String getEncryptedPassword();
    
    /**
     * Sets the encrypted password
     *
     * @param encryptedPassword String
     */
    void setEncryptedPassword(String encryptedPassword);

    /**
     * Retrieve the salt used to encrypt the password for this user
     * 
     * @return String password salt
     */
    String getSalt();
    
    /**
     * Sets the password salt (used to encrypt the password)
     * 
     * @param salt String password salt
     */
    void setSalt(String salt);
}
