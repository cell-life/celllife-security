package org.celllife.security.service;

import org.celllife.security.domain.SecurityUser;
import org.celllife.security.domain.SecurityUserDto;
import org.celllife.security.exception.InvalidOldPasswordException;
import org.celllife.security.exception.ResetPasswordException;
import org.celllife.security.exception.UnknownSecurityUserException;
import org.springframework.security.core.Authentication;

/**
 * Data Access Object (Repository) used to retrieve a Security User entity by their login identifier.
 */
public interface SecurityUserService {

    /**
     * Retrieve a SecurityUser given their unique login identifier
     * 
     * @param login String login name
     * @return Security User
     */
    SecurityUser findOneByLogin(String login);

    /**
     * Updates a SecurityUser given their encrypted password and salt.
     * 
     * @param user SecurityUser with new password and salt set
     */
    void updateEncryptedPasswordAndSalt(SecurityUser user);

    /**
     * Handles a password update for the specified user (including saving). Will check that the oldPassword matches with
     * the existing password before performing an update.
     * 
     * @param user
     * @throws UnknownSecurityUserException if the specified user cannot be found
     * @throws InvalidOldPasswordException if the old password does not match the current password
     */
    void updatePassword(SecurityUserDto user) throws UnknownSecurityUserException, InvalidOldPasswordException;

    /**
     * Handles the password reset for the specified user (including saving). Will also handle notifying the user of
     * their password reset using the correct channels.
     * 
     * @param auth Authentication object for the logged in user (used, for example, to limit password resets for admin
     *        users). Can be null
     * @param user SecurityUserDto whose password should be reset
     * @return String message for the user (can either contain the password or an instruction on how to get their new
     *         password)
     * @throws UnknownSecurityUserException if the specified user cannot be found
     * @throws ResetPasswordException if there is an issue resetting the password (for example the user is not an administrator)
     */
    String resetPassword(Authentication auth, SecurityUserDto user) throws UnknownSecurityUserException,
            ResetPasswordException;
    
    /**
     * Determines if the specified user is an administrator. Typically used for resetting of passwords (default implementation)
     * @param auth Authentication
     * @return boolean true if the user is considered an administrator
     */
    boolean isAdministrator(Authentication auth);
}
