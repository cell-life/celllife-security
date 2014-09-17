package org.celllife.security.service;

import java.util.Collection;

import org.apache.commons.lang.RandomStringUtils;
import org.celllife.security.domain.SecurityUser;
import org.celllife.security.domain.SecurityUserDto;
import org.celllife.security.exception.InvalidOldPasswordException;
import org.celllife.security.exception.ResetPasswordException;
import org.celllife.security.exception.UnknownSecurityUserException;
import org.celllife.security.utils.SecurityServiceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

public abstract class AbstractSecurityUserServiceImpl implements SecurityUserService {

    private static Logger log = LoggerFactory.getLogger(AbstractSecurityUserServiceImpl.class);

    private String administratorRole = "ROLE_ADMINISTRATOR";

    @Override
    public void updatePassword(SecurityUserDto user) throws UnknownSecurityUserException, InvalidOldPasswordException {
        SecurityUser securityUser = findOneByLogin(user.getLogin());
        if (securityUser == null) {
            throw new UnknownSecurityUserException("User with login '" + user.getLogin() + "' does not exist.");
        }
        // deal with password resets before merging
        if (!StringUtils.isEmpty(user.getPassword())) {
            if (StringUtils.isEmpty(user.getOldPassword())) {
                throw new InvalidOldPasswordException("In order to reset the password for the user with login '"
                        + user.getLogin() + "' please set the oldPassword.");
            }
            // valid oldPassword and then reset if valid
            if (SecurityServiceUtils.isValidPassword(securityUser, user.getOldPassword())) {
                log.info("Updating password for '" + user.getLogin() + "'");
                SecurityServiceUtils.setPasswordAndSalt(securityUser, user.getPassword());
            } else {
                throw new InvalidOldPasswordException("Cannot update password for user with login '" + user.getLogin()
                        + "' - oldPassword is not valid. Please try again.");
            }
        }
        updateEncryptedPasswordAndSalt(securityUser);
    }

    /**
     * Basic default implementation that allows only an admin user to reset a password. Please implement your own
     * version that emails or smses the password to the user.
     */
    @Override
    public String resetPassword(Authentication auth, SecurityUserDto user) throws UnknownSecurityUserException,
            ResetPasswordException {
        if (isAdministrator(auth)) {
            return resetPassword(user);
        } else {
            throw new ResetPasswordException("Unable to reset password for user with login '" + user.getLogin() + "'");
        }
    }

    protected String resetPassword(SecurityUserDto user) throws UnknownSecurityUserException {
        SecurityUser securityUser = findOneByLogin(user.getLogin());
        if (securityUser == null) {
            throw new UnknownSecurityUserException("User with login '" + user.getLogin() + "' does not exist.");
        }
        log.info("Resetting password for '" + user.getLogin() + "'");
        String newPassword = RandomStringUtils.randomAlphanumeric(6);
        SecurityServiceUtils.setPasswordAndSalt(securityUser, newPassword);
        updateEncryptedPasswordAndSalt(securityUser);
        return newPassword;
    }

    @Override
    public boolean isAdministrator(Authentication auth) {
        boolean admin = false;
        log.debug("checking isAdministrator on " + auth);
        if (auth != null) {
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            if (authorities != null) {
                for (GrantedAuthority a : authorities) {
                    if (a.getAuthority() != null && a.getAuthority().trim().equalsIgnoreCase(administratorRole)) {
                        admin = true;
                        break;
                    }
                }
            }
        }
        return admin;
    }

    /**
     * Specify the authority to match when determining if a user has administrator permissions. This is necessary for
     * the default implementation of reset password.
     * 
     * @param administratorRole String role name, default is 'ROLE_ADMINISTRATOR'
     */
    public void setAdministratorRole(String administratorRole) {
        this.administratorRole = administratorRole;
    }
}