package org.celllife.security.domain;

import java.io.Serializable;

/**
 * Data Transfer Object to be used in the REST service for setting and resetting passwords
 */
public class SecurityUserDto implements Serializable {

    private static final long serialVersionUID = 8681278666806362212L;

    private String login;
    private String password;
    private String oldPassword;
    
    public SecurityUserDto() {
        
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    @Override
    public String toString() {
        return "SecurityUserDto [login=" + login + ", password=" + password + ", oldPassword=" + oldPassword + "]";
    }
}
