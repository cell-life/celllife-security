package org.celllife.security;

import org.celllife.security.domain.SecurityUser;

public class TestSecurityUser implements SecurityUser {

    private static final long serialVersionUID = 2279534864574431562L;

    private String login;
    private String encryptedPassword;
    private String salt;
    
    public TestSecurityUser(String login, String encryptedPassword, String salt) {
        this.login = login;
        this.encryptedPassword = encryptedPassword;
        this.salt = salt;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
