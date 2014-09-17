package org.celllife.security;

import junit.framework.Assert;

import org.celllife.security.domain.SecurityUser;
import org.celllife.security.utils.SecurityServiceUtils;
import org.junit.Test;

public class SecurityServiceUtilsTest {

    @Test
    public void encodeString() throws Exception {
        String encodedPassword = SecurityServiceUtils.encodeString("password");
        Assert.assertEquals("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", encodedPassword);
    }

    @Test
    public void encodeStringWithSalt() throws Exception {
        String encodedPassword = SecurityServiceUtils.encodeString("password"+"salt");
        Assert.assertEquals("7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99", encodedPassword);
    }
    
    @Test
    public void isValidPassword() throws Exception {
        SecurityUser user = new SecurityUser() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getLogin() {
                return "login";
            }

            @Override
            public String getEncryptedPassword() {
                return "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99";
            }

            @Override
            public String getSalt() {
                return "salt";
            }

            @Override
            public void setEncryptedPassword(String encryptedPassword) {
            }

            @Override
            public void setSalt(String salt) {
            }
        };
        Boolean validPassword = SecurityServiceUtils.isValidPassword(user,"password");
        Assert.assertTrue(validPassword);
    }

    @Test
    public void isInvalidPassword() throws Exception {
        SecurityUser user = new SecurityUser() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getLogin() {
                return "login";
            }

            @Override
            public String getEncryptedPassword() {
                return "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99";
            }

            @Override
            public String getSalt() {
                return "salt";
            }

            @Override
            public void setEncryptedPassword(String encryptedPassword) {
            }

            @Override
            public void setSalt(String salt) {
            }
        };
        Boolean validPassword = SecurityServiceUtils.isValidPassword(user,"wordpass");
        Assert.assertFalse(validPassword);
    }
}
