package org.celllife.security;

import java.util.ArrayList;
import java.util.Collection;

import junit.framework.Assert;

import org.celllife.security.domain.SecurityUser;
import org.celllife.security.domain.SecurityUserDto;
import org.celllife.security.exception.InvalidOldPasswordException;
import org.celllife.security.exception.ResetPasswordException;
import org.celllife.security.exception.UnknownSecurityUserException;
import org.celllife.security.service.AbstractSecurityUserServiceImpl;
import org.celllife.security.service.SecurityUserService;
import org.celllife.security.utils.SecurityServiceUtils;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class AbstractSecurityUserServiceImplTest {
    
    @Test
    public void testUpdatePassword() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            TestSecurityUser user = new TestSecurityUser("login", "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99", "salt");
            @Override
            public SecurityUser findOneByLogin(String login) {
                Assert.assertEquals("login", login);
                return user;
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
                Assert.assertEquals(this.user, user);
                Assert.assertEquals("salt", user.getSalt());
                Assert.assertEquals("a86dfa10a82c0eea16380b2d35094eaa5d0b7fa2973c0365e33b7c117901916e", user.getEncryptedPassword());
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        dto.setOldPassword("password");
        dto.setPassword("password2");
        securityUserService.updatePassword(dto);
    }

    @Test(expected = InvalidOldPasswordException.class)
    public void testUpdatePasswordNoOldPassword() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            @Override
            public SecurityUser findOneByLogin(String login) {
                return new TestSecurityUser("login", "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99", "salt");
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        dto.setPassword("password2");
        securityUserService.updatePassword(dto);
    }

    @Test(expected = InvalidOldPasswordException.class)
    public void testUpdatePasswordInvalidOldPassword() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            @Override
            public SecurityUser findOneByLogin(String login) {
                return new TestSecurityUser("login", "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99", "salt");
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        dto.setPassword("password2");
        dto.setOldPassword("blah");
        securityUserService.updatePassword(dto);
    }

    @Test(expected = UnknownSecurityUserException.class)
    public void testUpdatePasswordNoUser() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            @Override
            public SecurityUser findOneByLogin(String login) {
                return null;
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        securityUserService.updatePassword(dto);
    }
    
    @Test
    public void testResetPassword() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            TestSecurityUser user = new TestSecurityUser("login", "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99", "salt");
            @Override
            public SecurityUser findOneByLogin(String login) {
                Assert.assertEquals("login", login);
                return user;
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
                Assert.assertEquals(this.user, user);
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("role_administrator"));
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(null, null, authorities);
        
        String newPassword = securityUserService.resetPassword(auth, dto);
        boolean validPassword = SecurityServiceUtils.isValidPassword(securityUserService.findOneByLogin("login"), newPassword);
        Assert.assertTrue(validPassword);
    }

    @Test(expected = ResetPasswordException.class)
    public void testResetPasswordNoAuthority() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            @Override
            public SecurityUser findOneByLogin(String login) {
                return null;
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        securityUserService.resetPassword(null, dto);
    }

    @Test(expected=UnknownSecurityUserException.class)
    public void testResetPasswordUnknownUser() throws Exception {
        SecurityUserService securityUserService = new AbstractSecurityUserServiceImpl() {
            @Override
            public SecurityUser findOneByLogin(String login) {
                return null;
            }
            @Override
            public void updateEncryptedPasswordAndSalt(SecurityUser user) {
            }
        };
        SecurityUserDto dto = new SecurityUserDto();
        dto.setLogin("login");
        
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("role_administrator"));
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(null, null, authorities);
        
        securityUserService.resetPassword(auth, dto);
    }
}
