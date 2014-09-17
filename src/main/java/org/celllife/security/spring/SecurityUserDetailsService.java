package org.celllife.security.spring;

import java.util.ArrayList;
import java.util.List;

import org.celllife.security.domain.SecurityUser;
import org.celllife.security.service.SecurityUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

/**
 * Used by Spring in order to retrieve a Security User entity that it can use for authentication
 */
@Transactional
public class SecurityUserDetailsService implements UserDetailsService {

    private static Logger log = LoggerFactory.getLogger(SecurityUserDetailsService.class);

    private String defaultAuthority = "";

    @Autowired
    SecurityUserService securityUserService;

    public String getDefaultAuthority() {
        return defaultAuthority;
    }

    /**
     * Specify the default Authority given to all users who are successfully authenticated. This will differ
     * per application. Set this to the ROLE (e.g. STOCK).
     * 
     * @param defaultAuth String default role
     */
    public void setDefaultAuthority(String defaultAuth) {
        log.info("Setting default auth to " + defaultAuth);
        this.defaultAuthority = defaultAuth;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SecurityUser user = securityUserService.findOneByLogin(username);
        if (user == null) {
            throw new UsernameNotFoundException("Could not find user with login " + username);
        }

        List<SimpleGrantedAuthority> defaultAuths = new ArrayList<SimpleGrantedAuthority>();
        defaultAuths.add(new SimpleGrantedAuthority(defaultAuthority));

        return new SecurityUserDetails(user, defaultAuths);
    }

}
