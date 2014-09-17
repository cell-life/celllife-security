package org.celllife.security.spring;

import java.util.List;

import org.celllife.security.domain.SecurityUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * The User details used by Spring Security in order to authenticate
 */
public class SecurityUserDetails extends User {
	
	@SuppressWarnings("unused")
    private static Logger log = LoggerFactory.getLogger(SecurityUserDetails.class);

	private static final long serialVersionUID = 655111608903564631L;
	private String salt;

	public SecurityUserDetails(SecurityUser user, List<SimpleGrantedAuthority> defaultAuths) {
		super(user.getLogin(), user.getEncryptedPassword(), defaultAuths);
		this.salt = user.getSalt();
	}

	public String getSalt() {
		return salt;
	}
}
