package org.celllife.security.spring;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.celllife.security.utils.SecurityServiceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.encoding.PasswordEncoder;

/**
 * Implementation of the Spring Security PasswordEncoder used to encode passwords and check if a password is valid.
 */
public class EncryptedPasswordEncoder implements PasswordEncoder {
	
	private static Logger log = LoggerFactory.getLogger(EncryptedPasswordEncoder.class);

	@Override
	public String encodePassword(String password, Object salt) {
		try {
			String encodedPassword = SecurityServiceUtils.encodeString(password+salt);
			return encodedPassword;
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			log.warn("Could  not encode the password. Error:"+e.getMessage(), e);
		}
		return null;
	}

	@Override
	public boolean isPasswordValid(String encryptedPassword, String password, Object salt) {
		try {
			String hashedPassword = SecurityServiceUtils.encodeString(password + salt);
			if (hashedPassword.equals(encryptedPassword)) {
				return true;
			}
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			log.warn("Could not encode the password. It will be marked as invalid. Error:"+e.getMessage(), e);
		}
		return false;
	}

}
