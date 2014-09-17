package org.celllife.security.utils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.celllife.security.domain.SecurityUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityServiceUtils {

    private static Logger log = LoggerFactory.getLogger(SecurityServiceUtils.class);

    /**
     * This method will hash <code>strToEncode</code> using the preferred algorithm (SHA-256)
     * 
     * @param strToEncode string to encode
     * @return the SHA-1 encryption of a given string
     * @throws NoSuchAlgorithmException
     * @throws NoSuchAlgorithmException if the specified algorithm (SHA-256) does not exist
     * @throws UnsupportedEncodingException if the specified encoding (UTF-8) does not exist
     */
    public static String encodeString(String strToEncode) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String algorithm = "SHA-256";
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] input = strToEncode.getBytes("UTF-8");
        return hexString(md.digest(input));
    }

    /**
     * Used to generate password salts
     * 
     * @return a secure random token.
     */
    public static String getRandomToken() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Random rng = new Random();
        return encodeString(Long.toString(System.currentTimeMillis()) + Long.toString(rng.nextLong()));
    }

    /**
     * Updates the SecurityUser's password and salt. Will encrypt the specified password and create a salt if none
     * exists.
     * 
     * @param user SecurityUser to update
     * @param password String new plain text password.
     */
    public static void setPasswordAndSalt(SecurityUser user, String password) {
        try {
            if (user.getSalt() == null || user.getSalt().trim().isEmpty()) {
                user.setSalt(SecurityServiceUtils.getRandomToken());
            }
            user.setEncryptedPassword(SecurityServiceUtils.encodeString(password + user.getSalt()));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            // this should not happen during runtime
            throw new RuntimeException("Could not encrypt the user's password.", e);
        }
    }

    /**
     * Determines if the specified password is a valid password.
     * 
     * @param user SecurityUser containing the encrypted password and salt
     * @param password String plain text password (entered)
     * @return Boolean true if the password is a match, false if it is not or there is a problem with encoding
     */
    public static Boolean isValidPassword(SecurityUser user, String password) {
        String encryptedPassword = user.getEncryptedPassword();
        String salt = user.getSalt();
        try {
            String hashedPassword = SecurityServiceUtils.encodeString(password + salt);
            if (hashedPassword.equals(encryptedPassword)) {
                return true;
            }
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            log.warn("Could not encode the password. It will be marked as invalid. Error:" + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Convenience method to convert a byte array to a string.
     */
    private static String hexString(byte[] b) {
        StringBuffer buf = new StringBuffer();
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        int len = b.length;
        int high = 0;
        int low = 0;
        for (int i = 0; i < len; i++) {
            high = ((b[i] & 0xf0) >> 4);
            low = (b[i] & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }

        return buf.toString();
    }
}
