package org.celllife.security.exception;

/**
 * Exception used when it is not possible to reset the user's password
 */
public class InvalidOldPasswordException extends PasswordException {

    private static final long serialVersionUID = -1091267259385244043L;

    public InvalidOldPasswordException(String message) {
        super(message);
    }
}
