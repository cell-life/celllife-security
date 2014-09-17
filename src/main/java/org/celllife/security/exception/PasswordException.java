package org.celllife.security.exception;

/**
 * Exception used when there is an issue with setting or resetting a password
 */
public class PasswordException extends CellLifeSecurityException {

    private static final long serialVersionUID = 6259230710951052649L;

    public PasswordException(String message) {
        super(message);
    }

    public PasswordException() {
        super();
    }

    public PasswordException(String message, Throwable cause) {
        super(message, cause);
    }

    public PasswordException(Throwable cause) {
        super(cause);
    }
}
