package org.celllife.security.exception;

/**
 * Exception used the specified old password is not correct
 */
public class ResetPasswordException extends PasswordException {

    private static final long serialVersionUID = -4263811429543863545L;

    public ResetPasswordException(String message) {
        super(message);
    }
}
