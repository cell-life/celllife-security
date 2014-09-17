package org.celllife.security.exception;

/**
 * Exception used when a user cannot be found by the specified login
 */
public class UnknownSecurityUserException extends CellLifeSecurityException {

    private static final long serialVersionUID = -841546871074496351L;

    public UnknownSecurityUserException(String message) {
        super(message);
    }
}
