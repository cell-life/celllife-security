package org.celllife.security.exception;

/**
 * Parent class for all Security related exceptions thrown
 */
public class CellLifeSecurityException extends Exception {

    private static final long serialVersionUID = -4506046781246024742L;

    public CellLifeSecurityException() {
        super();
    }

    public CellLifeSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public CellLifeSecurityException(String message) {
        super(message);
    }

    public CellLifeSecurityException(Throwable cause) {
        super(cause);
    }
}
