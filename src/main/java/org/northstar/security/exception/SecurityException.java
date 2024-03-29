package org.northstar.security.exception;

public class SecurityException extends RuntimeException{

    public SecurityException(Exception e){
        super(e);
    }
}
