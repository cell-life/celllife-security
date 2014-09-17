package org.celllife.security.interfaces.service;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.celllife.security.domain.SecurityUserDto;
import org.celllife.security.exception.InvalidOldPasswordException;
import org.celllife.security.exception.ResetPasswordException;
import org.celllife.security.exception.UnknownSecurityUserException;
import org.celllife.security.service.SecurityUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/service/user/password")
public class UserController {

    private static Logger log = LoggerFactory.getLogger(UserController.class);

    public static final int SC_UNPROCESSABLE_ENTITY = 422;

    @Autowired
    SecurityUserService securityUserService;

    @Value("${external.base.url}")
    String baseUrl;

    @ResponseBody
    @RequestMapping(method = RequestMethod.PUT)
    public void changePassword(@RequestBody SecurityUserDto user, HttpServletResponse response) throws IOException {
        log.info("Changing password for " + user);
        try {
            securityUserService.updatePassword(user);
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (UnknownSecurityUserException e) {
            log.warn("Cannot change password: user with login '" + user.getLogin() + "' does not exist.");
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        } catch (InvalidOldPasswordException e) {
            log.warn("Cannot change password: invalid old password specified for '" + user.getLogin() + "'. Error: "
                    + e.getMessage());
            response.sendError(SC_UNPROCESSABLE_ENTITY);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/reset", method = RequestMethod.PUT, produces = MediaType.APPLICATION_JSON_VALUE)
    public String resetPassword(@RequestBody SecurityUserDto user, HttpServletResponse response) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("resetting password for " + user);
        try {
            String newPassword = securityUserService.resetPassword(auth, user);
            response.setStatus(HttpServletResponse.SC_OK);
            return newPassword;
        } catch (UnknownSecurityUserException e) {
            log.warn("Cannot reset password: user with login '" + user.getLogin() + "' does not exist.");
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        } catch (ResetPasswordException e) {
            log.warn("Cannot reset password for '" + user.getLogin() + "'. Error: " + e.getMessage());
            response.sendError(SC_UNPROCESSABLE_ENTITY);
        }
        return null;
    }
}
