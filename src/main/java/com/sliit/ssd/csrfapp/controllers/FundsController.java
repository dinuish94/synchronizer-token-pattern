package com.sliit.ssd.csrfapp.controllers;

import com.sliit.ssd.csrfapp.exceptions.UnauthorizedException;
import com.sliit.ssd.csrfapp.models.FundTransfer;
import com.sliit.ssd.csrfapp.services.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Handles fund transfer functions
 *
 * Created by dinukshakandasamanage on 9/6/18.
 */
@RestController
public class FundsController {

    private static Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping("/transfer")
    public String transferFunds(@ModelAttribute FundTransfer fundTransfer, HttpServletRequest request) throws UnauthorizedException, IOException {
        String sessionId = authenticationService.sessionIdFromCookies(request.getCookies());

        logger.info("Validating token...");
        if (authenticationService.validateCSRFToken(sessionId, fundTransfer.getCsrf())){

            logger.info("Token validated...");
            // a new CSRF token is created for the session
            authenticationService.generateToken(sessionId);
            return "success";
        }
        logger.error("Invalid token!!!");
        throw new UnauthorizedException();
    }


}
