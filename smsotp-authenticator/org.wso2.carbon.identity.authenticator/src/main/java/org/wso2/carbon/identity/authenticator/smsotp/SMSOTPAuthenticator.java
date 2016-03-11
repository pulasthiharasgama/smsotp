/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.smsotp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.io.*;

/**
 * Authenticator of SMSOTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    AuthenticationContext authContext = new AuthenticationContext();
    Map<String, String> newAuthenticatorProperties;
    private String otpToken;
    private String mobile;
    private String savedOTPString = null;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method");
        }
        return StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.CODE));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        String resourceName = SMSOTPConstants.PROPERTIES_FILE;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties prop = new Properties();

        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        try {
            prop.load(resourceStream);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Can not find the file", e);
        }

        newAuthenticatorProperties = context.getAuthenticatorProperties();
        newAuthenticatorProperties.put("username", prop.getProperty("username"));
        newAuthenticatorProperties.put("password", prop.getProperty("password"));
        newAuthenticatorProperties.put("from", prop.getProperty("from"));
        newAuthenticatorProperties.put("text", prop.getProperty("text"));
        context.setAuthenticatorProperties(newAuthenticatorProperties);

        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
        otpToken = token.generateToken(secret, "" + SMSOTPConstants.NUMBER_BASE, SMSOTPConstants.NUMBER_DIGIT);
        Object myToken = otpToken;
        authContext.setProperty(otpToken, myToken);

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
//        clientId = authenticatorProperties.get(SMSOTPConstants.API_KEY);
//        clientSecret = authenticatorProperties.get(SMSOTPConstants.API_SECRET);
        String smsUrl = authenticatorProperties.get(SMSOTPConstants.SMS_URL);
        String httpMethod = authenticatorProperties.get(SMSOTPConstants.HTTP_METHOD);
        String headerString = authenticatorProperties.get(SMSOTPConstants.HEADERS);
        String payload = authenticatorProperties.get(SMSOTPConstants.PAYLOAD);

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", SMSOTPConstants.LOGIN_PAGE);
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = SMSOTPConstants.RETRY_PARAMS;
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators="
                    + getName() + retryParam);
        } catch (IOException e) {
            log.error("Authentication failed!", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        String username = getUsername(context);
        if (username != null) {
            UserRealm userRealm = getUserRealm(username);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                try {
                    mobile = userRealm.getUserStoreManager()
                            .getUserClaimValue(username, SMSOTPConstants.MOBILE_CLAIM, null).toString();
                } catch (UserStoreException e) {
                    log.error("Cannot find the user claim for mobile", e);
                    throw new AuthenticationFailedException("Cannot find the user claim for mobile " + e.getMessage(),
                            e);
                }
                try {
                    savedOTPString = userRealm.getUserStoreManager()
                            .getUserClaimValue(username, SMSOTPConstants.SAVED_OTP_LIST, null).toString();
                } catch (UserStoreException e) {
                    log.error("Cannot find the user claim for OTP list", e);
                    throw new AuthenticationFailedException(
                            "Cannot find the user claim for OTP list " + e.getMessage(), e);
                }
            }
        }

        if (!StringUtils.isEmpty(smsUrl) && !StringUtils.isEmpty(httpMethod) && !StringUtils.isEmpty(mobile)) {
            try {
                if (!sendRESTCall(smsUrl, httpMethod, headerString, payload)) {
                    log.error("Unable to send the code");
                    throw new AuthenticationFailedException("Unable to send the code");
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while sending the HTTP request", e);
                }
            }
        } else if(StringUtils.isEmpty(smsUrl)){
            if (log.isDebugEnabled()) {
                log.debug("SMS URL is null");
            }
        } else if(StringUtils.isEmpty(httpMethod)){
            if (log.isDebugEnabled()) {
                log.debug("HTTP Method is null");
            }
        }
    }

    /**
     * Process the response of the SMSOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) authContext.getProperty(otpToken);
        if (userToken.equals(contextToken)) {
            context.setSubject(AuthenticatedUser
                    .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
        } else if (savedOTPString != null && savedOTPString.contains(userToken)) {
            context.setSubject(AuthenticatedUser
                    .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));

            savedOTPString = savedOTPString.replaceAll(userToken, "").replaceAll(",,", ",");

            String username = getUsername(context);
            if (username != null) {
                UserRealm userRealm = getUserRealm(username);
                username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                if (userRealm != null) {
                    try {
                        userRealm.getUserStoreManager().setUserClaimValue(username, SMSOTPConstants.SAVED_OTP_LIST,
                                savedOTPString, null);
                    } catch (UserStoreException e) {
                        log.error("Unable to set the user claim for OTP List for user " + username, e);
                    }
                }
            }
        } else if (savedOTPString == null) {
            log.error("The claim " + SMSOTPConstants.SAVED_OTP_LIST + " does not contain any values");
        } else {
            log.error("Verification Error due to Code Mismatch");
            throw new AuthenticationFailedException("Verification Error due to Code Mismatch");
        }
    }

    /**
     * Get the user realm of the logged in user
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        UserRealm userRealm = null;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm", e);
        }
        return userRealm;
    }

    /**
     * Get the username of the logged in User
     */
    private String getUsername(AuthenticationContext context) {
        String username = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null
                    && context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        return username;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    public String getFriendlyName() {
        return SMSOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    public String getName() {
        return SMSOTPConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property smsUrl = new Property();
        smsUrl.setName(SMSOTPConstants.SMS_URL);
        smsUrl.setDisplayName("SMS URL");
        smsUrl.setRequired(true);
        smsUrl.setDescription("Enter client sms url value");
        smsUrl.setDisplayOrder(0);
        configProperties.add(smsUrl);
        
        Property httpMethod = new Property();
        httpMethod.setName(SMSOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
        httpMethod.setDescription("Enter the HTTP Method used by the SMS API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);
        
        Property headers = new Property();
        headers.setName(SMSOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API seperated by comma, with the Header name and value seperated by \":\"");
        headers.setDisplayOrder(2);
        configProperties.add(headers);
        
        Property payload = new Property();
        payload.setName(SMSOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the SMS API");
        payload.setDisplayOrder(3);
        configProperties.add(payload);   

        return configProperties;
    }

    public boolean sendRESTCall(String smsUrl, String httpMethod, String headerString, String payload) throws IOException {
        HttpsURLConnection connection = null;
        try {
            
            smsUrl = smsUrl.replaceAll("&num", mobile).replaceAll("&msg", "Verification Code: " + otpToken );
                        
            URL smsProviderUrl = new URL(smsUrl);
            connection = (HttpsURLConnection) smsProviderUrl.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            
            String[] headerList;
            
            if(headerString != ""){
                headerString = headerString.replaceAll("&num", mobile).replaceAll("&msg", "Verification Code: " + otpToken );
                
                headerList = headerString.split(",");
                
                for(int i =0; i<headerList.length; i++){
                    String[] header  = headerList[i].split(":");
                    connection.setRequestProperty(header[0], header[1]);
                } 
            }
        
            if(httpMethod.toLowerCase().contains("get")){
                connection.setRequestMethod("GET");
            } else if (httpMethod.toLowerCase().contains("post")){
                connection.setRequestMethod("POST");
                if(payload != ""){
                    payload = payload.replaceAll("&num", mobile).replaceAll("&msg", "Verification Code: " + otpToken );
                }
                
                OutputStreamWriter writer = null;
                try{
                    writer = new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
                    writer.write(payload);
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while posting payload message", e);
                    }
                    throw new IOException();
                }finally{
                    writer.close();
                }   
            }
            
            if (connection.getResponseCode() >= 200 && connection.getResponseCode() < 300) {
                if (log.isDebugEnabled()) {
                    log.debug("Code is successfully sent to your mobile number");
                }
                return true;
            }
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid URL", e);
            }
            throw new MalformedURLException();
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while setting the HTTP method", e);
            }
            throw new ProtocolException();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the HTTP response", e);
            }
            throw new IOException();
        } finally {
            connection.disconnect();
        }
        return false;
    }
}
