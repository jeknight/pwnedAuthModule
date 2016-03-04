/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011-2015 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt.
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file at legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

package org.forgerock.openam.examples;

import java.security.Principal;
import java.util.Map;
import java.util.ResourceBundle;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;


import javax.security.auth.login.LoginException;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;

import com.iplanet.dpro.session.service.InternalSession;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;

import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;

import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.Iterator;
import org.forgerock.openam.utils.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;




public class PwnedAuth extends AMLoginModule {

    // Name for the debug-log
    private final static String DEBUG_NAME = "PwnedAuth";
    private final static Debug debug = Debug.getInstance(DEBUG_NAME);

    // Name of the resource bundle
    private final static String amAuthPwnedAuth = "amAuthPwnedAuth";

    // Orders defined in the callbacks file
    private final static int STATE_BEGIN = 1;
    private final static int STATE_AUTH = 2;
    private final static int STATE_ERROR = 3;

    private Map<String, String> options;
    private ResourceBundle bundle;
    private Map sharedState;
    private String userName = null;
    private String userUUID = null;
    private String userMail = null;
    private AMIdentityRepository amIdentityRepo;
    private AMIdentity amIdentity;


    public PwnedAuth() {
        super();
    }


    /**
     * This method stores service attributes and localized properties for later
     * use.
     * @param subject
     * @param sharedState
     * @param options
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {

        debug.message("PwnedAuth::init");

        userName = (String) sharedState.get(getUserKey());
        if (userName == null || userName.isEmpty()) {
            try {
                //Session upgrade case. Need to find the user ID from the old session.
                SSOTokenManager mgr = SSOTokenManager.getInstance();
                InternalSession isess = getLoginState("PwnedAuth").getOldSession();
                if (isess == null) {
                    throw new AuthLoginException("amAuth", "noInternalSession", null);
                }
                SSOToken token = mgr.createSSOToken(isess.getID().toString());
                userUUID = token.getPrincipal().getName();
                userName = token.getProperty("UserToken");
                if (debug.messageEnabled()) {
                    debug.message("PwnedAuth.init() : UserName in SSOToken : " + userName);
                }
            } catch (SSOException ssoe) {
                debug.error("PwnedAuth.init() : Unable to retrieve userName from existing session", ssoe);
            } catch (AuthLoginException ale) {
                debug.error("PwnedAuth.init() : Unable to retrieve userName from existing session", ale);
            }
        }

        amIdentityRepo = getAMIdentityRepository(getRequestOrg());
        amIdentity = getIdentity();
        try {
            userMail = getEmailAddress(amIdentity);
        } catch (IdRepoException e) {
            debug.error("PwnedAuth.init() : Unable to retrieve mail address for user", e);
        } catch (SSOException ssoe) {
            debug.error("PwnedAuth.init() : Unable to retrieve mail address for user", ssoe);
        }      

        this.options = options;
        this.sharedState = sharedState;
        this.bundle = amCache.getResBundle(amAuthPwnedAuth, getLoginLocale());
    }

    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {

        debug.error("PwnedAuth::process state: {}", state);

        switch (state) {

            case STATE_BEGIN:
                // No time wasted here - simply modify the UI and
                // proceed to next state
                
                if (userMail == null || userMail.isEmpty()) {
                    debug.error("PwnedAuth : mail attribute empty so authentication succeeds");
                    return ISAuthConstants.LOGIN_SUCCEED;
                }
                if (!checkPwnedStatus()) {
                    debug.error("PwnedAuth : no breaches returned from haveIBeenPwned service");
                    return ISAuthConstants.LOGIN_SUCCEED;
                }
                return STATE_AUTH; 
                
            case STATE_AUTH:
                //return ISAuthConstants.LOGIN_SUCCEED;
                setErrorText("pwnedauth-error-1");
                return STATE_ERROR;
 
            case STATE_ERROR:
                return STATE_ERROR;
            default:
                throw new AuthLoginException("invalid state");
        }
    }

    @Override
    public Principal getPrincipal() {
        return new PwnedAuthPrincipal(userName);
    }


    private void setErrorText(String err) throws AuthLoginException {
        // Receive correct string from properties and substitute the
        // header in callbacks order 3.
        substituteHeader(STATE_ERROR, bundle.getString(err));
    }


    private boolean checkPwnedStatus() throws AuthLoginException {
        // Get service specific attribute configured in OpenAM
        String ssa = CollectionHelper.getMapAttr(options, "specificAttribute");

        // Get property from bundle
        String new_hdr = bundle.getString("pwnedauth-ui-login-header");
        substituteHeader(STATE_AUTH, new_hdr);


        String pwnedString = haveIBeenPwned();
        if (pwnedString == "") { return false; }
        else 
        {
            debug.message("PwnedAuth : result from service : " + pwnedString);

            // Parse JSON response into object map
            ObjectMapper mapper = new ObjectMapper();
            List<Map<String,Object>> userData = null;
            try {
                userData = mapper.readValue(pwnedString, mapper.getTypeFactory().constructCollectionType(List.class, Map.class));
            } catch (IOException e) {
                debug.error("IOException " + e.getMessage());
            };

            // Construct JavaScript warning + Pwned table
            String p1 =  "<div class=\"well\"><table class=\"table table-bordered table-striped\"><tbody><tr><th>Name</th><th>Breach date</th></tr>";
            for (int i=0; i < userData.size(); i++) {
                p1 = p1 + "<tr><td>" + (String)userData.get(i).get("Title") + "</td><td>" + (String)userData.get(i).get("BreachDate") + "</td></tr>";
            }
            String pwnedOutputScript = p1 + "</tbody></table></div>";

            String warningMsg = "Your email address (<strong>" + userMail + "</strong>) has been associated with an incident where data has been illegally accessed by hackers and then released publicly. Visit <strong><a href=\"https://haveibeenpwned.com\" target=\"_blank\">https://haveibeenpwned.com</a></strong> for a full description of the detected breach. Below is a summary of the breaches associated with your email address.";
            String clientScript =   "$(document).ready(function(){" +
                                    "$('#loginButton_0').attr('value','Continue');" +
                                    "strUI='<div class=\"alert alert-danger\"><strong>Warning </strong>" +
                                    warningMsg +
                                    "</div>" +
                                    pwnedOutputScript +
                                    "';" +
                                    "$('#callback_0').prepend(strUI);" +
                                    "});";


            replaceCallback(STATE_AUTH, 0, new ScriptTextOutputCallback(clientScript));
            replaceCallback(STATE_AUTH, 1, new HiddenValueCallback("callback_1"));

            return true;     
        }
    }


    /**
     * Gets the user's AMIdentity from LDAP.
     *
     * @return The AMIdentity for the user.
     */
    public AMIdentity getIdentity() {
        AMIdentity amIdentity = null;
        AMIdentityRepository amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        Set<AMIdentity> results = Collections.EMPTY_SET;

        try {
            idsc.setMaxResults(0);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.USER, userName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results.isEmpty()) {
                debug.error("PwnedAuth.getIdentity() : User " + userName + " is not found");
            } else if (results.size() > 1) {
                debug.error("PwnedAuth.getIdentity() : More than one user found for the userName " + userName);
            } else {
                amIdentity = results.iterator().next();
            }

        } catch (IdRepoException e) {
            debug.error("PwnedAuth.getIdentity() : Error searching Identities with username : " + userName, e);
        } catch (SSOException e) {
            debug.error("PwnedAuth.getIdentity() : Module exception : ", e);
        }
        return amIdentity;
    }

    /**
     * Gets the Email address of the user.
     *
     * @param identity The user's identity.
     * @return The user's email address.
     * @throws IdRepoException If there is a problem getting the user's email address.
     * @throws SSOException If there is a problem getting the user's email address.
     */
    private String getEmailAddress(AMIdentity identity) throws IdRepoException, SSOException {

        Set emails = identity.getAttribute("mail");

        Iterator itor = null;
        String mail = null;
        if (emails != null && !emails.isEmpty()) {
            itor = emails.iterator();
            mail = (String) itor.next();
        } else {
            debug.error("PwnedAuth.getEmailAddress() : IdRepo: no email found with username : " + userName);
        }
        return mail;
    }

    private String haveIBeenPwned() {
        String json = "";
        try {
            URL url = new URL("https://haveibeenpwned.com/api/v2/breachedaccount/" + userMail);
            debug.message("PwnedAuth.haveIBeenPwned(): url : " + url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (conn.getResponseCode() == 404) {
                debug.message("PwnedAuth.haveIBeenPwned() : response 404 - no breaches found");
                return json;
            }
            if (conn.getResponseCode() != 200) {
                debug.message("PwnedAuth.haveIBeenPwned(): HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException("PwnedAuth : HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                json = json + output;
            }
            conn.disconnect();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return json;
    }
    
}
