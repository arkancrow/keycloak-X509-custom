package be.zorgi.keycloak.spi.authentication;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.UserResource;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.cert.X509Certificate;
import java.util.*;

public class X509CustomClientCertificateAuthenticator extends AbstractX509ClientCertificateAuthenticator {

    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        try {

            dumpContainerAttributes(context);
            context.clearUser();

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, fall through and
                // continue processing the rest of the authentication flow
                logger.info("[X509CustomClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
//                context.challenge(createInfoResponse(context, "x509 client certificate is not available for mutual SSL."));
//                context.attempted();

                String errorMessage = "Certificate validation's failed.";
                context.challenge(createResponseNoCertificate(context, errorMessage));
                context.attempted();

                return;
            }

            X509AuthenticatorConfigModel config = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig() != null) {
                config = new X509AuthenticatorConfigModel(context.getAuthenticatorConfig());
            }
            if (config == null) {
                logger.warn("[X509CustomClientCertificateAuthenticator:authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.challenge(createInfoResponse(context, "X509 client authentication has not been configured yet"));
                context.attempted();
                return;
            }

            // Validate X509 client certificate
            try {
                CertificateValidator.CertificateValidatorBuilder builder = certificateValidationParameters(context.getSession(), config);
                CertificateValidator validator = builder.build(certs);
                validator.checkRevocationStatus()
                        .validateKeyUsage()
                        .validateExtendedKeyUsage();
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
                String errorMessage = "Certificate validation's failed.";
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            config.getConfig().put("x509-cert-auth.regular-expression", "SERIALNUMBER=(.*?),");
            Object serialNumber = getUserIdentityExtractor(config).extractUserIdentity(certs);
            config.getConfig().put("x509-cert-auth.regular-expression", "GIVENNAME=(.*?),");
            Object givenName = getUserIdentityExtractor(config).extractUserIdentity(certs);
            config.getConfig().put("x509-cert-auth.regular-expression", "SURNAME=(.*?),");
            Object surName = getUserIdentityExtractor(config).extractUserIdentity(certs);
            logger.debug("[X509CustomClientCertificateAuthenticator:authenticate] user info : " + serialNumber + " - " + givenName + " - " + surName);
            if (serialNumber == null) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                logger.warnf("[X509CustomClientCertificateAuthenticator:authenticate] Unable to extract user identity from certificate.");
                String errorMessage = "Unable to extract user identity from specified certificate";
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }
            logger.debug("[X509CustomClientCertificateAuthenticator:authenticate] user indentity : " + serialNumber.toString());
            UserModel user;
            try {
                context.getEvent().detail(Details.USERNAME, serialNumber.toString());
                context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, serialNumber.toString());
                user = getUserIdentityToModelMapper(config).find(context, serialNumber);
            } catch(ModelDuplicateException e) {
                logger.modelDuplicateException(e);
                String errorMessage = "X509 certificate authentication's failed.";
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            //If the user is not found, add it to the user repository
            if(user == null) {
                logger.debug("User not found, creating a new one.");
                KeycloakSession keycloakSession = context.getSession();
                UserProvider userProvider = keycloakSession.users();
                RealmModel realmModel = context.getRealm();
                user = userProvider.addUser(realmModel, serialNumber.toString());
                UserRepresentation rep = new UserRepresentation();
                rep.setUsername(serialNumber.toString());
                rep.setFirstName(givenName.toString());
                rep.setLastName(surName.toString());
                rep.setEnabled(true);
                logger.debug("[X509CustomClientCertificateAuthenticator:authenticate] create user model : " + user.toString());
                UserResource.updateUserFromRep(null, user, rep, keycloakSession, false);
                user = getUserIdentityToModelMapper(config).find(context, serialNumber);
            }

            if (invalidUser(context, user)) {
                String errorMessage = "X509 certificate authentication's failed.";
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Invalid user"));
                context.attempted();
                return;
            }

            if (!userEnabled(context, user)) {
                String errorMessage = "X509 certificate authentication's failed.";
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "User is disabled"));
                context.attempted();
                return;
            }
            if (context.getRealm().isBruteForceProtected()) {
                if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                    context.getEvent().user(user);
                    context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                    String errorMessage = "X509 certificate authentication's failed.";
                    context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                            errorMessage, "User is temporarily disabled. Contact administrator."));
                    context.attempted();
                    return;
                }
            }
            context.getAuthenticationSession().setAuthenticatedUser(user);
            context.setUser(user);

            // Check whether to display the identity confirmation
            if (!config.getConfirmationPageDisallowed()) {
                // FIXME calling forceChallenge was the only way to display
                // a form to let users either choose the user identity from certificate
                // or to ignore it and proceed to a normal login screen. Attempting
                // to call the method "challenge" results in a wrong/unexpected behavior.
                // The question is whether calling "forceChallenge" here is ok from
                // the design viewpoint?
                context.forceChallenge(createSuccessResponse(context, certs[0].getSubjectDN().getName()));
                // Do not set the flow status yet, we want to display a form to let users
                // choose whether to accept the identity from certificate or to specify username/password explicitly
            }
            else {
                // Bypass the confirmation page and log the user in
                context.success();
            }
        }
        catch(Exception e) {
            logger.errorf("[X509CustomClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
            context.attempted();
        }
    }

    private Response createErrorResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         String errorMessage,
                                         String ... errorParameters) {

        return createResponse(context, subjectDN, false, errorMessage, errorParameters);
    }

    private Response createSuccessResponse(AuthenticationFlowContext context,
                                           String subjectDN) {
        return createResponse(context, subjectDN, true, null, null);
    }

    private Response createResponse(AuthenticationFlowContext context,
                                    String subjectDN,
                                    boolean isUserEnabled,
                                    String errorMessage,
                                    Object[] errorParameters) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            List<FormMessage> errors = new LinkedList<>();

            errors.add(new FormMessage(errorMessage));
            if (errorParameters != null) {

                for (Object errorParameter : errorParameters) {
                    if (errorParameter == null) continue;
                    for (String part : errorParameter.toString().split("\n")) {
                        errors.add(new FormMessage(part));
                    }
                }
            }
            form.setErrors(errors);
        }

        MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
        formData.add("subjectDN", subjectDN);
        formData.add("isUserEnabled", String.valueOf(isUserEnabled));

        form.setFormData(formData);

        return form.createX509ConfirmPage();
    }

    private Response createResponseNoCertificate(AuthenticationFlowContext context, String errorMessage) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            List<FormMessage> errors = new LinkedList<>();

            errors.add(new FormMessage(errorMessage));
            form.setErrors(errors);
        }
        return form.createX509ConfirmPage();
    }

    private void dumpContainerAttributes(AuthenticationFlowContext context) {

        Map<String, Object> attributeNames = context.getSession().getAttributes();

        for (String name : attributeNames.keySet()) {
            logger.tracef("[X509ClientCertificateAuthenticator:dumpContainerAttributes] \"%s\"", name);
        }
    }

    private boolean userEnabled(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            return false;
        }
        return true;
    }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.clearUser();
            context.attempted();
            return;
        }
        if (context.getUser() != null) {
            context.success();
            return;
        }
        context.attempted();
    }
}
