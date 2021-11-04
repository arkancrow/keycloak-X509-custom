package be.zorgi.keycloak.spi.authentication;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class X509CustomClientCertificateAuthenticatorFactory extends AbstractX509ClientCertificateAuthenticatorFactory {

    public static final String PROVIDER_ID = "zorgi-auth-x509";
    public static final X509CustomClientCertificateAuthenticator SINGLETON =
            new X509CustomClientCertificateAuthenticator();

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    @Override
    public String getHelpText() {
        return "Zorgi - Custom X509 authentication.";
    }

    @Override
    public String getDisplayType() {
        return "Zorgi - X509/Validate Username Form";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }


    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
