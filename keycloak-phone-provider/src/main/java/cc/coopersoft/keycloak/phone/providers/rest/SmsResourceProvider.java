package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.providers.spi.PhoneProvider;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class SmsResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    SmsResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        if (!session.getProvider(PhoneProvider.class).servesRealm()) {
            throw new NotFoundException();
        }
        return new SmsResource(session);
    }

    @Override
    public void close() {
    }
}