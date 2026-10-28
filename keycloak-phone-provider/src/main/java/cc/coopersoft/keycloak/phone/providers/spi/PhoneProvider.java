package cc.coopersoft.keycloak.phone.providers.spi;

import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import org.keycloak.provider.Provider;

import java.util.Optional;


public interface PhoneProvider extends Provider {

    //TODO on key login support
    //boolean Verification(String phoneNumber, String token);

    boolean isDuplicatePhoneAllowed();

    boolean validPhoneNumber();

    boolean compatibleMode();

    int otpExpires();

    Optional<String> canonicalizePhoneNumber();

    Optional<String> defaultPhoneRegion();

    Optional<String> phoneNumberRegex();

    int tokenExpiresIn();

    boolean allowAuthenticationCodeForNewUsers();

    /**
     * Optional domain appended to outbound SMS as the OTPA footer (@domain #code)
     * for OS-level domain-bound OTP autofill. Configure via
     * {@code --spi-phone-default-otp-domain=example.com}.
     */
    Optional<String> otpDomain();

    /**
     * Whether this realm sends codes at all. Configure via
     * {@code --spi-phone-default-realms=realm-a,realm-b}; unset serves every realm.
     */
    boolean servesRealm();

    /**
     * Whether a code may be texted to this number: never a premium-rate one, and with
     * {@code --spi-phone-default-allowed-regions=US,CA} only one of those regions.
     */
    boolean allowsDestination(String phoneNumber);

    default int sendTokenCode(String phoneNumber, String sourceAddr, TokenCodeType type, String kind) {
        return sendTokenCode(phoneNumber, sourceAddr, type, kind, true);
    }

    /**
     * With {@code deliver} false, everything a send does (realm and region checks, hourly limits,
     * reusing a pending code, storing a new one) except texting it: what a number no user holds is
     * answered with, so its answers can't be told from a real send's.
     */
    int sendTokenCode(String phoneNumber, String sourceAddr, TokenCodeType type, String kind, boolean deliver);



}
