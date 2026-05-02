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

    int sendTokenCode(String phoneNumber, String sourceAddr, TokenCodeType type, String kind);



}
