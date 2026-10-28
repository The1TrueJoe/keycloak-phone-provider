package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.common.OptionalUtils;
import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.MessageSenderService;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneProvider;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServiceUnavailableException;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.validation.Validation;

import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultPhoneProvider implements PhoneProvider {

    private static final Logger logger = Logger.getLogger(DefaultPhoneProvider.class);
    private final KeycloakSession session;
    private final String service;
    private final int tokenExpiresIn;
    private final int targetHourMaximum;
    private final int sourceHourMaximum;

    private final Scope config;

    DefaultPhoneProvider(KeycloakSession session, Scope config) {
        this.session = session;
        this.config = config;

        this.service = session.listProviderIds(MessageSenderService.class)
                .stream().filter(s -> s.equals(config.get("service")))
                .findFirst().orElse(
                        session.listProviderIds(MessageSenderService.class)
                                .stream().findFirst().orElse(null));

        if (Validation.isBlank(this.service)) {
            logger.error("Message sender service provider not found!");
        }

        if (Validation.isBlank(config.get("service")))
            logger.debug("No message sender service provider specified! Default provider'" +
                    this.service
                    + "' will be used. You can use keycloak start param '--spi-phone-default-service' to specify a different one. ");

        logger.debug("SMS sender provider '" + this.service + "' will be used!");

        this.tokenExpiresIn = config.getInt("tokenExpiresIn", 60);
        this.targetHourMaximum = config.getInt("targetHourMaximum", 3);
        this.sourceHourMaximum = config.getInt("sourceHourMaximum", 10);
    }

    @Override
    public void close() {
    }

    private PhoneVerificationCodeProvider getTokenCodeService() {
        return session.getProvider(PhoneVerificationCodeProvider.class);
    }

    private String getRealmName() {
        return session.getContext().getRealm().getName();
    }

    private Optional<String> getStringConfigValue(String configName) {
        return OptionalUtils.ofBlank(OptionalUtils.ofBlank(config.get(getRealmName() + "-" + configName))
                .orElse(config.get(configName)));
    }

    private boolean getBooleanConfigValue(String configName, boolean defaultValue) {
        Boolean result = config.getBoolean(getRealmName() + "-" + configName, null);
        if (result == null) {
            result = config.getBoolean(configName, defaultValue);
        }
        return result;
    }

    @Override
    public boolean isDuplicatePhoneAllowed() {
        return getBooleanConfigValue("duplicate-phone", false);
    }

    @Override
    public boolean validPhoneNumber() {
        return getBooleanConfigValue("valid-phone", true);
    }

    @Override
    public boolean compatibleMode() {
        return getBooleanConfigValue("compatible", false);
    }

    @Override
    public int otpExpires() {
        return getStringConfigValue("otp-expires").map(Integer::valueOf).orElse(60 * 60);
    }

    @Override
    public Optional<String> canonicalizePhoneNumber() {
        return getStringConfigValue("canonicalize-phone-numbers");
    }

    @Override
    public Optional<String> defaultPhoneRegion() {
        return getStringConfigValue("phone-default-region");
    }

    @Override
    public Optional<String> phoneNumberRegex() {
        return getStringConfigValue("number-regex");
    }

    @Override
    public int tokenExpiresIn() {
        return tokenExpiresIn;
    }

    @Override
    public boolean allowAuthenticationCodeForNewUsers() {
        return getBooleanConfigValue("allow-authentication-code-for-new-users", false);
    }

    @Override
    public Optional<String> otpDomain() {
        return getStringConfigValue("otp-domain");
    }

    @Override
    public boolean servesRealm() {
        Set<String> realms = csv(config.get("realms"));
        return realms.isEmpty() || realms.contains(getRealmName().toUpperCase(Locale.ROOT));
    }

    @Override
    public boolean allowsDestination(String phoneNumber) {
        return allowedDestination(phoneNumber, Utils.defaultRegion(session),
                csv(getStringConfigValue("allowed-regions").orElse(null)));
    }

    static boolean allowedDestination(String phoneNumber, String defaultRegion, Set<String> allowedRegions) {
        PhoneNumberUtil util = PhoneNumberUtil.getInstance();
        try {
            var number = util.parse(phoneNumber, defaultRegion);
            if (util.getNumberType(number) == PhoneNumberType.PREMIUM_RATE) return false;
            return allowedRegions.isEmpty() || allowedRegions.contains(util.getRegionCodeForNumber(number));
        } catch (NumberParseException e) {
            return false;
        }
    }

    /** The upper-cased, non-blank entries of a comma-separated value; empty when unset. */
    static Set<String> csv(String value) {
        if (value == null) return Set.of();
        return Arrays.stream(value.split(","))
                .map(s -> s.trim().toUpperCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    @Override
    public int sendTokenCode(String phoneNumber, String sourceAddr, TokenCodeType type, String kind, boolean deliver) {

        logger.debug("send code to:" + phoneNumber);

        if (!servesRealm()) {
            throw new NotFoundException();
        }
        if (!allowsDestination(phoneNumber)) {
            throw new BadRequestException("Phone number is not supported");
        }

        // A pending code is reused before any limit is taken, so asking again within its lifetime is free.
        TokenCodeRepresentation ongoing = getTokenCodeService().ongoingProcess(phoneNumber, type);
        if (ongoing != null) {
            logger.debug(String.format("No need of sending a new %s code for %s", type.label, phoneNumber));
            return (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
        }

        if (getTokenCodeService().isAbusing(phoneNumber, type, sourceAddr, sourceHourMaximum, targetHourMaximum)) {
            throw new ForbiddenException("You requested the maximum number of messages the last hour");
        }

        TokenCodeRepresentation token = TokenCodeRepresentation.forPhoneNumber(phoneNumber);

        if (!deliver) {
            // ponytail: the stored code is never texted, so a user who gets this number within its
            // lifetime waits it out (tokenExpiresIn) before a real code goes out.
            getTokenCodeService().persistCode(token, type, tokenExpiresIn);
            return tokenExpiresIn;
        }

        try {
            session.getProvider(MessageSenderService.class, service).sendSmsMessage(type, phoneNumber, token.getCode(),
                    tokenExpiresIn, kind);
            getTokenCodeService().persistCode(token, type, tokenExpiresIn);

            logger.debug(String.format("Sent %s code to %s over %s", type.label, phoneNumber, service));

        } catch (MessageSendException e) {

            logger.error(String.format("Message sending to %s failed with %s: %s",
                    phoneNumber, e.getErrorCode(), e.getErrorMessage()));
            throw new ServiceUnavailableException("Internal server error");
        }

        return tokenExpiresIn;
    }

}
