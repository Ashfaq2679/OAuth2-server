package com.tech.authz.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.context.request.RequestContextListener;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.tech.authz.model.User;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
public class AuthServerConfig {
	private static final int KEY_SIZE = 2048;

	private static final String ALGORITHM_RSA = "RSA";

	private static final String SCOPE = "READ";

	private static final String ISSUER_URL = "http://localhost:9091";
	
	@Autowired
	private User user;

	@Value("${config.authserver.access-token.ttl:2}")
	private long accessTokenInMinutes;

	//TODO: adjust yml file to set list
	@Value("${config.authserver.client-id:postman}")
	private String clientId;

	@Value("${config.authserver.client-secret:postman-secret}")
	private String clientSecret;

	@Bean("user")
	@RequestScope
	User getUser() {
		return new User();
	}

	@Bean
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient postmanClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(clientId)
				.clientSecret(bcryptEncoder().encode(clientSecret))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope(SCOPE)
				.tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
						.accessTokenTimeToLive(Duration.ofMinutes(accessTokenInMinutes)).build())
				.build();
		
		RegisteredClient apiClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("api-client")
				.clientSecret(bcryptEncoder().encode("api-clientSecret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER).scope(SCOPE)
				.tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
						.accessTokenTimeToLive(Duration.ofMinutes(accessTokenInMinutes)).build())
				.build();
		List<RegisteredClient> clientList = new ArrayList<>();
		clientList.add(postmanClient);
		clientList.add(apiClient);
		
		return new InMemoryRegisteredClientRepository(clientList);
	}

	@Bean
	PasswordEncoder bcryptEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * We can either XML configuration or Java configuration to wire the filter into
	 * the Spring Security configuration. We can register the filter
	 * programmatically by creating a SecurityFilterChain bean. For example, it
	 * works with the addFilterAfter method on an HttpSecurity instance:
	 * springSecurityFilterChain, is responsible for all the security (protecting
	 * the application URLs, validating submitted username and passwords,
	 * redirecting to the log in form, and so on) within your application.
	 * 
	 * @param security
	 * @return
	 * @throws Exception
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(security);

		security.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

		return security.formLogin(Customizer.withDefaults()).build();
	}

	/**
	 * This is must if we want to use beans with request scope.
	 * 
	 * @return
	 */
	@Bean
	RequestContextListener requestContextListener() {
		return new RequestContextListener();
	}

	/**
	 * We don't need interactive flows
	 * 
	 * @return
	 */
	@Bean
	ClientSettings clientSettings() {
		return ClientSettings.builder().requireAuthorizationConsent(false).requireProofKey(false).build();
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer(ISSUER_URL).build();
	}

	@Bean
	JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);

		return (jwkSelector, secutityContext) -> jwkSelector.select(jwkSet);
	}

	private RSAKey generateRsa() throws NoSuchAlgorithmException {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
		keyPairGenerator.initialize(KEY_SIZE);
		return keyPairGenerator.generateKeyPair();
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {

		return context -> findClaims(context, user.getLoginId());
	}

	private void findClaims(JwtEncodingContext context, String loginId) {
		context.getClaims().claim("loginId", loginId);
		context.getClaims().claim("role", "ADMIN");
	}
}
