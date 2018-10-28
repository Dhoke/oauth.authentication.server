package spring.boot.authentication.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private TokenStore tokenStore;

	// Outlines client creds I think TODO
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

		clients.inMemory() // Specifies that the client store will be in memory, could be LDAP
			.withClient("client") // 'User with whom we identify in the bank'... not sure what this means, possibly the auth manager in the server? TODO
				.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit") // Sets the different available auth types.. I think TODO
				.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT", "USER") // Specifieds roles / groups provided by the auth server
				.scopes("read", "write") // 'Scope of the service'... vague too TODO
				.autoApprove(true)
				.secret(passwordEncoder().encode("password")); // 'password of the client'... I should hope not

	}

	// Configures authentication manager and token storage to be used
	// by end points
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.tokenStore(tokenStore);		
	}
	
	@Bean
	public TokenStore tokenStore() {
		// Alternate: JdbcTokenStore
		return new InMemoryTokenStore();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
