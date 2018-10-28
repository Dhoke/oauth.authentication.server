package spring.boot.authentication.server;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// NOTE: Probably better to split these out... right?
@EnableResourceServer
@RestController
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	@RequestMapping("/public")
	public String publicEndpoint() {
		return "Welcome to the public page!";
	}
	
	@RequestMapping("/private")
	public String privateEndpoint() {
		return "Welcome to the private endpoint.";
	}
	
	@RequestMapping("/admin")
	public String adminOnlyEndpoint() {
		return "I hope you're an admin!";
	}
	
	/**
	 * Configure who has access to which endpoints. By default no one has any access
	 * though some of the article implies the line 'requestMatches().antMatchers("/url") is what 
	 * actually causes the block
	 */
	public void configure(HttpSecurity httpSecurityConfig) throws Exception {
		httpSecurityConfig
			.authorizeRequests().antMatchers("/oauth/token", "/oauth/authorize**", "/public").permitAll(); // Permit everyone to /public
		
		httpSecurityConfig
			.requestMatchers().antMatchers("/private") // For /private...
				.and().authorizeRequests().antMatchers("/private").access("hasRole('USER')") // ...alow any with role 'USER'
			.and().requestMatchers().antMatchers("/admin") // For /admin...
				.and().authorizeRequests().antMatchers("/admin").access("hasRole('ADMIN')"); // allow any with role 'ADMIN'
	}
}
