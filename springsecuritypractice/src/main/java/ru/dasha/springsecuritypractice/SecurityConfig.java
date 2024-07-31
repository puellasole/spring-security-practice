package ru.dasha.springsecuritypractice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	
	private final UserDetailsService userDetailsService;
	
	@Autowired
	SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService){
		this.userDetailsService = userDetailsService;
	}
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
	      .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
	              authorizationManagerRequestMatcherRegistry
	                      .requestMatchers("/").permitAll()
	                      .anyRequest().authenticated())
	      .formLogin(form -> form.loginPage("/auth/login").permitAll().defaultSuccessUrl("/auth/success", true))
	      .logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
	    		  .invalidateHttpSession(true)
	    		  .clearAuthentication(true)
	    		  .deleteCookies("JSESSIONID")
	    		  .logoutSuccessUrl("/auth/login"));
	      
	      
	      //.httpBasic(Customizer.withDefaults());
	      
        return http.build();
    }

	@Bean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
	    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
	    manager.createUser(User.withUsername("user")
	      .password(passwordEncoder().encode("user"))
	      .authorities(Role.USER.getAuthorities())
	      .build());
	    manager.createUser(User.withUsername("admin")
	      .password(passwordEncoder().encode("admin"))
	      .authorities(Role.ADMIN.getAuthorities())
	      .build());
	    return manager;
	}
	
	@Bean
	protected DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		return daoAuthenticationProvider;
	}
	
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
	
}
