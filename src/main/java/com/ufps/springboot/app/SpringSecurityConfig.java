package com.ufps.springboot.app;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ufps.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.ufps.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.ufps.springboot.app.auth.handler.LoginSuccesHandler;
import com.ufps.springboot.app.auth.service.JWTService;
import com.ufps.springboot.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true )
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {


	@Autowired
	private LoginSuccesHandler loginHandler;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
	@Autowired
	private JWTService jwtService;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/","/css/**","/js/**","/img/**", "/listar**","/locale").permitAll()
		/*.antMatchers("/ver/**").hasAnyRole("USER")*/
		/*.antMatchers("/upload/**").hasAnyRole("USER")*/
		/*.antMatchers("/form/**").hasAnyRole("ADMIN")*/
		/*.antMatchers("/eliminar/**").hasAnyRole("ADMIN")*/
		/*.antMatchers("/factura/**").hasAnyRole("ADMIN")*/
		.anyRequest().authenticated()
		/*.and()
		.formLogin()
			.successHandler(loginHandler)
			.loginPage("/login")
		.permitAll()
		.and()
		.logout().permitAll()
		.and()
		.exceptionHandling().accessDeniedPage("/error_403")*/
		.and()
		.addFilter(new JWTAuthenticationFilter(authenticationManager(),jwtService))
		.addFilter(new JWTAuthorizationFilter(authenticationManager(),jwtService))
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}



	
	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception {
		
		build.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
		
		/*PasswordEncoder encoder = passwordEncoder;
		
		UserBuilder users = User.builder().passwordEncoder(encoder::encode);
		
		builder.inMemoryAuthentication()
		.withUser(users.username("admin").password("12345").roles("ADMIN", "USER"))
		.withUser(users.username("user").password("12345").roles("USER"));
		*/
	}
	
}
