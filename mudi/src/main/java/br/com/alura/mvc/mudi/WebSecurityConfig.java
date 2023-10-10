package br.com.alura.mvc.mudi;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Autowired
	DataSource dataSource;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
				.requestMatchers("/home/**").permitAll()
                .requestMatchers("/css/**").permitAll()
				.anyRequest().authenticated()
			)
			.formLogin((form) -> form
				.loginPage("/login")
				.defaultSuccessUrl("/usuario/pedido", true)
				.permitAll()
			)
			.logout((logout) -> {
				logout.logoutUrl("/logout")
				.logoutSuccessUrl("/home");
			})
			.csrf(csrf -> csrf.disable());

		return http.build();
	}

//	@Bean
//	UserDetailsManager users(DataSource dataSource) {
//		
////		UserDetails user = 
////				User.builder()
////				.username("joao")
////				.password(enconder.encode("joao"))
////				.roles("ADM")
////				.build();
//		JdbcUserDetailsManager users = new JdbcUserDetailsManager(this.dataSource);
////		users.createUser(user);
//		return users;
//	}
	
	@Bean
    public UserDetailsManager users(DataSource dataSource) {
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        return users;
    }
	
	@Bean
    public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(16);   
    } 

}
