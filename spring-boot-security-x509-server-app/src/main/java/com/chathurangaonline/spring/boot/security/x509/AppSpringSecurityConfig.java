package com.chathurangaonline.spring.boot.security.x509;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.User;

@EnableWebSecurity
public class AppSpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }

    /**
     * subjectPrincipalRegex("CN=(.*?)(?:,|$)") :- The regular expression used to extract a username from the client certificate’s subject name.
     * (CN value of the client certificate)
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().antMatchers("/actuator/**").permitAll().and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
    }





    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public User loadUserByUsername(String username) {
                if (username != null) {
                    return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
                }
                return null;
            }
        };
    }
}
