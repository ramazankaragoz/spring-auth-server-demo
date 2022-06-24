package com.demo.authzdemo.config;

import com.demo.authzdemo.config.authentication.CustomOAuth2UserService;
import com.demo.authzdemo.config.authentication.UserIdentityAuthenticationSuccessHandler;
import com.demo.authzdemo.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final CustomOAuth2UserService oauthUserService;
    private final UserService userService;

    public WebSecurityConfig(CustomOAuth2UserService oauthUserService, UserService userService) {
        this.oauthUserService = oauthUserService;
        this.userService = userService;
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/assets/**", "/webjars/**", "/h2-console/**", "/error**", "/error/**");
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {


        http.cors().and()
                .csrf().disable()
                .headers()
                .and()
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().authenticated()
                )
                .oauth2Login().userInfoEndpoint()
                .userService(oauthUserService)
                .and().successHandler(new UserIdentityAuthenticationSuccessHandler(userService));

       /*http.cors().and()
                .csrf().disable()
                .headers()
                .and()
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());*/

        return http.build();

    }

    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123456")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }


}
