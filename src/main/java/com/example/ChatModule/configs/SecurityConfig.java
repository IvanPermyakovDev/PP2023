package com.example.ChatModule.configs;

import com.example.ChatModule.security.LogoutService;
import com.example.ChatModule.security.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    private UserDetailServiceImpl userDetailService;
    @Autowired
    private JwtRequestFilter jwtRequestFilter;
    @Autowired
    private LogoutService logoutService;
    @Bean
    public SecurityFilterChain filterchian(HttpSecurity http) throws Exception{
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())

                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
                   .loginPage("/sign").permitAll())

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/register/**").anonymous()
                        .requestMatchers("/auth/**").anonymous()
                        .requestMatchers("/sign").permitAll()
                        .requestMatchers(HttpMethod.GET,"/grad_lk").authenticated()
                        .requestMatchers("/grad/**").authenticated()
                        .requestMatchers("/rep/**").authenticated()
                        .requestMatchers("/doc/**").authenticated()
                        .requestMatchers("/EP/**").authenticated()
                        .requestMatchers("/faculty/**").authenticated()
                        .requestMatchers("/university/**").authenticated()
                        .anyRequest().permitAll()

                )
                .authenticationProvider(daoAuthenticationProvider())

                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendRedirect("/sign"))
                )
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)

                .logout(logout ->
                        logout
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutUrl("/logout")
                                .logoutSuccessUrl("/sign")
                );

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailService);
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
