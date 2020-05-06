package com.algaworks.algafood.auth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    final PasswordEncoder passwordEncoder;
    final AuthenticationManager authenticationManager;
    final UserDetailsService userDetailsService;
    final JwtKeyStoreProperties keyStoreProperties;

    public AuthorizationServerConfig(PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager,
                                     UserDetailsService userDetailsService, JwtKeyStoreProperties keyStoreProperties) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.keyStoreProperties = keyStoreProperties;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("algafood-web")
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("write", "read")
                    .accessTokenValiditySeconds(60 * 60 * 6)

                .and()
                    .withClient("analytics")
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("write", "read")
                    .redirectUris("http://aplicacao-cliente")
                .and()
                    .withClient("webadmin")
                    .authorizedGrantTypes("implicit")
                    .scopes("write", "read")
                    .redirectUris("http://aplicacao-cliente");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        var tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(
                new JwtCustomClaimsTokenEnhancer(),
                jwtAccessTokenConverter()
        ));

        endpoints.authenticationManager(authenticationManager)
                 .userDetailsService(userDetailsService)
                 .reuseRefreshTokens(false)
                .tokenEnhancer(tokenEnhancerChain)
                 .accessTokenConverter(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        var accessTokenConverter = new JwtAccessTokenConverter();
        var jksResource = new ClassPathResource(keyStoreProperties.getPath());
        var keyStoreKeyFactory =  new KeyStoreKeyFactory(jksResource, keyStoreProperties.getPassword().toCharArray());
        var keyPair = keyStoreKeyFactory.getKeyPair(keyStoreProperties.getKeyPairAlias());

        accessTokenConverter.setKeyPair(keyPair);

        return accessTokenConverter;
    }
}