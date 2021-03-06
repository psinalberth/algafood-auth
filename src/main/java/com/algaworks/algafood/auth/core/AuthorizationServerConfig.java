package com.algaworks.algafood.auth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    final AuthenticationManager authenticationManager;
    final UserDetailsService userDetailsService;
    final JwtKeyStoreProperties keyStoreProperties;
    final DataSource dataSource;

    public AuthorizationServerConfig(AuthenticationManager authenticationManager,
                                     UserDetailsService userDetailsService, JwtKeyStoreProperties keyStoreProperties,
                                     DataSource dataSource) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.keyStoreProperties = keyStoreProperties;
        this.dataSource = dataSource;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .jdbc(dataSource);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()")
                .allowFormAuthenticationForClients();
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
                 .accessTokenConverter(jwtAccessTokenConverter())
                 .tokenEnhancer(tokenEnhancerChain)
                 .approvalStore(approvalStore(endpoints.getTokenStore()))
                 .tokenGranter(tokenGranter(endpoints));
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

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }

    private ApprovalStore approvalStore(TokenStore tokenStore) {
        var approvalStore = new TokenApprovalStore();
        approvalStore.setTokenStore(tokenStore);

        return approvalStore;
    }
}