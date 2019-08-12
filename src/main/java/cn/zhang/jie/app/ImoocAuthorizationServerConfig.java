package cn.zhang.jie.app;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import cn.zhang.jie.app.authentication.TokenStoreConfig;
import cn.zhang.jie.core.properties.OAuth2ClientProperties;
import cn.zhang.jie.core.properties.SercurityProperties;

@Configuration
//这个注解表示已经实现了一个认证服务器，认证服务器表示已经可以提供4中授权模式
@EnableAuthorizationServer
public class ImoocAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private UserDetailsService userDetailsService; 
	@Autowired
	private SercurityProperties sercurityProperties;
	@Autowired
	private TokenStore tokenStore;  
	@Autowired(required = false)
	private JwtAccessTokenConverter jwtAccessTokenConverter; 
	//可以添加自定义的增强器
	@Autowired(required = false)
	private TokenEnhancer jwtTokenEnhancer; 
	
	//TokenEndpoint 是处理 /oauth/token 的入口点
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		//令牌的默认存储是在内存中的，这里可以修改为存储到 Redis 中
		endpoints.tokenStore(tokenStore)
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService);
		if(jwtAccessTokenConverter != null && jwtTokenEnhancer != null) {
			//使用增强器链来处理,将多个增强器组合起来
			TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
			List<TokenEnhancer> enhancers = new ArrayList<>();
			enhancers.add(jwtTokenEnhancer);
			enhancers.add(jwtAccessTokenConverter);
			enhancerChain.setTokenEnhancers(enhancers);
			
			//可以更换令牌的实现
			endpoints
				.tokenEnhancer(enhancerChain)
				.accessTokenConverter(jwtAccessTokenConverter); 
		}
		//当重新发放令牌后，令牌的存储是在Redis中，具体格式是:
//		1) "client_id_to_access:imooc"
//		2) "refresh_auth:5aadb932-e8a4-49bc-b51b-2ca6f1668cfe"
//		3) "auth:87824ab6-020d-4c25-b99a-f564dd15a942"
//		4) "refresh_to_access:5aadb932-e8a4-49bc-b51b-2ca6f1668cfe"
//		5) "uname_to_access:imooc:admin"
//		6) "access:87824ab6-020d-4c25-b99a-f564dd15a942"
//		7) "auth_to_access:2c1140f87ac66cfaf0c9d06959fe9908"
//		8) "access_to_refresh:87824ab6-020d-4c25-b99a-f564dd15a942"
//		9) "refresh:5aadb932-e8a4-49bc-b51b-2ca6f1668cfe"
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		//配置给哪些客户端发放令牌
		InMemoryClientDetailsServiceBuilder builder = clients.inMemory();
		if(ArrayUtils.isNotEmpty(sercurityProperties.getOauth2().getClients())) {
			for(OAuth2ClientProperties config : sercurityProperties.getOauth2().getClients()) {
				builder.withClient(config.getClientId()).secret(config.getClientSecret())
				//令牌的有效时间
				.accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
				//支持哪些授权模式
				.authorizedGrantTypes("refresh_token", "password")
				.accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
				//可以指定refreshToken的有效时间，一般该值比如是一个星期等，长于 accessToken
				.refreshTokenValiditySeconds(2592000)
				//令牌的权限，如果请求参数中带了 scope 参数，那么一定是下面的三者之一
				.scopes("all", "read", "write");
			}
		}
	}
}

