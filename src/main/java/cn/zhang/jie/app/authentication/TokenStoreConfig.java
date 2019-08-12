package cn.zhang.jie.app.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import cn.zhang.jie.core.properties.SercurityProperties;

/**
 * $ 负责令牌的存取
 * @author admin
 *
 */

@Configuration
public class TokenStoreConfig {

	@Autowired
	private RedisConnectionFactory redisConnectionFactory;
	
	@Bean
	@ConditionalOnProperty(prefix = "imooc.security.oauth2", name = "storeType", havingValue = "redis")
	public TokenStore redisTokenStore() {
		return new RedisTokenStore(redisConnectionFactory);
	}
	
	@Configuration
	//参数一，检查配置文件的前缀
	//参数二，表示参数/属性的名字
	//参数三，当参数/属性的值是 jwt 时，这个类里所有的配置都会生效
	//参数四，当配置文件里没有以 imooc.security.oauth2 为前缀的配置时，下面这些配置也是生效的
	@ConditionalOnProperty(prefix = "imooc.security.oauth2", name = "storeType", havingValue = "jwt", matchIfMissing = true)
	public static class JwtTokenConfig {
		@Autowired
		private SercurityProperties sercurityProperties;
		
		@Bean
		public TokenStore jwtTokenStore() {
			return new JwtTokenStore(jhwtAccessTokenConverter());
		}
		
		@Bean
		public JwtAccessTokenConverter jhwtAccessTokenConverter() {
			JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
			//使用指定的秘钥签名JWT
			accessTokenConverter.setSigningKey(sercurityProperties.getOauth2().getJwtSigningKey());
			return accessTokenConverter;
		}  
		
		@Bean
		@ConditionalOnMissingBean(name = "jwtTokenEnhancer")
		public TokenEnhancer jwtTokenEnhancer() {
			//这里可以往 jwt 中添加内容
			return new ImoocJwtTokenEnhancer();
		}
	} 
}
