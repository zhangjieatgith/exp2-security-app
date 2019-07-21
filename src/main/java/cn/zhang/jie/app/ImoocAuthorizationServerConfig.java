package cn.zhang.jie.app;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
//这个注解表示已经实现了一个认证服务器，认证服务器表示已经可以提供4中授权模式
@EnableAuthorizationServer
public class ImoocAuthorizationServerConfig {

	
}
