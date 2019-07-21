package cn.zhang.jie.app;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppSecurityConfig {

	@Bean
	//加上该配置后，就启用了密码加解密的功能
	public PasswordEncoder passwordEncoder() {
		//这里也可以返回自定义的加解密，比如 md5的方式
		return new BCryptPasswordEncoder();
	} 
}
