package cn.zhang.jie.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.social.security.SpringSocialConfigurer;

import cn.zhang.jie.app.authentication.ImoocAuthenticationFailHandler;
import cn.zhang.jie.app.authentication.ImoocAuthenticationSuccessHandler;
import cn.zhang.jie.app.authentication.SmsCodeAppFilter;
import cn.zhang.jie.app.authentication.ValidateCodeRepository;
import cn.zhang.jie.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import cn.zhang.jie.core.properties.SercurityProperties;
import cn.zhang.jie.core.validate.code.SmsCodeFilter;
import cn.zhang.jie.core.validate.code.ValidateCodeFilter;
import cn.zhang.jie.core.validate.code.ValidateCodeSecurityConfig;
import cn.zhang.jie.core.validate.code.constants.SecurityConstants;

/**
 * $ 测试流程
 * 	0.用户名 + 密码的访问方式
 * 	1.访问路径 http://127.0.0.1:8040/authentication/form 获取access_token。请求头中使用了 authentication(Basic aW1vb2M6aW1vb2NzZWNyZXQ=) 和 Content-Type(application/x-www-form-urlencoded)，此时会生成标准OAuth协议的响应信息
 * 		{
    		"access_token": "e02b57d3-94a8-4f53-b443-c699f28428a0",
    		"token_type": "bearer",
    		"refresh_token": "d4b683d5-1ddd-4198-ab0c-e652ce259d71",
    		"expires_in": 43199
		}
	2.使用获取的 access_token 访问某个rest服务，例如 : http://localhost:8040/user/me，在请求头使用了 Authorization(bearer e02b57d3-94a8-4f53-b443-c699f28428a0)，它使用了上一步生成的 access_token 
 * 	
 * 
 * @author admin
 *
 */

@Configuration
//表示启用资源服务器
@EnableResourceServer
public class ImoocResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Autowired
	private ImoocAuthenticationSuccessHandler imoocAuthenticationSuccessHandler;
	@Autowired
	private ImoocAuthenticationFailHandler imoocAuthenticationFailHandler; 
	@Autowired
	private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig; 
	@Autowired
	private SpringSocialConfigurer imoocSocialSecurityConfig;
	@Autowired
	private SercurityProperties sercurityProperties;
	@Autowired
	private ValidateCodeRepository ValidateCodeRepository;
	
	//访问资源服务时的安全配置
	@Override
	public void configure(HttpSecurity http) throws Exception {
		
//		SmsCodeFilter smsCodeFilter = new SmsCodeFilter();
//		smsCodeFilter.setAuthenticationFailureHandler(imoocAuthenticationFailHandler);
//		smsCodeFilter.setSercurityProperties(sercurityProperties);
//		smsCodeFilter.afterPropertiesSet();
		
		SmsCodeAppFilter smsCodeFilter = new SmsCodeAppFilter();
		smsCodeFilter.setAuthenticationFailureHandler(imoocAuthenticationFailHandler);
		smsCodeFilter.setValidateCodeRepository(ValidateCodeRepository);;
		smsCodeFilter.setSercurityProperties(sercurityProperties);
		smsCodeFilter.afterPropertiesSet();
		
		
		http.formLogin()
			.loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
			.loginProcessingUrl(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_FORM)
			.successHandler(imoocAuthenticationSuccessHandler)
			.failureHandler(imoocAuthenticationFailHandler);
		http.addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class)
			.apply(smsCodeAuthenticationSecurityConfig).and()
			.apply(imoocSocialSecurityConfig).and()
			.authorizeRequests().antMatchers(
				SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
				SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
				sercurityProperties.getBrowser().getLoginPage(),
				SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*",
				sercurityProperties.getBrowser().getSignUpUrl(),
				sercurityProperties.getBrowser().getSignOutUrl(),
				"/user/regist")
			.permitAll()
			.anyRequest()
			.authenticated()
			.and()
		.csrf().disable();
	}
}
