package cn.zhang.jie.app.authentication;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import cn.zhang.jie.core.properties.SercurityProperties;
import cn.zhang.jie.core.validate.code.ValidateCode;
import cn.zhang.jie.core.validate.code.ValidateCodeException;
import cn.zhang.jie.core.validate.code.ValidateCodeProcessor;
import cn.zhang.jie.core.validate.code.ValidateCodeType;

/**
 * $ 区别于 broswer 版本，这里不使用 session 来存取验证码，而是使用外部存储，如Redis
 * 
 * @author admin
 *
 */
public class SmsCodeAppFilter extends OncePerRequestFilter implements InitializingBean{

	private AuthenticationFailureHandler authenticationFailureHandler;
	
	private ValidateCodeRepository validateCodeRepository;
	
	//存放配置的拦截URL
	private Set<String> urls = new HashSet<>();

	private SercurityProperties sercurityProperties;
	
	private AntPathMatcher pathMatcher = new AntPathMatcher();
	
	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		String [] configUrls = StringUtils.splitByWholeSeparatorPreserveAllTokens(sercurityProperties.getCode().getSms().getUrl(), ",");
		for(String url : configUrls) {
			//这里是配置的url
			urls.add(url);
		}
		urls.add("/authentication/mobile");	
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		boolean action = false;
		for(String url : urls) {
			if(pathMatcher.match(url, request.getRequestURI())) {
				action = true;
			}
		}
		if(action) {
			try {
				validate(new ServletWebRequest(request));
			} catch (ValidateCodeException e) {
				authenticationFailureHandler.onAuthenticationFailure(request, response, e);
				return;
			}
		}
		filterChain.doFilter(request, response);
	}

	private void validate(ServletWebRequest request) throws ServletRequestBindingException {
		ValidateCode codeInSession = validateCodeRepository.get(request, ValidateCodeType.SMS);
		String codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(), "smsCode");
		if(StringUtils.isBlank(codeInRequest)) {
			throw new ValidateCodeException("验证码的值不能为空");
		}
		if(codeInSession == null) {
			throw new ValidateCodeException("验证码不存在");
		}
		if(codeInSession.isExpired()) {
			validateCodeRepository.remove(request, ValidateCodeType.SMS);
			throw new ValidateCodeException("验证码已过期");
		}
		if(!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
			throw new ValidateCodeException("验证码不匹配");
		}
		validateCodeRepository.remove(request, ValidateCodeType.SMS);
	}

	public AuthenticationFailureHandler getAuthenticationFailureHandler() {
		return authenticationFailureHandler;
	}
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		this.authenticationFailureHandler = authenticationFailureHandler;
	}
	public Set<String> getUrls() {
		return urls;
	}
	public void setUrls(Set<String> urls) {
		this.urls = urls;
	}
	public SercurityProperties getSercurityProperties() {
		return sercurityProperties;
	}
	public void setSercurityProperties(SercurityProperties sercurityProperties) {
		this.sercurityProperties = sercurityProperties;
	}

	public ValidateCodeRepository getValidateCodeRepository() {
		return validateCodeRepository;
	}
	public void setValidateCodeRepository(ValidateCodeRepository validateCodeRepository) {
		this.validateCodeRepository = validateCodeRepository;
	}
}
