package cn.zhang.jie.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.zhang.jie.core.properties.LoginType;
import cn.zhang.jie.core.properties.SercurityProperties;

@Component("imoocAuthenticationSuccessHandler")
public class ImoocAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private SercurityProperties sercurityProperties; 
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		logger.info("登录成功");
		if(LoginType.JSON.equals(sercurityProperties.getBrowser().getLoginType())) {
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(authentication));
		}else {
			//否则使用父类的处理方式，即跳转
			super.onAuthenticationSuccess(request, response, authentication);
		}
	}
}
