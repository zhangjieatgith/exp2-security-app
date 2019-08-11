package cn.zhang.jie.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.zhang.jie.core.properties.LoginType;
import cn.zhang.jie.core.properties.SercurityProperties;
import cn.zhang.jie.core.validate.code.ValidateCodeSecurityConfig;

@Component("imoocAuthenticationSuccessHandler")
public class ImoocAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private SercurityProperties sercurityProperties;
	@Autowired
	private ClientDetailsService clientDetailsService; 
	@Autowired
	private AuthorizationServerTokenServices authorizationServerTokenServices; 
	
	@SuppressWarnings("unchecked")
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		logger.info("登录成功");
		
		//这是请求头中将 ClientId 和 ClientSecret 进行Base64编码的请求头信息
		String header = request.getHeader("Authorization");
		if (header == null || !header.startsWith("Basic ")) {
			throw new UnapprovedClientAuthenticationException("请求头中没有Client信息");
		}
		try {
			String[] tokens = extractAndDecodeHeader(header, request);
			assert tokens.length == 2;
			//解析请求头中的Base64编码的Authentication属性，并获取Client的信息
			String clientId = tokens[0];
			String clientSecret = tokens[1];
			//构建 ClientDetails 
			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
			
			//表示无法获取第三方英勇的信息，抛出异常
			if(clientDetails == null) {
				throw new UnapprovedClientAuthenticationException("clientid 对应的配置信息不存在" + clientId);
				//比对请求中的密码和系统中的密码是否一致
			}else if(!StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
				throw new UnapprovedClientAuthenticationException("client secret 不匹配 " + clientId);
			}
			
			//参数一表示不同的授权模式，需要的参数信息不一样。参数四表示使用哪一种授权模式
			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(), "custom");
			OAuth2Request oauth2Request = tokenRequest.createOAuth2Request(clientDetails);
			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oauth2Request, authentication);
			//最终目的是生成令牌
			OAuth2AccessToken oauth2AccessToken = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(oauth2AccessToken));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//抽取和解析请求头中的信息
	private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
			throws IOException {

		byte[] base64Token = header.substring(6).getBytes("UTF-8");
		byte[] decoded;
		try {
			decoded = Base64.decode(base64Token);
		}
		catch (IllegalArgumentException e) {
			throw new BadCredentialsException(
					"Failed to decode basic authentication token");
		}

		String token = new String(decoded, "UTF-8");

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		return new String[] { token.substring(0, delim), token.substring(delim + 1) };
	}
}
