package cn.zhang.jie.app.authentication;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class ImoocJwtTokenEnhancer implements TokenEnhancer {

	//将自定义的信息加入到 access_token 中
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		//保存额外信息到JWT中
		Map<String,Object> info = new HashMap<>();
		info.put("company", "imooc");
		info.put("content", "nothing...");
		//设置附加信息
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
		return accessToken;
	}
}
