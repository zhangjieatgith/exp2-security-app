package cn.zhang.jie.app.authentication;

import org.springframework.web.context.request.ServletWebRequest;

import cn.zhang.jie.core.validate.code.ValidateCode;
import cn.zhang.jie.core.validate.code.ValidateCodeType;

/**
 * $ 针对app的验证码处理，不能直接放在 session 中，而是应该放在 外部存储中，例如 Redis
 * @author admin
 *
 */
public interface ValidateCodeRepository {
	//保存验证码
	void save(ServletWebRequest request, ValidateCode code, ValidateCodeType validateCodeType);
	//获取验证码
	ValidateCode get(ServletWebRequest request, ValidateCodeType validateCodeType);
	//移除验证码
	void remove(ServletWebRequest request, ValidateCodeType codeType);
}
