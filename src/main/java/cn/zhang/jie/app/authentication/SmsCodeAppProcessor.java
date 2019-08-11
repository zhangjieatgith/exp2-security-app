package cn.zhang.jie.app.authentication;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import cn.zhang.jie.core.validate.code.SmsCodeGenerator;
import cn.zhang.jie.core.validate.code.ValidateCodeException;
import cn.zhang.jie.core.validate.code.ValidateCodeType;
import cn.zhang.jie.core.validate.code.sms.SmsCode;
import cn.zhang.jie.core.validate.code.sms.SmsCodeSender;

@Component("smsCodeAppProcessor")
public class SmsCodeAppProcessor {
	
	@Autowired
	private ValidateCodeRepository validateCodeRepository;
	@Autowired
	private SmsCodeGenerator smsCodeGenerator;
	@Autowired
	private SmsCodeSender smsCodeSender;
	
	public void create(ServletWebRequest request) throws Exception {
		SmsCode validateCode = generate(request);
		save(request, validateCode);
		send(request, validateCode);
	}
	
	public void save(ServletWebRequest request,SmsCode code) {
		//这里是为了不将图片保存到session中，而是仅仅将图形校验码保存到session中
		validateCodeRepository.save(request, code, ValidateCodeType.SMS);
	}
	
	public void validate(ServletWebRequest request) throws ValidateCodeException{
		SmsCode code = (SmsCode) validateCodeRepository.get(request, ValidateCodeType.SMS);
		String codeParam;
		try {
			codeParam=ServletRequestUtils.getStringParameter(request.getRequest(), "smsCode");
		} catch (ServletRequestBindingException e) {
			throw new ValidateCodeException("获取验证码的值失败");
		}
		if(StringUtils.isBlank(codeParam)){
			throw new ValidateCodeException("验证码不能为空");
		}
		if(code==null){
			throw new ValidateCodeException("验证码不存在");
		}
		if(code.isExpired()){
			validateCodeRepository.remove(request, ValidateCodeType.SMS);
			throw new ValidateCodeException("验证码已失效");
		}
		if(!StringUtils.equals(codeParam, code.getCode())){
			throw new ValidateCodeException("验证码不匹配");
		}
	}
	
	
	public String getGeneratorType(ServletWebRequest request){
		return StringUtils.substringAfter(request.getRequest().getRequestURI(), "/code/");
	}
	
	public String getSessionKey(ServletWebRequest request){
		return buildKey(request, ValidateCodeType.SMS);
	}
	
	//生成校验码
	private SmsCode generate(ServletWebRequest request) {
		return (SmsCode) smsCodeGenerator.generate(request);
	}
	
	//发送校验码，由子类实现
	public void send(ServletWebRequest request,SmsCode code) {
		String mobile;
		try {
			mobile = ServletRequestUtils.getRequiredStringParameter(request.getRequest(), "mobile");
			smsCodeSender.send(mobile, code.getCode());
		} catch (ServletRequestBindingException e) {
			e.printStackTrace();
		}
	}
	
	private String buildKey(ServletWebRequest request, ValidateCodeType type) {
		String deviceId = request.getHeader("deviceId");
		if(StringUtils.isBlank(deviceId)) {
			throw new RuntimeException("请在请求头中携带 deviceId 参数");
		}
		return "code:" + type.toString().toLowerCase() + ":" + deviceId;
	}

	public ValidateCodeRepository getValidateCodeRepository() {
		return validateCodeRepository;
	}

	public void setValidateCodeRepository(ValidateCodeRepository validateCodeRepository) {
		this.validateCodeRepository = validateCodeRepository;
	}

	public SmsCodeGenerator getSmsCodeGenerator() {
		return smsCodeGenerator;
	}

	public void setSmsCodeGenerator(SmsCodeGenerator smsCodeGenerator) {
		this.smsCodeGenerator = smsCodeGenerator;
	}

	public SmsCodeSender getSmsCodeSender() {
		return smsCodeSender;
	}

	public void setSmsCodeSender(SmsCodeSender smsCodeSender) {
		this.smsCodeSender = smsCodeSender;
	}
}
