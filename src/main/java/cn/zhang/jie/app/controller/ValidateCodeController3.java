package cn.zhang.jie.app.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import cn.zhang.jie.app.authentication.SmsCodeAppProcessor;

@RestController
public class ValidateCodeController3 {

	@Autowired
	private SmsCodeAppProcessor smsCodeAppProcessor;
	
	@GetMapping("/code/newSms")
	public void createCode(HttpServletRequest request, HttpServletResponse response) throws Exception {
		smsCodeAppProcessor.create(new ServletWebRequest(request));
	}
}
