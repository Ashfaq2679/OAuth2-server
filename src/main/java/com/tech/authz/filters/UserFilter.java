package com.tech.authz.filters;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tech.authz.model.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * This filter will extract value of custom header and set it as User's
 * loginId. name of header is configurable
 * 
 * @author ashfaq
 *
 */
@Component
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
public class UserFilter extends OncePerRequestFilter {
	
	
	@Value("${config.authserver.header.login-id:X_LOGIN_ID}")
	private String headerName;
	
	@Autowired
	private User user;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		user.setLoginId(request.getHeader(headerName));
		logger.info("USER-LOGIN-ID:" + user.getLoginId());
		filterChain.doFilter(request, response);
	}

}
