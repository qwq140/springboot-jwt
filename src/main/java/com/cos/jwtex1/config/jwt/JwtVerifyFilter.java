package com.cos.jwtex1.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.jwtex1.config.auth.PrincipalDetails;
import com.cos.jwtex1.domain.User;
import com.cos.jwtex1.domain.UserRepository;

// DI 안댐 JwtVerifyFilter는 컴포넌트가 아니기 때문에
public class JwtVerifyFilter extends BasicAuthenticationFilter{

	private final UserRepository userRepository;
	private final AuthenticationManager authenticationManager;
	
	public JwtVerifyFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		
		this.authenticationManager =authenticationManager;
		this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader("Authorization");
		System.out.println(header);
		
		if(header == null || header.startsWith("Bearer")) {
			chain.doFilter(request, response);
		}
		
		String token = request.getHeader("Authorization").replace("Bearer", "");
		
		// 검증1 (헤더+페이로드+ HAMAC512 해쉬한 값) == SIGNATURE
		// 검증2 (만료시간 확인)
		DecodedJWT dJwt =  JWT.require(Algorithm.HMAC512("홍길동")).build().verify(token);
		Long userId = dJwt.getClaim("userId").asLong();
		
		User userEntity = userRepository.findById(userId).get();
		PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
		
		Authentication authentication =
				new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), principalDetails.getPassword(),principalDetails.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		System.out.println("권한이나 인증이 필요한 요청이 들어옴");
		chain.doFilter(request, response);
	}

}
