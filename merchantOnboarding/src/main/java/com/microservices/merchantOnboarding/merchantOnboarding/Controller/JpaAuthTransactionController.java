package com.microservices.merchantOnboarding.merchantOnboarding.Controller;
import java.util.Objects;


import com.microservices.merchantOnboarding.merchantOnboarding.Component.JwtTokenUtil;
import com.microservices.merchantOnboarding.merchantOnboarding.Component.MyAuthenticationException;

import com.microservices.merchantOnboarding.merchantOnboarding.Model.LoginRequest;
import com.microservices.merchantOnboarding.merchantOnboarding.Model.LoginResponse;
import com.microservices.merchantOnboarding.merchantOnboarding.Model.MerchantDetails;
import com.microservices.merchantOnboarding.merchantOnboarding.Repository.JpaAuthTransactionRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
public class JpaAuthTransactionController {
//	
//	
@Value("${jwt.http.request.header}")
private String tokenHeader;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;


	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JpaAuthTransactionRepository jpaAuthTransactionRepository;




	@RequestMapping(value = "${jwt.login.uri}", method = RequestMethod.POST)
	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequestDto)
			throws MyAuthenticationException {

		authenticate(loginRequestDto.getUsername(), loginRequestDto.getPassword());

		//authentication aka puch tacha complete preparing JWT for the response, below
		final MerchantDetails userDetails =(MerchantDetails) userDetailsService.loadUserByUsername(loginRequestDto.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new LoginResponse(token));
	}

	@ExceptionHandler({MyAuthenticationException.class})
	public ResponseEntity<String> handleAuthenticationException(MyAuthenticationException e) {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	}

	private void authenticate(String username, String password) {
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new MyAuthenticationException("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new MyAuthenticationException("INVALID_CREDENTIALS", e);
		}
	}
//	
//	
//
}
