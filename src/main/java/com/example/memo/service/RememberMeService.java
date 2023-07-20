package com.example.memo.service;

import java.util.UUID;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;

@Service
public class RememberMeService extends TokenBasedRememberMeServices {

	public RememberMeService(UserDetailsService userDetailsService) {
		super(UUID.randomUUID().toString(), userDetailsService);
	}
}
