package com.example.memo.domain.model;

import static com.example.memo.configuration.security.WebSecurityConfig.ROLE_MEMBER;

import com.example.memo.domain.entity.Member;
import java.util.Collections;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
public class AuthorizedMember extends User {

	private final Member member;

	public AuthorizedMember(Member member) {
		super(member.getEmail(), member.getPassword(),
			Collections.singletonList(new SimpleGrantedAuthority(ROLE_MEMBER)));
		this.member = member;
	}
}
