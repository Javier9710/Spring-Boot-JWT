package com.ufps.springboot.app.auth.service;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ufps.springboot.app.auth.SimpleGrantedAuthoritiesMixin;
import com.ufps.springboot.app.auth.filter.JWTAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTServiceImpl implements JWTService {
	
	public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

	@Override
	public String create(Authentication auth) throws JsonProcessingException {
		//SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
		
		
		
		//SecretKey secretKey = new SecretKeySpec("algunaLlaveSecreta".getBytes(), SignatureAlgorithm.HS256.getJcaName());
		
		String username = ((User) auth.getPrincipal()).getUsername();
		
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));
		
		String token = Jwts.builder()
				.setClaims(claims)
                .setSubject(username)
                .signWith(SECRET_KEY)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000L))
                .compact();
		
		
		return null;
	}

	@Override
	public boolean validate(String token) {
		
		try {
			
			getClaims(token);
			
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
			

		}
		
	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(SECRET_KEY)
				.build()
				.parseClaimsJws(resolve(token))
				.getBody();
		return claims;
	}

	@Override
	public String GetUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws JsonParseException, JsonMappingException, IOException {
		Object roles = getClaims(token).get("authorities");
		
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthoritiesMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		
		return authorities;
	}

	@Override
	public String resolve(String token) {
		if (token != null && token.startsWith("Bearer ")) {
			return token.replace("Bearer ", "");
		}
		return null;
		
	}

}
