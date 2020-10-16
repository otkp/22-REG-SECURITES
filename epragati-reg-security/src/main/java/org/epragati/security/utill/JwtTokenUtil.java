package org.epragati.security.utill;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.epragati.jwt.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.epragati.security.service.ExternalUserService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -3301605591108950415L;

	private static final String CLAIM_KEY_USERNAME = "sub";
	private static final String CLAIM_KEY_SCOPE = "scope";
	private static final String CLAIM_KEY_CREATED = "created";
	private static final String CLAIM_KEY_JTI = "jti";
	private static final String CLAIM_LIST_DELIMITERS = ",";
	private static final String USER_DETAILS = ",";

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private Long expiration;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private ExternalUserService externalUserService;

	public String getUsernameFromToken(String token) {
		String username;
		try {
			String tokenValue = externalUserService.getTokenfromHash(token);
			final Claims claims = getClaimsFromToken(tokenValue);

			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	public Date getCreatedDateFromToken(String token) {
		Date created;
		try {
			String tokenValue = externalUserService.getTokenfromHash(token);
			final Claims claims = getClaimsFromToken(tokenValue);
			created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
		} catch (Exception e) {
			created = null;
		}
		return created;
	}

	public Date getExpirationDateFromToken(String token) {
		Date expiration;
		try {

			final Claims claims = getClaimsFromToken(token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}

	public String getUserIdFromToken(String token) {
		String audience;
		try {
			String tokenValue = externalUserService.getTokenfromHash(token);
			final Claims claims = getClaimsFromToken(tokenValue);
			audience = (String) claims.getId();
		} catch (Exception e) {
			audience = null;
		}
		return audience;
	}

	public List<String> getUserRoleFromToken(String token) {
		List<String> roles;
		try {
			String tokenValue = externalUserService.getTokenfromHash(token);
			final Claims claims = getClaimsFromToken(tokenValue);
			String roleStr = (String) claims.get(CLAIM_KEY_SCOPE);
			roles = Arrays.asList(roleStr.split(CLAIM_LIST_DELIMITERS));
		} catch (Exception e) {
			roles = null;
		}
		return roles;
	}

	private Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}

	private Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + expiration * 1000);
	}

	private Boolean isTokenExpired(String token) {
		String tokenValue = externalUserService.getTokenfromHash(token);
		final Date expiration = getExpirationDateFromToken(tokenValue);
		return expiration.before(new Date());
	}

	private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}

	public String generateToken(JwtUser userDetails) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_KEY_JTI, String.valueOf(userDetails.getId()));
		claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
		String roles = userDetails.getAuthorities().stream().map(i -> i.toString())
				.collect(Collectors.joining(CLAIM_LIST_DELIMITERS));
		claims.put(CLAIM_KEY_SCOPE, roles);
		claims.put(USER_DETAILS, userDetails);
		claims.put(CLAIM_KEY_CREATED, new Date());
		return generateToken(claims);
	}

	public String generateToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims).setExpiration(generateExpirationDate())
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public String refreshToken(String token) {
		String refreshedToken;
		try {
			String tokenValue = externalUserService.getTokenfromHash(token);
			final Claims claims = getClaimsFromToken(tokenValue);
			claims.put(CLAIM_KEY_CREATED, new Date());
			refreshedToken = generateToken(claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		JwtUser user = (JwtUser) userDetails;
		final String username = getUsernameFromToken(token);
		// final Date created = getCreatedDateFromToken(token);
		// final Date expiration = getExpirationDateFromToken(token);
		return (username.equals(user.getUsername()) && !isTokenExpired(token));
		// && !isCreatedBeforeLastPasswordReset(created,
		// user.getLastPasswordResetDate()));
	}

	public JwtUser getUserDetailsByToken(String token) {
		JwtUser user;
		try {
			user = (JwtUser) userDetailsService.loadUserByUsername(this.getUserIdFromToken(token));

		} catch (Exception e) {
			user = null;
		}
		return user;
	}
}
