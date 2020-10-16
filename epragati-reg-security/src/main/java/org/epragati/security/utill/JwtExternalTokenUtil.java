package org.epragati.security.utill;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.epragati.security.vo.JwtExternalUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;



@Component
public class JwtExternalTokenUtil implements Serializable {

	

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String CLAIM_KEY_USERNAME = "sub";
	private static final String CLAIM_KEY_SCOPE = "scope";
	private static final String CLAIM_KEY_CREATED = "created";
	private static final String CLAIM_KEY_JTI = "jti";
	private static final String CLAIM_LIST_DELIMITERS = ",";
	private static final String USER_DETAILS = "USER_DETAILS";
	/*private static final String secretKey = "gamif1cation$123";*/

	@Value("${extUser.secret.key}")  
	private String secretKey;

	@Value("${extUser.expiration}")
	private Long expiration;

	@Autowired
	private UserDetailsService userDetailsService;

	public String getUsernameFromToken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFromToken(token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	public Date getCreatedDateFromToken(String token) {
		Date created;
		try {
			final Claims claims = getClaimsFromToken(token);
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
			final Claims claims = getClaimsFromToken(token);
			audience = (String) claims.getId();
		} catch (Exception e) {
			audience = null;
		}
		return audience;
	}
	
	public JwtExternalUser getUserDetailsFromToken(String token) {
		JwtExternalUser audience = new JwtExternalUser();
		try {
			
			final Claims claims = getClaimsFromToken(token);
			LinkedHashMap<String, String> Obj = (LinkedHashMap)claims.get("USER_DETAILS");
			audience.setName(Obj.get("name"));
			audience.setMobile(Obj.get("mobile"));
			audience.setEmail(Obj.get("email"));
			audience.setUserId(Obj.get("userId"));

		} catch (Exception e) {
			audience = null;
		}
		return audience;
	}

	public List<String> getUserRoleFromToken(String token) {
		List<String> roles;
		try {
			final Claims claims = getClaimsFromToken(token);
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
			claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}

	private Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + expiration * 1000);
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public String generateToken(JwtExternalUser userDetails) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_KEY_JTI, String.valueOf(userDetails.getUserId()));
		claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
		claims.put(USER_DETAILS, userDetails);
		claims.put(CLAIM_KEY_CREATED, new Date());
		return generateToken(claims);
	}

	public String generateToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims).setExpiration(generateExpirationDate())
				.signWith(SignatureAlgorithm.HS512, secretKey).compact();
	}

	public String refreshToken(String token) {
		String refreshedToken;
		try {
			final Claims claims = getClaimsFromToken(token);
			claims.put(CLAIM_KEY_CREATED, new Date());
			refreshedToken = generateToken(claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		JwtExternalUser user = (JwtExternalUser) userDetails;
		final String username = getUsernameFromToken(token);
		return (username.equals(user.getUsername()) && !isTokenExpired(token));
	}

	public JwtExternalUser getUserDetailsByToken(String token) {
		JwtExternalUser user;
		try {
			user = (JwtExternalUser) userDetailsService.loadUserByUsername(this.getUserIdFromToken(token));

		} catch (Exception e) {
			user = null;
		}
		return user;
	}
}

