package org.epragati.security.service;

import java.util.Optional;

import org.epragati.regservice.dto.TokenAuthenticationDTO;
import org.epragati.security.utill.ExternalUserVO;
import org.epragati.security.vo.JwtExternalUser;

/**
 * 
 * @author pbattula
 *
 */
public interface ExternalUserService {

	JwtExternalUser validateToken(String token);

	String authenticateUser(ExternalUserVO externalUserVO);

	void saveTokenAndHash(String token, String hash);

	String getTokenfromHash(String string);

	/**
	 * 
	 * @param string
	 * @return
	 */
	Optional<TokenAuthenticationDTO> getTokenDtofromHash(String string);
}
