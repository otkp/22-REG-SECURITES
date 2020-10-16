package org.epragati.security.service;

import org.epragati.security.utill.ExternalUserVO;
import org.epragati.security.utill.JwtExternalTokenUtil;
import org.epragati.security.vo.JwtExternalUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.epragati.exception.BadRequestException;
import org.epragati.jwt.JwtUser;
import org.epragati.regservice.dto.TokenAuthenticationDTO;
import org.epragati.regservice.dao.TokenAuthenticationDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ExternalUserServiceImpl implements ExternalUserService {
	@Autowired
	private JwtExternalTokenUtil jwtExternalTokenUtil;

	@Autowired
	private TokenAuthenticationDAO tokenAuthenticationDAO;

	private static final Logger logger = LoggerFactory.getLogger(ExternalUserServiceImpl.class);

	@Override
	public String authenticateUser(ExternalUserVO externalUserVO) {

		return this.generateToken(externalUserVO);

	}

	private String generateToken(ExternalUserVO externalUserVO) {

		JwtExternalUser jwtUser = new JwtExternalUser(externalUserVO.getUserId(), externalUserVO.getMobile(),
				externalUserVO.getEmail(), externalUserVO.getName());
		String token = jwtExternalTokenUtil.generateToken(jwtUser);
		logger.debug("token {}", token);
		return token;

	}

	@Override
	public JwtExternalUser validateToken(String token) {
		JwtExternalUser userDetails = jwtExternalTokenUtil.getUserDetailsFromToken(token);
		logger.info("User Details [{}]", userDetails);
		if (userDetails != null) {
			return userDetails;
		}
		return null;
	}

	@Override
	public void saveTokenAndHash(String token, String hash) {
		try {
			TokenAuthenticationDTO tokenAuthenticationDTO = new TokenAuthenticationDTO();
			tokenAuthenticationDTO.setToken(token);
			tokenAuthenticationDTO.setHash(hash);
			tokenAuthenticationDTO.setCreatedDate(LocalDateTime.now());
			tokenAuthenticationDTO.setExpirationDate(LocalDateTime.now().plusHours(3));
			tokenAuthenticationDAO.save(tokenAuthenticationDTO);
			logger.debug("Saving Details as [{}]",tokenAuthenticationDTO);
			logger.info("Join point executed :: [{}]",tokenAuthenticationDTO.getlUpdate());
		} catch (Exception e) {
			logger.error(e.getMessage());
		}

	}

	@Override
	public String getTokenfromHash(String hash) {
		Optional<TokenAuthenticationDTO> tokenAuthenticationDTO = tokenAuthenticationDAO.findByHash(hash);
		if ((!tokenAuthenticationDTO.isPresent())
				||tokenAuthenticationDTO.get().getExpirationDate().isBefore(LocalDateTime.now())
				||(tokenAuthenticationDTO.get().getLogOutTime()!=null&&
						tokenAuthenticationDTO.get().getLogOutTime().isBefore(LocalDateTime.now()))) {
			throw new BadRequestException("Token Authentication Failed");

		}
//		if (tokenAuthenticationDTO.get().getExpirationDate().isBefore(LocalDateTime.now())) {
//			throw new BadRequestException("Token Authentication Failed");
//		}
//		if(tokenAuthenticationDTO.get().getLogOutTime()!=null&&
//				tokenAuthenticationDTO.get().getLogOutTime().isBefore(LocalDateTime.now())) {
//			throw new BadRequestException("Token Authentication Failed");
//		}
		return tokenAuthenticationDTO.get().getToken();
	}

	/**
	 * Get Jwt Token Collection Dto from DB with hashToken... and to save Token in
	 * DL db when Rest Call happens from REG server.
	 */
	@Override
	public Optional<TokenAuthenticationDTO> getTokenDtofromHash(String string) {
		Optional<TokenAuthenticationDTO> tokenAuthenticationDTO = tokenAuthenticationDAO.findByHash(string);
//		if (!tokenAuthenticationDTO.isPresent()) {
//			logger.error("Token not found related to Hash: [{}] ",string);
//			throw new BadRequestException("Token Authentication Failed");
//
//		}
//		if (tokenAuthenticationDTO.get().getExpirationDate().isBefore(LocalDateTime.now())) {
//			logger.error("Token Expired already ");
//			throw new BadRequestException("Token Authentication Failed");
//		}
		if ((!tokenAuthenticationDTO.isPresent())
				||tokenAuthenticationDTO.get().getExpirationDate().isBefore(LocalDateTime.now())
				||(tokenAuthenticationDTO.get().getLogOutTime()!=null&&
						tokenAuthenticationDTO.get().getLogOutTime().isBefore(LocalDateTime.now()))) {
			throw new BadRequestException("Token Authentication Failed");

		}
		return tokenAuthenticationDTO;
	}

}
