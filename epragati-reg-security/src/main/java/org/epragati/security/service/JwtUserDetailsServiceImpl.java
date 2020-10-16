package org.epragati.security.service;

import java.util.Optional;

import org.epragati.master.dao.UserDAO;
import org.epragati.master.dto.UserDTO;
import org.epragati.security.mapper.JwtUserMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsServiceImpl.class);

	@Autowired
	private UserDAO userDAO;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Optional<UserDTO> userOptional = userDAO.findByUserId(username);
		if (!userOptional.isPresent()) {
			logger.info("User is not found [{}]", username);
			//throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
			throw new UsernameNotFoundException(String.format("Invalid USERNAME/PASSWORD '%s'.", username));

		}
		logger.debug("User is found [{}]", username);
		return JwtUserMapper.create(userOptional.get());

		/*
		 * if (UserType.ROLE_ONLINE_FINANCER.equals(userOptional.get().getUserType())) {
		 * logger.info("User is role matched as ROLE_ONLINE_FINANCER");
		 * 
		 * }
		 * 
		 * if
		 * (UserType.ROLE_ONLINE_FINANCER_SUB.equals(userOptional.get().getUserType()))
		 * { logger.info("User is role matched as ROLE_ONLINE_FINANCER_SUB");
		 * 
		 * Optional<Integer> levelOptional =
		 * employeeService.getEmployeeLevel(userOptional.get().getUserId());
		 * 
		 * if (levelOptional.isPresent()) { logger.info("User level is [{}]",
		 * levelOptional.get()); if (levelOptional.get() == 1) {
		 * logger.info("User level is 1"); return
		 * JwtUserMapper.create(userOptional.get()); } }
		 * logger.info("User level is not matched."); }
		 * 
		 * logger.info("User is role not matched");
		 * 
		 * // TODO: throw new AuthenticationException("Unauthorized") { };
		 */

	}

	public UserDetails loadByAdhar(String adharNo) throws UsernameNotFoundException {
		Optional<UserDTO> userOptional = userDAO.findAllByAadharNo(adharNo);
		if (!userOptional.isPresent()) {
			logger.info("User is not found [{}]", adharNo);
			throw new UsernameNotFoundException(String.format("No user found with this adhar '%s'.", adharNo));
		}
		logger.debug("User is found [{}]", adharNo);
		return JwtUserMapper.create(userOptional.get());

	}
}
