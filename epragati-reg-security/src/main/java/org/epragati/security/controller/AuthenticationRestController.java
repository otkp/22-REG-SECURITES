package org.epragati.security.controller;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.epragati.common.dao.PropertiesDAO;
import org.epragati.common.dto.PropertiesDTO;
import org.epragati.common.vo.UserStatusEnum;
import org.epragati.constants.AadhaarConstants;
import org.epragati.constants.MessageKeys;
import org.epragati.exception.BadRequestException;
import org.epragati.jwt.JwtUser;
import org.epragati.master.dao.LoginDetailsDAO;
import org.epragati.master.dao.UserDAO;
import org.epragati.master.dao.UserLoginHistoryDAO;
import org.epragati.master.dto.LoginDetails;
import org.epragati.master.dto.UserDTO;
import org.epragati.master.dto.UserLoginHistoryDTO;
import org.epragati.master.vo.UserVO;
import org.epragati.security.service.ExternalUserService;
import org.epragati.security.utill.JwtTokenUtil;
import org.epragati.security.vo.CaptchaResponseVO;
import org.epragati.security.vo.CaptchaValidationVO;
import org.epragati.security.vo.JwtAuthenticationResult;
import org.epragati.uidailogin.entity.LoginStatusType;
import org.epragati.uidailogin.entity.LoginStatusTypeDao;
import org.epragati.util.AppMessages;
import org.epragati.util.GateWayResponse;
import org.epragati.util.JwtAuthenticationRequest;
import org.epragati.util.RoleEnum;
import org.epragati.util.payment.HashingUtil;
import org.epragati.util.validators.PasswordValidator;
import org.epragati.vcr.constant.VcrConstent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@CrossOrigin
@RestController
@SuppressWarnings({ "unchecked", "rawtypes" })
public class AuthenticationRestController {

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationRestController.class);

	@Value("${jwt.header}")
	private String tokenHeader;

	@Autowired
	private UserLoginHistoryDAO userLoginHistoryDAO;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private ExternalUserService externalUserService;

	@Autowired
	private RestTemplate restTemplate;

	@Autowired
	private AppMessages appMessages;

	@Value("${isCaptchEnabled:false}")
	private Boolean isCaptchEnabled;

	@Value("${generateCaptchaUrl:}")
	private String generateCaptchaUrl;

	@Value("${validateCaptchaUrl:}")
	private String validateCaptchaUrl;

	@Autowired
	private UserDAO userDAO;

	@Autowired
	private PropertiesDAO propertiesDAO;

	@Autowired
	private LoginStatusTypeDao dao;
	
	@Autowired
	private LoginDetailsDAO loginDetailsDAO;
	
	

	private JwtAuthenticationResult getJwtAuthenticationResult(JwtAuthenticationRequest authenticationRequest,
			String mobileVcr,HttpServletRequest request) {
		// Perform the security

		final Authentication authentication;
		JwtUser jwtUser = (JwtUser) userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		Optional<LoginDetails> lastUserDTO=loginDetailsDAO.findByUserNameOrderByLUpdateDesc(authenticationRequest.getUsername());
		String statusStr="S";
		Optional<UserLoginHistoryDTO> logHistDTO=userLoginHistoryDAO.findTopByUserIdAndStatusOrderByLUpdateDesc(authenticationRequest.getUsername(),statusStr);
		if (authenticationRequest.getPassword() != null) {
			if (StringUtils.isEmpty(authenticationRequest.getCapchaValue())
					|| StringUtils.isEmpty(authenticationRequest.getCapchaId())) {
				throw new BadRequestException("invalid captcha value");
			}

			authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
			getValidateUser(jwtUser.getPrimaryRole().getName(), authenticationRequest.getPassword(),
					authenticationRequest.getIsUidsStatus(), mobileVcr);

		} else {
			// for UIDAI based AUTH. IMPL.
			check(jwtUser);
			authentication=createSuccessAuthentication(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
					authenticationRequest.getPassword()),jwtUser);
			long minutes = jwtUser.getUserAadhaarAuthTime().until(LocalDateTime.now(), ChronoUnit.MINUTES);
			if (minutes >= 2) {
				// TODO: RE check below sentence
				throw new BadRequestException("Aadhaar Authentication Expired. So please Authenticate once...");
			}
		}
		//Renwals check:
		

		SecurityContextHolder.getContext().setAuthentication(authentication);
		final String hash;
		if(null!=jwtUser.getPrimaryRole() && Arrays.asList(RoleEnum.DEALER.getName(),RoleEnum.DRIVINGSCHOOL.getName()).contains(jwtUser.getPrimaryRole().getName())
				&& (jwtUser.getValidTo() == null || jwtUser.getValidTo().isBefore(LocalDate.now()))) {
			hash=null;
		}else {
			final String token = jwtTokenUtil.generateToken(jwtUser);
			hash = HashingUtil.sha512HashCal(token);
			externalUserService.saveTokenAndHash(token, hash);
			saveLoginHistoryDetails(authenticationRequest.getUsername(), "S");
			saveSessionDetails(request, token, authenticationRequest.getUsername());
		}
		   
		if(lastUserDTO.isPresent())
		{
			String datstr=PasswordValidator.covertISTTime(lastUserDTO.get().getLoginTime());
			jwtUser.setLastLoginTime(datstr);
		}else if(logHistDTO.isPresent())
		{
			String datstr=PasswordValidator.covertISTTime(logHistDTO.get().getLoginTime());
			jwtUser.setLastLoginTime(datstr);
		}else {
			jwtUser.setLastLoginTime("N/A");
		}
		JwtAuthenticationResult result = new JwtAuthenticationResult(jwtUser.getId(), jwtUser.getFirstname(),
				jwtUser.getLastname(), jwtUser.getPrimaryRole(), jwtUser.getAdditionalRoles(), hash,
				jwtUser.getOfficeCode(), jwtUser.getParentUserId(), jwtUser.isParent(),
				jwtUser.isPasswordResetRequired(),jwtUser.getValidTo(),jwtUser.getLastLoginTime());
		
		return result;
	}

	@RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
	public GateWayResponse<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest,
			@RequestParam(name = "mobile", required = false) String mobile,HttpServletRequest request) throws AuthenticationException {

		try {
			logger.debug("Authentication Start, UserID: {}", authenticationRequest.getUsername());
			//validateUserDetailsExistsOrNot(authenticationRequest.getUsername());
			validateCaptcha(authenticationRequest);
			authenticationRequest.setUsername(authenticationRequest.getUsername().toUpperCase());
			JwtAuthenticationResult result = getJwtAuthenticationResult(authenticationRequest, mobile, request);
			logger.debug("ROLE [{}]", result.getPrimaryRole());

			if (StringUtils.isNotBlank(mobile) && mobile.trim().equals(VcrConstent.VCR)
					&& (!(result.getPrimaryRole().equals(VcrConstent.ROLE_MVI)
							|| result.getPrimaryRole().equals(VcrConstent.ROLE_DTC)
							|| result.getPrimaryRole().equals(VcrConstent.ROLE_RTO)))) {

				logger.debug("ROLE NOT MATCH FOR VCR [{}]", result.getPrimaryRole());
				throw new BadRequestException("you are Unauthorised user..");

			}
			return new GateWayResponse(result);
		} catch (BadRequestException e) {
			logger.error(" UserID: {}, Exception :{}", authenticationRequest.getUsername(), e.getMessage());
			return new GateWayResponse(false, HttpStatus.BAD_REQUEST, e.getMessage(), e.getMessage());
		} catch (Exception e) {
			saveLoginHistoryDetails(authenticationRequest.getUsername(), "F");
			logger.error(" UserID: {}, Exception :{}", authenticationRequest.getUsername(), e.getMessage());
			return new GateWayResponse(false, HttpStatus.BAD_REQUEST, e.getMessage(), e.getMessage());
		}
	}

	

	@RequestMapping(value = "${jwt.route.authentication.path.external}", method = RequestMethod.POST)
	public GateWayResponse<?> createAuthenticationTokenForExteral(
			@RequestBody JwtAuthenticationRequest authenticationRequest,HttpServletRequest request) throws AuthenticationException {

		try {
			logger.debug("Authentication Start, UserID: {}", authenticationRequest.getUsername());
			String user = "EXTERNAL_USER";
			JwtAuthenticationResult result = getJwtAuthenticationResult(authenticationRequest, user,request);
			return new GateWayResponse(result);
		} catch (BadRequestException e) {
			logger.error(" UserID: {}, Exception :{}", authenticationRequest.getUsername(), e.getMessage());
			return new GateWayResponse(false, HttpStatus.BAD_REQUEST, e.getMessage(), e.getMessage());
		} catch (Exception e) {
			saveLoginHistoryDetails(authenticationRequest.getUsername(), "F");
			logger.error(" UserID: {}, Exception :{}", authenticationRequest.getUsername(), e.getMessage());
			return new GateWayResponse(false, HttpStatus.BAD_REQUEST, e.getMessage(), e.getMessage());
		}
	}

	private void validateCaptcha(JwtAuthenticationRequest userVO) {

		if (isCaptchEnabled && StringUtils.isNoneBlank(userVO.getCapchaId())
				&& StringUtils.isNoneBlank(userVO.getCapchaValue())) {

			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<JwtAuthenticationRequest> httpEntity = new HttpEntity<>(userVO, headers);
			ResponseEntity<String> responseEntity = null;

			responseEntity = restTemplate.exchange(validateCaptchaUrl, HttpMethod.POST, httpEntity, String.class);

			if (responseEntity == null) {
				logger.error("Exception occured while while VAlidating captcha url [{}]" + validateCaptchaUrl);

				throw new BadRequestException("Captcha Validating Failed");
			}

			ObjectMapper mapper = new ObjectMapper();
			CaptchaValidationVO authenticationRepsoneVO = null;
			try {
				authenticationRepsoneVO = mapper.readValue(responseEntity.getBody(), CaptchaValidationVO.class);
			} catch (JsonParseException e) {
				logger.error("captcha validation parsing error [{}]", responseEntity.getBody());
			} catch (JsonMappingException e) {
				logger.error("captcha validation parsing error [{}]", responseEntity.getBody());
			} catch (IOException e) {
				logger.error("captcha validation parsing error [{}]", responseEntity.getBody());

			}

			if (authenticationRepsoneVO != null && !authenticationRepsoneVO.isResult()) {
				throw new BadRequestException("Invalid captcha");
			}

		}

	}

//throw new BadRequestException("Invalid captcha");
	private void saveLoginHistoryDetails(String userId, String status) {

		UserLoginHistoryDTO userHistoryDTO = new UserLoginHistoryDTO();

		userHistoryDTO.setLoginTime(LocalDateTime.now());
		userHistoryDTO.setStatus(status);
		userHistoryDTO.setUserId(userId);

		userLoginHistoryDAO.save(userHistoryDTO);

	}
private void saveSessionDetails(HttpServletRequest request,String hash,String userName) {
		
		Optional<UserDTO> optUserDetails =  userDAO.findByUserIdAndUserStatus(userName, UserStatusEnum.ACTIVE);
		if(!optUserDetails.isPresent()) {
			return;
		}
		UserDTO userDTO = optUserDetails.get();
		
		LoginDetails loginDetails = new LoginDetails();
		
		loginDetails.setUserName(userName);
		loginDetails.setAadharNo(userDTO.getAadharNo());
		loginDetails.setLoginTime(LocalDateTime.now());
		loginDetails.setMobileNumber(userDTO.getMobile());
		loginDetails.setSystemIp(request.getRemoteAddr());
		loginDetails.setToken(hash);
		
		
//		if(userDTO.getPrimaryRole().getName().equals(RoleEnum.STA.getName())
//				||(userDTO.getAdditionalRoles()!=null&&
//						userDTO.getAdditionalRoles().stream().anyMatch(role->role.getName().equals(RoleEnum.STA.getName())))) {
//			
//			loginDetails.setLoginType("captcha");
//			loginDetails.setAadharAuthTime(null);
//		}
		if(!StringUtils.isEmpty(userDTO.getLastLoginType())
				&&userDTO.getLastLoginType().equals(AadhaarConstants.RequestType.EKYC.getContent())) {
			loginDetails.setLoginType(AadhaarConstants.RequestType.EKYC.getContent());
			loginDetails.setDeviceNumber(userDTO.getDeviceId());
			loginDetails.setAadharAuthTime(userDTO.getUserAadhaarAuthTime());
			
		}else if(!StringUtils.isEmpty(userDTO.getLastLoginType())
				&&userDTO.getLastLoginType().equals(AadhaarConstants.RequestType.OPT.getContent())){
			loginDetails.setLoginType(AadhaarConstants.RequestType.OPT.getContent());
			loginDetails.setAadharAuthTime(userDTO.getUserAadhaarAuthTime());
		}else {
			loginDetails.setLoginType("captcha");
		}
		
		loginDetails.setOfficeCode(userDTO.getOffice().getOfficeCode());
		loginDetailsDAO.save(loginDetails);
		
		userDTO.setDeviceId(null);
		userDTO.setLastLoginType(null);
		userDAO.save(userDTO);
		
	}
	@RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.GET)
	public GateWayResponse<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
		String token = request.getHeader(tokenHeader);
		// JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);
		String refreshedToken = jwtTokenUtil.refreshToken(token);
		final String hash = HashingUtil.sha512HashCal(refreshedToken);
		externalUserService.saveTokenAndHash(refreshedToken, hash);
		return new GateWayResponse(hash);
	}
	@PostMapping(value = "/validateCaptcha" ,produces = {
			MediaType.APPLICATION_JSON_VALUE,MediaType.APPLICATION_XML_VALUE})
	public GateWayResponse<?> captchaValidation(@RequestBody JwtAuthenticationRequest userVO)
			throws ServletException, IOException {
			try {
				validateCaptcha(userVO);
			}catch (Exception e) {
				logger.error(appMessages.getLogMessage(MessageKeys.SVS_RESULTNOTAVAILABLE), e.getMessage());
				return new GateWayResponse<>(HttpStatus.BAD_GATEWAY, "Failed", e.getMessage());
			}
		return new GateWayResponse<>(HttpStatus.OK, "Success", "captcha validation success");
	}

	@RequestMapping(value = "/generateCaptcha", method = RequestMethod.GET, produces = {
			MediaType.APPLICATION_JSON_VALUE })
	@ResponseBody
	public GateWayResponse<?> generateCaptcha(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		if (true) {
			HttpHeaders headers = new HttpHeaders();
			headers.set("Accept", "application/json");
			HttpEntity entity = new HttpEntity(headers);
			ResponseEntity<String> responseEntity = null;
			try {
				responseEntity = restTemplate.exchange(generateCaptchaUrl, HttpMethod.GET, entity, String.class);
				if (responseEntity == null) {

					logger.error("Exception occured while while generating captcha url [{}]" + generateCaptchaUrl);
					return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR,
							"Exception occured while generation captcha");

					// return new GateWayResponse<>(HttpStatus.OK);
				}

				ObjectMapper mapper = new ObjectMapper();
				CaptchaResponseVO authenticationRepsoneVO = mapper.readValue(responseEntity.getBody(),
						CaptchaResponseVO.class);

				return new GateWayResponse<>(authenticationRepsoneVO.getResult());
			} catch (HttpClientErrorException httpClientErrorException) {

				logger.error(appMessages.getLogMessage(MessageKeys.RESTGATEWAYSERVICEIMPL_PAN_HTTPCLIENTERROR),
						httpClientErrorException.getMessage());

			} catch (Exception e) {
				logger.error(appMessages.getLogMessage(MessageKeys.SVS_RESULTNOTAVAILABLE), e.getMessage());

			}
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR,
					"Exception occured while generation captcha");
		}
		return new GateWayResponse<>(HttpStatus.OK, "captcha Disabled", "captcha Disabled");
	}

	/*
	 * @RequestMapping(value = "/generateCaptcha", method = RequestMethod.GET,
	 * produces = { MediaType.APPLICATION_JSON_VALUE })
	 * 
	 * @ResponseBody public GateWayResponse<JwtAuthenticationRequest>
	 * generateCaptcha(HttpServletRequest request, HttpServletResponse response)
	 * throws ServletException, IOException { final String FILE_TYPE = "jpeg";
	 * String captchaStr = "";
	 * 
	 * captchaStr = generateCaptchaTextMethod2(6); String capchaID =
	 * UUID.randomUUID().toString(); capchaMap.put(capchaID, captchaStr);
	 * 
	 * try {
	 * 
	 * int width = 130; Color bg = Color.WHITE; int height = 40; Color fg = new
	 * Color(0, 100, 0);
	 * 
	 * Font font = new Font("Arial", Font.BOLD, 20); BufferedImage cpimg = new
	 * BufferedImage(width, height, BufferedImage.OPAQUE); Graphics g =
	 * cpimg.createGraphics();
	 * 
	 * g.setFont(font); g.setColor(bg); g.fillRect(0, 0, width, height);
	 * g.setColor(fg); g.drawString(captchaStr, 10, 25); ByteArrayOutputStream baos
	 * = new ByteArrayOutputStream();
	 * 
	 * ImageIO.write(cpimg, FILE_TYPE, baos); byte[] imgBytes = baos.toByteArray();
	 * 
	 * IOUtils.closeQuietly(baos); JwtAuthenticationRequest userVO = new
	 * JwtAuthenticationRequest(); userVO.setCapchaId(capchaID);
	 * userVO.setCapchaEncodedImg(Base64.getEncoder().encodeToString(imgBytes));
	 * 
	 * return new GateWayResponse<JwtAuthenticationRequest>(userVO);
	 * 
	 * } catch (Exception e) { throw new
	 * BadRequestException("OOps.. There is an Error while generate capcha. please try again."
	 * ); }
	 * 
	 * }
	 */
	private String generateCaptchaTextMethod2(int captchaLength) {

		String saltChars = "1234567890";
		StringBuffer captchaStrBuffer = new StringBuffer();
		java.util.Random rnd = new java.util.Random();

		// build a random captchaLength chars salt
		while (captchaStrBuffer.length() < captchaLength) {
			int index = (int) (rnd.nextFloat() * saltChars.length());
			captchaStrBuffer.append(saltChars.substring(index, index + 1));
		}

		return captchaStrBuffer.toString();

	}

	@RequestMapping(value = "/hello", method = RequestMethod.GET)
	public ResponseEntity<String> hello(HttpServletRequest request) {

		return ResponseEntity.ok("<h1> DONE </h1>");
	}

	@Autowired
	private PasswordEncoder passwordEncoder;

	@GetMapping(path = "/getEncPwd")
	public String getEncPassword(@RequestParam(value = "password") String password, HttpServletResponse response)
			throws IOException {

		return "<h4>'" + password + "' Encrypted Value:: <b style=\"color:blue;\">" + passwordEncoder.encode(password)
				+ "<b><h4>";
	}

	/**
	 * service for Aadhaar based authentication
	 * ========================================================================
	 */

	@GetMapping(path = "/chkAdhrWithUser")
	public GateWayResponse<?> checkAdhar(@RequestParam(value = "userName") String userName) {

		try {

			Optional<UserDTO> userLoad = userDAO.findByUserIdAndUserStatus(userName, UserStatusEnum.ACTIVE);
			UserVO userVO = new UserVO();
			if (userLoad.isPresent()) {
				userVO.setUserDepartment(userLoad.get().getPrimaryRole().getName());
				Optional<PropertiesDTO> propDTO = propertiesDAO
						.findByDepartmentRolesRolesStatusRoleNameAndDepartmentRolesRolesStatusStatusTrue(
								userLoad.get().getPrimaryRole().getName());
				if (propDTO.isPresent()) {
					userVO.setUserDepartment("RTADEPT");
					if (StringUtils.isBlank(userLoad.get().getAadharNo())) {
						return new GateWayResponse<>(Boolean.FALSE, HttpStatus.OK,
								"you are not authorized user please consult your DTC/RTO to get it added your aadhar.");
					}
					userVO.setAadharNo(userLoad.get().getAadharNo());
				}
			} else {
				return new GateWayResponse<>(Boolean.FALSE, HttpStatus.OK, "User doesn't exists");
			}
			return new GateWayResponse<>(Boolean.TRUE, HttpStatus.OK, userVO);
			/*
			 * return (userLoad.isPresent() &&
			 * !StringUtils.isBlank(userLoad.get().getAadharNo())) ? new
			 * GateWayResponse<>(Boolean.TRUE, HttpStatus.OK, userLoad.get().getAadharNo())
			 * : new GateWayResponse<>(Boolean.FALSE, HttpStatus.OK,
			 * "you are not authorized user please consult your DTC/RTO to get it added your aadhar."
			 * );
			 */
		} catch (Exception e) {
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong", e.getMessage());
		}
	}

	// check User
	private UserDetails check(UserDetails user) {
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		if (!user.isAccountNonLocked()) {
			logger.debug("User account is locked");

			throw new LockedException(
					messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));
		}
		return user;
	}

	private Authentication createSuccessAuthentication(Authentication authentication, UserDetails user) {
		GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user,
				authentication.getCredentials(), authoritiesMapper.mapAuthorities(user.getAuthorities()));
		result.setDetails(authentication.getDetails());

		return result;
	}

	private void getValidateUser(String role, String password, Boolean validate, String mobileVcr) {
		if (validate == null && StringUtils.isEmpty(mobileVcr)) {
			throw new BadRequestException("Invalid inputs");
		}
		Optional<PropertiesDTO> propDTO = propertiesDAO
				.findByDepartmentRolesRolesStatusRoleNameAndDepartmentRolesRolesStatusStatusTrue(role);
		Optional<LoginStatusType> loginStatus = dao.findByUdaiLoginStatus(validate);
		if (!loginStatus.isPresent() && StringUtils.isEmpty(mobileVcr)) {
			throw new BadRequestException("Login status mismatched");
		}
		if (propDTO.isPresent() && password != null && validate) {
			throw new BadRequestException("Aadhaar authentication needed for your userid..");
		}
	}
	
	
	@GetMapping(value="/getUserIdFromToken")
	public ResponseEntity<?> getUserIdFromToken(@RequestParam(required = true) String token) {

		if (StringUtils.isEmpty(token)) {
			return new ResponseEntity<>("please provide token value", HttpStatus.BAD_REQUEST);
		}
		try {
			String userid = jwtTokenUtil.getUserIdFromToken(token);
			if (StringUtils.isEmpty(userid)) {
				return new ResponseEntity<>("Token is invalid", HttpStatus.NOT_FOUND);
			}
			return new ResponseEntity<>(userid, HttpStatus.OK);
		} catch (Exception ex) {
			return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		}

	}
}
