package org.epragati.security.config;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.epragati.common.dao.RequestDAO;
import org.epragati.common.dto.RequestDataDTO;
import org.epragati.constants.CommonConstants;
import org.epragati.security.utill.JwtTokenUtil;
import org.epragati.security.utill.MutableHttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Value("${jwt.header}")
	private String tokenHeader;

	@Autowired
	private RequestDAO requestDAO;

	private static final List<MediaType> VISIBLE_TYPES = Arrays.asList(MediaType.valueOf("text/*"),
			MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML,
			MediaType.valueOf("application/*+json"), MediaType.valueOf("application/*+xml"),
			MediaType.MULTIPART_FORM_DATA);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String authToken = request.getHeader(this.tokenHeader);
		// authToken.startsWith("Bearer ")
		// String authToken = header.substring(7);
		String username = jwtTokenUtil.getUsernameFromToken(authToken);

		// log.info("checking authentication für user " + username);

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			// It is not compelling necessary to load the use details from the database. You
			// could also store the information
			// in the token and read it from it. It's up to you ;)
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

			// For simple validation it is completely sufficient to just check the token
			// integrity. You don't have to call
			// the database compellingly. Again it's up to you ;)
			if (jwtTokenUtil.validateToken(authToken, userDetails)) {
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				log.debug("authenticated user " + username + ", setting security context");
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		if (isAsyncDispatch(request)) {
			chain.doFilter(request, response);
		} else {
			RequestDataDTO requestData = new RequestDataDTO();
			doFilterWrapped(wrapRequest(request), wrapResponse(response), chain, requestData);
		}

	}

	protected void doFilterWrapped(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response,
			FilterChain filterChain, RequestDataDTO requestDataDTO) throws ServletException, IOException {
		try {
			beforeRequest(request, response, requestDataDTO);
			filterChain.doFilter(request, response);
		} finally {
			afterRequest(request, response, requestDataDTO);
			response.copyBodyToResponse();
		}

	}

	protected void beforeRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response,
			RequestDataDTO requestDataDTO) {
		if (log.isInfoEnabled() && !StringUtils.isEmpty(request.getServletPath())
				&& !skipLoggingPaths().contains(request.getServletPath()) && !StringUtils.isEmpty(request.getMethod())
				&& !request.getMethod().equalsIgnoreCase(HttpMethod.OPTIONS.name())) {
			logRequestHeader(requestDataDTO, request, request.getRemoteAddr() + "|>");
			logRequestUrl(requestDataDTO, request, request.getRemoteAddr() + "|>");

		}
	}

	protected List<String> skipLoggingPaths() {
		List<String> path = new ArrayList<>();
		path.add("/auth");
		path.add("/generateCaptcha");
		return path;
	}

	protected void afterRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response,
			RequestDataDTO requestDataDTO) {
		if (log.isInfoEnabled() && !StringUtils.isEmpty(request.getServletPath())
				&& !skipLoggingPaths().contains(request.getServletPath()) && !StringUtils.isEmpty(request.getMethod())
				&& !request.getMethod().equalsIgnoreCase(HttpMethod.OPTIONS.name())) {
			logRequestBody(requestDataDTO, request, request.getRemoteAddr() + "|>");
			requestDataDTO.setCreatedDate(LocalDateTime.now());
			requestDataDTO.setlUpdate(LocalDateTime.now());
			requestDAO.save(requestDataDTO);
			// logResponse(response, request.getRemoteAddr() + "|<");
		}
	}

	private static void logRequestHeader(RequestDataDTO requestDataDTO, ContentCachingRequestWrapper request,
			String prefix) {
		Map<String, String> map = new HashMap<>();
		Collections.list(request.getHeaderNames()).stream().forEach(header -> {
			map.put(header, request.getHeader(header));
		});
		// request.get
		/*
		 * if(request.getHeaderNames()!=null) { request.getSession().set }
		 */
		// log.info("headers [{}]", map);
		if (!map.isEmpty()) {
			requestDataDTO.setHeaders(map);
		}

	}

	private static void logRequestUrl(RequestDataDTO requestDataDTO, ContentCachingRequestWrapper request,
			String prefix) {
		Map<String, String[]> paramMap = request.getParameterMap();
		if (!CollectionUtils.isEmpty(paramMap)) {
			requestDataDTO.setParameterMap(paramMap);
		}
		if (request != null) {
			requestDataDTO.setServletPath(request.getServletPath());
			requestDataDTO.setContextPath(request.getContextPath());
			requestDataDTO.setRequestUrl(request.getRequestURL().toString());
			requestDataDTO.setRequestURI(request.getRequestURI());
			try {
				requestDataDTO.setRemoteIp(request.getRemoteAddr());
				InetAddress inetAddress = InetAddress.getLocalHost();

				if (inetAddress != null) {
					requestDataDTO.setInetIp(inetAddress.getHostAddress());
				}
			} catch (UnknownHostException e) {
				log.error("Exception occured for getting Remote Address");
			}

		}
	}

	private static void logRequestBody(RequestDataDTO requestDataDTO, ContentCachingRequestWrapper request,
			String prefix) {
		byte[] content = request.getContentAsByteArray();
		if (HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
			if (content.length > 0) {
				logContent(requestDataDTO, content, request.getContentType(), request.getCharacterEncoding(), prefix);
			}
		}
	}

	private static void logResponse(RequestDataDTO requestDataDTO, ContentCachingResponseWrapper response,
			String prefix) {
		int status = response.getStatus();
		// log.info("{} {} {}", prefix, status,
		// HttpStatus.valueOf(status).getReasonPhrase());
		// log.info("{}", prefix);
		byte[] content = response.getContentAsByteArray();
		if (content.length > 0) {
			logContent(requestDataDTO, content, response.getContentType(), response.getCharacterEncoding(), prefix);
		}
	}

	private static void logContent(RequestDataDTO requestDataDTO, byte[] content, String contentType,
			String contentEncoding, String prefix) {
		MediaType mediaType = MediaType.valueOf(contentType);
		boolean visible = VISIBLE_TYPES.stream().anyMatch(visibleType -> visibleType.includes(mediaType));
		if (visible) {
			try {
				String contentString = new String(content, contentEncoding);
				if (!StringUtils.isEmpty(contentString)) {
					requestDataDTO.setPayload(contentString);
				}
			} catch (UnsupportedEncodingException e) {
				// log.error("{} [{} bytes content]", prefix, content.length);
			}
		}
	}

	private static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
		MutableHttpServletRequest mutableRequest = new MutableHttpServletRequest(request);
		mutableRequest.putHeader(CommonConstants.TRACKING_NO,
				LocalDate.now().toString() + "-" + UUID.randomUUID().toString());
		HttpServletRequest req = (HttpServletRequest) mutableRequest;

		if (req instanceof ContentCachingRequestWrapper) {
			return (ContentCachingRequestWrapper) req;
		} else {
			return new ContentCachingRequestWrapper(req);
		}
	}

	private static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
		if (response instanceof ContentCachingResponseWrapper) {
			return (ContentCachingResponseWrapper) response;
		} else {
			return new ContentCachingResponseWrapper(response);
		}
	}

}
