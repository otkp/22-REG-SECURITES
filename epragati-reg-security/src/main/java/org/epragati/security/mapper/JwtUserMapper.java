package org.epragati.security.mapper;

import org.apache.commons.lang3.StringUtils;
import org.epragati.jwt.JwtUser;
import  org.epragati.master.dto.UserDTO;

public class JwtUserMapper {

	private JwtUserMapper() {
		
	}
	

	public static JwtUser create(UserDTO user) {
		return new JwtUser(
                user.getUserId(),
                user.getFirstName(),
                user.getLastName(),
                user.getPassword(),
                user.getPrimaryRole(),
                user.getAdditionalRoles(),
               (user.getOffice()==null?StringUtils.EMPTY:user.getOffice().getOfficeCode()),
                user.getParentUserId(),
                user.isParent(),
                user.isPasswordResetRequired(),
                user.getIsAccountNonLocked(),
                user.getUserAadhaarAuthTime(),
                user.getValidTo()
        );
	}
	
}
