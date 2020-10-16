package org.epragati.security.utill;

import java.util.Date;

public class DateUtils {

	public static Date pareDate(Long date) {

		if (date == null) {
			return null;
		}

		return new Date(date);

	}
}
