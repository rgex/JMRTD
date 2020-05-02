/* $Id: JJ2000ImageWriteParam.java 1517 2013-08-05 09:10:41Z martijno $ */

package org.jmrtd.imageio;

import java.util.Locale;

import javax.imageio.ImageWriteParam;

public class JJ2000ImageWriteParam extends ImageWriteParam {

	private double bitRate = Double.NaN;

	public JJ2000ImageWriteParam(Locale locale) {
		super(locale);
	}

	public double getBitRate() {
		return bitRate;
	}

	public void setBitrate(double bitRate) {
		this.bitRate = bitRate;
	}
}
