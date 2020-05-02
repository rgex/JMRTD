/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: CVCAFile.java 1824 2019-11-06 08:25:39Z martijno $
 */

package org.jmrtd.lds;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jmrtd.PassportService;
import org.jmrtd.cert.CVCPrincipal;

/* TODO: Use CVCPrincipal instead of String for references? */
/**
 * File structure for CVCA file (on EAC protected documents).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1824 $
 */
public class CVCAFile extends AbstractLDSFile {

  private static final long serialVersionUID = -1100904058684365703L;

  public static final byte CAR_TAG = 0x42;
  public static final int LENGTH = 36;

  private short fid;

  private String caReference = null;

  private String altCAReference = null;

  /**
   * Constructs a CVCA file by reading from a stream.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  public CVCAFile(InputStream inputStream) throws IOException {
    this(PassportService.EF_CVCA, inputStream);
  }

  /**
   * Constructs a new CVCA file from the data contained in an input stream.
   *
   * @param fid file identifier
   * @param inputStream stream with the data to be parsed
   *
   * @throws IOException on error reading from input stream
   */
  public CVCAFile(short fid, InputStream inputStream) throws IOException {
    this.fid = fid;
    readObject(inputStream);
  }

  /**
   * Constructs a new CVCA file with default file identifier.
   *
   * @param caReference CA reference
   * @param altCAReference alternative CA reference
   */
  public CVCAFile(String caReference, String altCAReference) {
    this(PassportService.EF_CVCA, caReference, altCAReference);
  }

  /**
   * Constructs a new CVCA file with the given certificate references.
   *
   * @param fid file identifier
   * @param caReference main CA certificate reference
   * @param altCAReference second (alternative) CA certificate reference
   */
  public CVCAFile(short fid, String caReference, String altCAReference) {
    if (caReference == null
        || caReference.length() > 16
        || (altCAReference != null && altCAReference.length() > 16)) {
      throw new IllegalArgumentException();
    }
    this.fid = fid;
    this.caReference = caReference;
    this.altCAReference = altCAReference;
  }

  /**
   * Constructs a new CVCA file with the given certificate reference.
   *
   * @param fid file identifier
   * @param caReference main CA certificate reference
   */
  public CVCAFile(short fid, String caReference) {
    this(fid, caReference, null);
  }

  /**
   * Returns the file identifier of this CVCA file.
   *
   * @return the file identifier
   */
  public short getFID() {
    return fid;
  }

  @Override
  protected void readObject(InputStream inputStream) throws IOException {
    DataInputStream dataIn = new DataInputStream(inputStream);
    int tag = dataIn.read();
    if (tag != CAR_TAG) {
      throw new IllegalArgumentException("Wrong tag, expected " + Integer.toHexString(CAR_TAG) + ", found " + Integer.toHexString(tag));
    }
    int length = dataIn.read();
    if (length > 16) {
      throw new IllegalArgumentException("Wrong length");
    }
    byte[] data = new byte[length];
    dataIn.readFully(data);
    caReference = new String(data);
    tag = dataIn.read();
    if (tag != 0 && tag != -1) {
      if (tag != CAR_TAG) {
        throw new IllegalArgumentException("Wrong tag");
      }
      length = dataIn.read();
      if (length > 16) {
        throw new IllegalArgumentException("Wrong length");
      }
      data = new byte[length];
      dataIn.readFully(data);
      altCAReference = new String(data);
      tag = dataIn.read();
    }
    while (tag != -1) {
      if (tag != 0) {
        throw new IllegalArgumentException("Bad file padding");
      }
      tag = dataIn.read();
    }
  }

  @Override
  protected void writeObject(OutputStream outputStream) throws IOException {
    byte[] result = new byte[LENGTH];
    result[0] = CAR_TAG;
    result[1] = (byte)caReference.length();
    System.arraycopy(caReference.getBytes(), 0, result, 2, result[1]);
    if (altCAReference != null) {
      int index = result[1] + 2;
      result[index] = CAR_TAG;
      result[index + 1] = (byte)altCAReference.length();
      System.arraycopy(altCAReference.getBytes(), 0, result, index + 2,
          result[index + 1]);
    }
    outputStream.write(result);
  }

  /**
   * Returns the CA Certificate identifier.
   *
   * @return the CA Certificate identifier
   */
  public CVCPrincipal getCAReference() {
    return caReference == null ? null : new CVCPrincipal(caReference);
  }

  /**
   * Returns the second (alternative) CA Certificate identifier, null if none
   * exists.
   *
   * @return the second (alternative) CA Certificate identifier
   */
  public CVCPrincipal getAltCAReference() {
    return altCAReference == null ? null : new CVCPrincipal(altCAReference);
  }

  /**
   * Returns a textual representation of this CVCAFile.
   *
   * @return a textual representation of this CVCAFile
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("CA reference: \"").append(caReference).append("\"")
        .append(((altCAReference != null) ? ", Alternative CA reference: " + altCAReference : ""))
        .toString();
  }

  /**
   * Tests whether this CVCAFile is equal to the provided object.
   *
   * @param other some other object
   *
   * @return whether this CVCAFile equals the other object
   */
  @Override
  public boolean equals(Object other) {
    if (other == null) {
      return false;
    }
    if (!this.getClass().equals(other.getClass())) {
      return false;
    }

    CVCAFile otherCVCAFile = (CVCAFile)other;
    return caReference.equals(otherCVCAFile.caReference)
        && ((altCAReference == null && otherCVCAFile.altCAReference == null)
            || (altCAReference != null && altCAReference.equals(otherCVCAFile.altCAReference)));
  }

  /**
   * Computes a hash code of this CVCAFile.
   *
   * @return a hash code
   */
  @Override
  public int hashCode() {
    return 11 * caReference.hashCode()
        + ((altCAReference != null) ? 13 * altCAReference.hashCode() : 0)
        + 5;
  }

  /**
   * Returns the length of the content of this CVCA file. This always returns {@value #LENGTH}.
   *
   * @return {@value #LENGTH}
   */
  public int getLength() {
    return LENGTH;
  }
}
