/*
 *  Copyright (C) 2015 Gabriel POTTER (gpotter2)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Util class to create SSLSocket using a KeyStore certificate to connect a server
 * 
 * @author gpotter2
 *
 */
public class SSLSocketKeystoreFactory {
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessource()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @author gpotter2
	 */
	public static SSLSocket getSocketWithCert(String ip, int port, String pathToCert, String passwordFromCert) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
		InetAddress ip2 = InetAddress.getByName(ip);
		if(ip2 == null){
			new NullPointerException("The ip must be a correct IP !").printStackTrace();
			return null;
		}
		File f = new File(pathToCert);
		if(!f.exists()){
			new NullPointerException("The specified path point to a non existing file !");
			return null;
		}
		return getSocketWithCert(ip2, port, new FileInputStream(f), passwordFromCert);
	}
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessourceAsStream()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @author gpotter2
	 */
	public static SSLSocket getSocketWithCert(String ip, int port, InputStream pathToCert, String passwordFromCert) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
		InetAddress ip2 = InetAddress.getByName(ip);
		if(ip2 == null){
			new NullPointerException("The ip must be a correct IP !").printStackTrace();
			return null;
		}
		return getSocketWithCert(ip2, port, pathToCert, passwordFromCert);
	}
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessource()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @author gpotter2
	 */
	public static SSLSocket getSocketWithCert(InetAddress ip, int port, String pathToCert, String passwordFromCert) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
		File f = new File(pathToCert);
		if(!f.exists()){
			new NullPointerException("The specified path point to a non existing file !");
			return null;
		}
		return getSocketWithCert(ip, port, new FileInputStream(f), passwordFromCert);
	}
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessourceAsStream()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @author gpotter2
	 */
	public static SSLSocket getSocketWithCert(InetAddress ip, int port, InputStream pathToCert, String passwordFromCert) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
		TrustManager[] tmm = new TrustManager[1];
		KeyStore ks  = KeyStore.getInstance("JKS");
		ks.load(pathToCert, passwordFromCert.toCharArray());
		tmm[0]=tm(ks);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tmm, null);
		SSLSocketFactory SocketFactory = (SSLSocketFactory) ctx.getSocketFactory();
		return (SSLSocket) SocketFactory.createSocket(ip, port);
	}
	
	/**
	 * Util class to get the X509TrustManager
	 * 
	 * 
	 * @param keystore
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @author gpotter2
	 */
	private static X509TrustManager tm(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustMgrFactory.init(keystore);
        TrustManager trustManagers[] = trustMgrFactory.getTrustManagers();
        for (int i = 0; i < trustManagers.length; i++) {
            if (trustManagers[i] instanceof X509TrustManager) {
                return (X509TrustManager) trustManagers[i];
            }
        }
        return null;
    };
}
