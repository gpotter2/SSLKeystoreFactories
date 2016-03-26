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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * Util class to create SSLServerSocket using a KeyStore certificate to connect a server
 * 
 * @author gpotter2
 *
 */
public class SSLServerSocketKeystoreFactory {
	
	private static String instance;
	/**
	 * CONFIGURATION SECTION
	 */
	static {
		instance = "JKS"/* TODO REPLACE WITH BKS IF USING IT*/;
		/*
		 * Several Notes: 
		 * - Android only works with BKS, so you need to use only BKS certs files
		 * - As before Android 15, BKS-v1 was used, you need to convert BKS in BKS-v1 to use it in Android 15-; BUT as Android 23+ doesn't support BKS-v1
		 * and as BKS-v1 is deprecated, you need to have both of the certs and use them in fuction of the version
		 * - Java doesn't support BKS without library
		 * - A BKS format client can be connected a JKS format server
		 */
	}
	
	/**
	 * 
	 * A SSL algorithms types chooser enum
	 * 
	 * @author gpotter2
	 *
	 */
	public static enum ServerSecureType {
		@Deprecated
		SSL("SSL"),
		@Deprecated
		SSLv2("SSLv2"),
		SSLv3("SSLv3"),
		@Deprecated
		TLS("TLS"),
		@Deprecated
		TLSv1("TLSv1"),
		TLSv1_1("TLSv1.1"),
		TLSv1_2("TLSv1.2");
		
		private String type;
		
		private ServerSecureType(String type){
			this.type = type;
		}
		public String getType(){
			return type;
		}
	}
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessource()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLServerSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @throws UnrecoverableKeyException Cannot get the keys of the KeyStore
	 * @author gpotter2
	 */
	public static SSLServerSocket getServerSocketWithCert(int port, String pathToCert, String passwordFromCert, ServerSecureType type) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException{
		File f = new File(pathToCert);
		if(!f.exists()){
			new NullPointerException("The specified path point to a non existing file !");
			return null;
		}
		return getServerSocketWithCert(port, new FileInputStream(f), passwordFromCert, type);
	}
	
	/**
	 * 
	 * @param ip The IP to connect the socket to
	 * @param port The port of the socket
	 * @param pathToCert The path to the KeyStore cert (can be with getClass().getRessourceAsStream()....)
	 * @param passwordFromCert The password of the KeyStore cert
	 * @return The SSLServerSocket or null if the connection was not possible
	 * @throws IOException If the socket couldn't be created
	 * @throws KeyManagementException  If the KeyManager couldn't be loaded
	 * @throws CertificateException If the certificate is not correct (null or damaged) or the password is incorrect
	 * @throws NoSuchAlgorithmException If the certificate is from an unknown type
	 * @throws KeyStoreException If your system is not compatible with JKS KeyStore certificates
	 * @throws UnrecoverableKeyException Cannot get the keys of the KeyStore
	 * @author gpotter2
	 */
	public static SSLServerSocket getServerSocketWithCert(int port, InputStream pathToCert, String passwordFromCert, ServerSecureType type) throws IOException,
									KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException{
		X509TrustManager[] tmm;
		X509KeyManager[] kmm;
		KeyStore ks  = KeyStore.getInstance(instance);
		ks.load(pathToCert, passwordFromCert.toCharArray());
		tmm=tm(ks);
		kmm=km(ks, passwordFromCert);
		SSLContext ctx = SSLContext.getInstance(type.getType());
		ctx.init(kmm, tmm, null);
		SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) ctx.getServerSocketFactory();
		SSLServerSocket ssocket = (SSLServerSocket) socketFactory.createServerSocket(port);
		return ssocket;
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
	private static X509TrustManager[] tm(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustMgrFactory.init(keystore);
        TrustManager trustManagers[] = trustMgrFactory.getTrustManagers();
        for (int i = 0; i < trustManagers.length; i++) {
            if (trustManagers[i] instanceof X509TrustManager) {
            	X509TrustManager[] tr = new X509TrustManager[1];
            	tr[0] = (X509TrustManager) trustManagers[i];
                return tr;
            }
        }
        return null;
    };
    /**
     * Util class to get the X509KeyManager
     * 
     * @param keystore
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @author gpotter2
     */
    private static X509KeyManager[] km(KeyStore keystore, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
		KeyManagerFactory keyMgrFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyMgrFactory.init(keystore, password.toCharArray());
        KeyManager keyManagers[] = keyMgrFactory.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
            	X509KeyManager[] kr = new X509KeyManager[1];
            	kr[0] = (X509KeyManager) keyManagers[i];
                return kr;
            }
        }
        return null;
    };
}
