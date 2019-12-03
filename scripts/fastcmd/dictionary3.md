-----------------------------------------------------------------------------------------
https://github.com/rest-assured/rest-assured/wiki/Usage

@TestExecutionListeners(MockitoTestExecutionListener.class)
private Duration loginTimeout = Duration.ofSeconds(3);
-----------------------------------------------------------------------------------------
Type netsh winsock reset and press Enter.
Type netsh int ip reset and press Enter.
Type ipconfig /release and press Enter.
Type ipconfig /renew and press Enter.
Type ipconfig /flushdns and press Enter.
-----------------------------------------------------------------------------------------
@HypermediaDisabled
-----------------------------------------------------------------------------------------
sudo systemctl restart NetworkManager.service


nmcli nm enable false
sleep 5
nmcli nm enable true 

  sudo ip link set eth0 down
  sudo ip link set eth0 up
  
  
  sudo killall NetworkManager 
  
sudo -i
( ifdown $(ifquery --list -X lo|xargs echo) && ifup $(ifquery --list -X lo|xargs echo) )&

nmcli nm enable false eth0 && nmcli nm enable true eth0
-----------------------------------------------------------------------------------------
public class <T extends Self<T>> Self<T> {
    public T someMethodThatReturnsSelf() {
        return (T) this; //yeah, this ugly and generates warnings, but it does work.
    }
}
-----------------------------------------------------------------------------------------
https://github.com/yildirimabdullah/spring-kafka-test
https://mguenther.github.io/kafka-junit/
-----------------------------------------------------------------------------------------
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super("/api/**");
        this.setAuthenticationManager(authenticationManager);
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return super.requiresAuthentication(request, response);
    }
-----------------------------------------------------------------------------------------
@RestController
//@EnablePrometheusEndpoint
public class DemoApplication {
    private static final Counter requestTotal = Counter.build()
            .name("sample_counter")
            .labelNames("status")
            .help("A simple Counter to illustrate custom Counters in Spring Boot and Prometheus").register();

    @GetMapping("/test")
    public String testRequestMetrics() {
        final Random random = new Random(System.currentTimeMillis());
        if (random.nextInt(2) > 0) {
            requestTotal.labels("success").inc();
        } else {
            requestTotal.labels("error").inc();
        }
        return "Welcome to my world!";
    }
}
-----------------------------------------------------------------------------------------
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/web/admin/**").hasAnyRole(ADMIN.toString(), GUEST.toString())
                .anyRequest().permitAll()
                .and()
                .formLogin().loginPage("/web/login").permitAll()
                .and()
                .csrf().ignoringAntMatchers("/contact-email")
                .and()
                .logout().logoutUrl("/web/logout").logoutSuccessUrl("/web/").permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("admin").roles(ADMIN.toString())
                .and()
                .withUser("guest").password("guest").roles(GUEST.toString());
    }

}
-----------------------------------------------------------------------------------------
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.ServletRequest;
import javax.servlet.FilterChain;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
@WebFilter(urlPatterns = "/api/count")
public class ExampleFilter implements Filter{
    private static final Logger logger = LoggerFactory.getLogger(ExampleFilter.class);
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        logger.info("filter:"+ ((HttpServletRequest)servletRequest).getRequestURL());
        filterChain.doFilter(servletRequest, servletResponse);
    }
    @Override
    public void destroy() {
    }

-----------------------------------------------------------------------------------------
<project>
  ...
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>build-helper-maven-plugin</artifactId>
        <version>3.0.0</version>
        <executions>
          <execution>
            <id>timestamp-property</id>
            <goals>
              <goal>timestamp-property</goal>
            </goals>
            <configuration>
              <name>next.year</name>
              <pattern>yyyy</pattern>
              <unit>year</unit>
              <offset>+1</offset>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
  ...
</project>
-----------------------------------------------------------------------------------------
public interface HasContactInformation {
 
    String getFirstName();
    void setFirstName(String firstName);
 
    String getFullName();
 
    String getLastName();
    void setLastName(String lastName);
 
    String getPhoneNr();
    void setPhoneNr(String phoneNr);
 
}
And now an adapter as a support class:

@Data
public class ContactInformationSupport implements HasContactInformation {
 
    private String firstName;
    private String lastName;
    private String phoneNr;
 
    @Override
    public String getFullName() {
        return getFirstName() + " " + getLastName();
    }
}
The interesting part comes now, see how easy it is to now compose contact information into both model classes:

public class User implements HasContactInformation {
 
    // Whichever other User-specific attributes
 
    @Delegate(types = {HasContactInformation.class})
    private final ContactInformationSupport contactInformation =
            new ContactInformationSupport();
 
    // User itself will implement all contact information by delegation
     
}
-----------------------------------------------------------------------------------------
@echo off
start Brackets.exe %*

-----------------------------------------------------------------------------------------
@SupportedSourceVersion(SourceVersion.RELEASE_8)
-----------------------------------------------------------------------------------------
ftp.server.ip=129.9.100.10
ftp.server.port=21
ftp.client.name=read
ftp.client.password=readpdf
ftp.client.name.canwrite=capital
ftp.client.password.canwrite=capitalpass

https://www.programcreek.com/java-api-examples/index.php?project_name=kbastani%2Fspring-boot-starter-amazon-s3#
-----------------------------------------------------------------------------------------
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


@SpringBootApplication
public class RouteServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(RouteServiceApplication.class, args);
    }

    @Bean
    RestOperations restOperations() {
        RestTemplate restTemplate = new RestTemplate(new TrustEverythingClientHttpRequestFactory());
        restTemplate.setErrorHandler(new NoErrorsResponseErrorHandler());
        return restTemplate;
    }

    private static final class NoErrorsResponseErrorHandler extends DefaultResponseErrorHandler {

        @Override
        public boolean hasError(ClientHttpResponse response) throws IOException {
            return false;
        }

    }

    private static final class TrustEverythingClientHttpRequestFactory extends SimpleClientHttpRequestFactory {

        @Override
        protected HttpURLConnection openConnection(URL url, Proxy proxy) throws IOException {
            HttpURLConnection connection = super.openConnection(url, proxy);

            if (connection instanceof HttpsURLConnection) {
                HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;

                httpsConnection.setSSLSocketFactory(getSslContext(new TrustEverythingTrustManager()).getSocketFactory());
                httpsConnection.setHostnameVerifier(new TrustEverythingHostNameVerifier());
            }

            return connection;
        }

        private static SSLContext getSslContext(TrustManager trustManager) {
            try {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, new TrustManager[]{trustManager}, null);
                return sslContext;
            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);

            }

        }
    }

    private static final class TrustEverythingHostNameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }

    }

    private static final class TrustEverythingTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

    }

}
-----------------------------------------------------------------------------------------
import java.util.UUID;

/**
 * Created by alex on 2017/10/27.
 */
public class NonceUtils {
    public static String nonce() {
        return UUID.randomUUID().toString().replace("-", "").toLowerCase();
    }
}
-----------------------------------------------------------------------------------------
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by alex on 2017/10/22.
 */
public class DefaultCipherHelper implements CipherHelper {

    private final String ALGORITHM = "RSA";
    private final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private final String SIGN_ALGORITHMS = "SHA1WithRSA";

    private final String publicKey;
    private final String privateKey;

    public DefaultCipherHelper(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] encrypt(byte[] plaintext) {
        try {
            // 使用默认RSA
            RSAPublicKey publicKey = createPublicKey(this.publicKey);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            int bitLengthOfPuk = publicKey.getModulus().bitLength() / 8;
            int blockSize = bitLengthOfPuk - 11;
            if (plaintext.length > blockSize) {
                List<byte[]> blocks = block(plaintext, blockSize);
                ByteBuffer buffer = ByteBuffer.allocate(blocks.size() * bitLengthOfPuk);
                for (byte[] block : blocks) {
                    buffer.put(cipher.doFinal(block));
                }
                return buffer.array();
            } else {
                return cipher.doFinal(plaintext);
            }

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("padding算法不存在");
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("明文长度非法");
        } catch (BadPaddingException e) {
            throw new RuntimeException("明文数据已损坏");
        }
    }

    public byte[] decrypt(byte[] ciphertext) {
        try {
            // 使用默认RSA
            RSAPrivateKey privateKey = createPrivateKey(this.privateKey);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            int blockSize = privateKey.getModulus().bitLength() / 8;
            if (ciphertext.length > blockSize) {
                List<byte[]> blocks = block(ciphertext, blockSize);
                ByteBuffer buffer = ByteBuffer.allocate(blocks.size() * blockSize);
                for (byte[] block : blocks) {
                    buffer.put(cipher.doFinal(block));
                }

                buffer.flip();
                byte[] result = new byte[buffer.limit()];
                buffer.get(result);
                return result;
            } else {
                return cipher.doFinal(ciphertext);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("padding算法不存在");
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("明文长度非法");
        } catch (BadPaddingException e) {
            throw new RuntimeException("明文数据已损坏");
        }
    }


    public byte[] sign(byte[] data, byte[] nonce) {
        try {
            PrivateKey privateKey = createPrivateKey(this.privateKey);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(privateKey);

            byte[] withSalt = concat(data, nonce);

            signature.update(withSalt);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法");
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密公钥非法,请检查");
        } catch (SignatureException e) {
            throw new RuntimeException("签名异常");
        }
    }

    public boolean verify(byte[] data, byte[] nonce, byte[] signature) {
        try {
            PublicKey publicKey = createPublicKey(this.publicKey);
            Signature instance = Signature.getInstance(SIGN_ALGORITHMS);
            instance.initVerify(publicKey);
            byte[] withSalt = concat(data, nonce);
            instance.update(withSalt);
            return instance.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法");
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密公钥非法,请检查");
        } catch (SignatureException e) {
            throw new RuntimeException("签名异常");
        }
    }


    private RSAPublicKey createPublicKey(String puk) {
        try {
            byte[] buffer = Base64.decodeBase64(puk);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            KeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("公钥非法");
        } catch (NullPointerException e) {
            throw new RuntimeException("公钥数据为空");
        }
    }

    private RSAPrivateKey createPrivateKey(String prk) {
        try {
            byte[] buffer = Base64.decodeBase64(prk);
            KeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("私钥非法");
        } catch (NullPointerException e) {
            throw new RuntimeException("私钥数据为空");
        }
    }

    private byte[] concat(byte[] b1, byte[] b2) {
        byte[] withSalt = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, withSalt, 0, b1.length);
        System.arraycopy(b2, 0, withSalt, b1.length, b2.length);
        return withSalt;
    }

    private List<byte[]> block(byte[] src, int blockSize) {
        int group;
        if (src.length % blockSize == 0) {
            group = src.length / blockSize;
        } else {
            group = src.length / blockSize + 1;
        }

        List<byte[]> blocks = new ArrayList<byte[]>();
        for (int i = 0; i < group; i++) {
            int from = i * blockSize;
            int to = Math.min(src.length, (i + 1) * blockSize);

            byte[] block = Arrays.copyOfRange(src, from, to);

            blocks.add(block);
        }
        return blocks;
    }

}
-----------------------------------------------------------------------------------------
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;

@Aspect
public class RemoteWebDriverAspect {

    @Before("call(org.openqa.selenium.remote.RemoteWebDriver+.new(..))")
    @SuppressWarnings("PMD.AvoidCatchingThrowable")
    public void remoteWebDriverBeforeAspect(JoinPoint joinPoint) throws Throwable {
        System.out.println("Before Creating driver...");
    }

    @Around("call(org.openqa.selenium.remote.RemoteWebDriver+.new(..))")
    @SuppressWarnings("PMD.AvoidCatchingThrowable")
    public Object remoteWebDriverAspect(ProceedingJoinPoint point) throws Throwable {

        //Code to run before creating the driver
        long startTime = System.currentTimeMillis();
        System.out.println("\n[" + elapsedTime(startTime) + "] Trying to create a Remote Web Driver");
        Object driver = null;
        int numOfRetries = 0;
        while (driver == null & numOfRetries < Constants.MaxTimesToRetry) {
            try {
                System.out.println("[" + elapsedTime(startTime) + "] Try number : " + numOfRetries);
                driver = point.proceed();
            } catch (Throwable throwable) {
                System.out.println("[" + elapsedTime(startTime) + "] Device allocation failed");
                String message = throwable.getMessage();
                System.out.println(message);
                numOfRetries++;
                Thread.sleep(Constants.WaitOnRetry);
            }
        }

        if (driver != null) {
            //Code to run after successfully creating a driver
            System.out.println("[" + elapsedTime(startTime) + "] Remote Web Driver initialized successfully");
        }

        else {
            //Code to run when used up retries with no success
            System.out.println("[" + elapsedTime(startTime) + "] Failed to initialize a Remote Web Driver");
            //Throw exception?
        }

        return driver;
    }

    private long elapsedTime(long startTime){
        return (System.currentTimeMillis() - startTime) / 1000;
    }
}
-----------------------------------------------------------------------------------------
	private static void handleError(HttpURLConnection connection) throws IOException {
		String msg = "Failed to upload media.";
		InputStream errorStream = connection.getErrorStream();
		if (errorStream != null) {
			InputStreamReader inputStreamReader = new InputStreamReader(errorStream, UTF_8);
			BufferedReader bufferReader = new BufferedReader(inputStreamReader);
			try {
				StringBuilder builder = new StringBuilder();
				String outputString;
				while ((outputString = bufferReader.readLine()) != null) {
					if (builder.length() != 0) {
						builder.append("\n");
					}
					builder.append(outputString);
				}
				String response = builder.toString();
				msg += "Response: " + response;
			}
			finally {
				bufferReader.close();
			}
		}
		throw new RuntimeException(msg);
	}

	private static byte[] readFile(File path) throws FileNotFoundException, IOException {
		int length = (int)path.length();
		byte[] content = new byte[length];
		InputStream inStream = new FileInputStream(path);
		try {
			inStream.read(content);
		}
		finally {
			inStream.close();
		}
		return content;
	}

	private static byte[] readURL(URL url) throws IOException {
		HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		connection.setDoOutput(true);
		int code = connection.getResponseCode();
		if (code > HttpURLConnection.HTTP_OK) {
			handleError(connection);
		}
		InputStream stream = connection.getInputStream();

		if (stream == null) {
			throw new RuntimeException("Failed to get content from url " + url + " - no response stream");
		}
		byte[] content = read(stream);
		return content;
	}

	private static byte[] read(InputStream input) throws IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		try {
			byte[] buffer = new byte[1024];
			int nBytes = 0;
			while ((nBytes = input.read(buffer)) > 0) {
				output.write(buffer, 0, nBytes);
			}
			byte[] result = output.toByteArray();
			return result;
		} finally {
			try{
				input.close();
			} catch (IOException e){

			}
		}
	}
-----------------------------------------------------------------------------------------
import io.prometheus.client.Summary;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.context.annotation.Scope;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * This class automatically times (via aspectj) the execution of annotated methods, if it's been enabled via {@link EnablePrometheusTiming},
 * for methods annotated with {@link PrometheusTimeMethod}
 *
 * @author Andrew Stuart
 */
@Aspect("pertarget(io.prometheus.client.spring.web.MethodTimer.timeable())")
@Scope("prototype")
@ControllerAdvice
public class MethodTimer {
    private final ReadWriteLock summaryLock = new ReentrantReadWriteLock();
    private final HashMap<String, Summary> summaries = new HashMap<String, Summary>();

    @Pointcut("@annotation(io.prometheus.client.spring.web.PrometheusTimeMethod)")
    public void annotatedMethod() {}

    @Pointcut("annotatedMethod()")
    public void timeable() {}

    private PrometheusTimeMethod getAnnotation(ProceedingJoinPoint pjp) throws NoSuchMethodException {
        assert(pjp.getSignature() instanceof MethodSignature);
        MethodSignature signature = (MethodSignature) pjp.getSignature();

        PrometheusTimeMethod annot = AnnotationUtils.findAnnotation(pjp.getTarget().getClass(), PrometheusTimeMethod.class);
        if (annot != null) {
            return annot;
        }

        // When target is an AOP interface proxy but annotation is on class method (rather than Interface method).
        final String name = signature.getName();
        final Class[] parameterTypes = signature.getParameterTypes();
        Method method = ReflectionUtils.findMethod(pjp.getTarget().getClass(), name, parameterTypes);
        return AnnotationUtils.findAnnotation(method, PrometheusTimeMethod.class);
    }

    private Summary ensureSummary(ProceedingJoinPoint pjp, String key) throws IllegalStateException {
        PrometheusTimeMethod annot;
        try {
            annot = getAnnotation(pjp);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Annotation could not be found for pjp \"" + pjp.toShortString() +"\"", e);
        } catch (NullPointerException e) {
            throw new IllegalStateException("Annotation could not be found for pjp \"" + pjp.toShortString() +"\"", e);
        }

        assert(annot != null);

        Summary summary;

        // We use a writeLock here to guarantee no concurrent reads.
        final Lock writeLock = summaryLock.writeLock();
        writeLock.lock();
        try {
            // Check one last time with full mutual exclusion in case multiple readers got null before creation.
            summary = summaries.get(key);
            if (summary != null) {
                return summary;
            }

            // Now we know for sure that we have never before registered.
            summary = Summary.build()
                    .name(annot.name())
                    .help(annot.help())
                    .register();

            // Even a rehash of the underlying table will not cause issues as we mutually exclude readers while we
            // perform our updates.
            summaries.put(key, summary);

            return summary;
        } finally {
            writeLock.unlock();
        }
    }

    @Around("timeable()")
    public Object timeMethod(ProceedingJoinPoint pjp) throws Throwable {
        String key = pjp.getSignature().toLongString();

        Summary summary;
        final Lock r = summaryLock.readLock();
        r.lock();
        try {
            summary = summaries.get(key);
        } finally {
            r.unlock();
        }

        if (summary == null) {
            summary = ensureSummary(pjp, key);
        }

        final Summary.Timer t = summary.startTimer();

        try {
            return pjp.proceed();
        } finally {
            t.observeDuration();
        }
    }
}
-----------------------------------------------------------------------------------------
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.tree.xpath.XPathExpressionEngine;

/**
 * @author Chirag Jayswal
 *
 */
public class XPathUtils {

	/**
	 * 
	 * @param xmlFile
	 * @return
	 * @throws IOException
	 */
	public static XMLConfiguration read(File xmlFile) throws IOException{
		String xmlsrc = FileUtil.readFileToString(xmlFile, "UTF-8");
		return read(xmlsrc);
	}
	
	/**
	 * 
	 * @param src
	 * @return
	 */
	public static XMLConfiguration read(String src) {
		try {
			// remove all namespaces from xml
			src = removeNSAndPreamble(src);
			XMLConfiguration config = new XMLConfiguration();
			config.setDelimiterParsingDisabled(true);
			config.load(new ByteArrayInputStream(src.getBytes()));
			config.setExpressionEngine(new XPathExpressionEngine());
			return config;

		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * @param xmlStr
	 * @return
	 */
	private static String removeNSAndPreamble(String xmlStr) {
		String xsltString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:output method=\"xml\" indent=\"yes\" encoding=\"UTF-8\"/><xsl:template match=\"/\"><xsl:copy><xsl:apply-templates/></xsl:copy></xsl:template><xsl:template match=\"@*\"><xsl:attribute name=\"{local-name()}\"><xsl:value-of select=\"current()\"/></xsl:attribute></xsl:template><xsl:template match=\"*\"><xsl:element name=\"{local-name()}\"><xsl:apply-templates select=\"@* | * | text()\"/></xsl:element></xsl:template><xsl:template match=\"text()\"><xsl:copy><xsl:value-of select=\"current()\"/></xsl:copy></xsl:template></xsl:stylesheet>";
		try (ByteArrayOutputStream bo = new ByteArrayOutputStream()) {
			TransformerFactory factory = TransformerFactory.newInstance();
			Source xslt = new StreamSource(new ByteArrayInputStream(xsltString.getBytes()));
			Transformer transformer = factory.newTransformer(xslt);

			Source xmlSrc = new StreamSource(new ByteArrayInputStream(xmlStr.getBytes()));
			transformer.transform(xmlSrc, new StreamResult(bo));
			return bo.toString();
		} catch (TransformerException e) {
			System.err.println(e.getMessage());
		} catch (IOException e1) {
			System.err.println(e1.getMessage());
		}

		System.err.println("Unable to clean Namespace and Preamble from xml source, will use unmodified xml.");
		return xmlStr;
	}
}
-----------------------------------------------------------------------------------------
import java.lang.reflect.Method;
import java.util.regex.Pattern;

public abstract class StringMatcher {
	protected String stringToMatch;

	public StringMatcher(String stringToMatch) {
		this.stringToMatch = stringToMatch;
	}

	@Override
	public String toString() {
		return this.getClass().getSimpleName() + ":" + stringToMatch;
	}

	abstract public boolean match(String target);

	/**
	 * provision for define matcher in external data file, that can be converted
	 * to actual one in code!
	 * 
	 * @param type
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher get(String type, String stringToMatch) {
		try {
			Method m = ClassUtil.getMethod(StringMatcher.class, type);
			return (StringMatcher) m.invoke(null, stringToMatch);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static StringMatcher exact(String stringToMatch) {
		return new Exact(stringToMatch);
	}

	public static StringMatcher exactIgnoringCase(String stringToMatch) {
		return new ExactIgnoringCase(stringToMatch);
	}

	public static StringMatcher startsWith(String stringToMatch) {
		return new StartsWith(stringToMatch);
	}

	public static StringMatcher startsWithIgnoringCase(String stringToMatch) {
		return new StartsWithIgnoringCase(stringToMatch);
	}

	public static StringMatcher endsWith(String stringToMatch) {
		return new EndsWith(stringToMatch);
	}

	public static StringMatcher endsWithIgnoringCase(String stringToMatch) {
		return new EndsWithIgnoringCase(stringToMatch);
	}

	public static StringMatcher contains(String stringToMatch) {
		return new Contains(stringToMatch);
	}

	public static StringMatcher containsIgnoringCase(String stringToMatch) {
		return new ContainsIgnoringCase(stringToMatch);
	}

	/**
	 * @param stringToMatch
	 *            : valid regular expression
	 * @return
	 */
	public static StringMatcher like(String stringToMatch) {
		return new Like(stringToMatch);
	}

	/**
	 * @param stringToMatch
	 *            : valid regular expression
	 * @return
	 */
	public static StringMatcher likeIgnoringCase(String stringToMatch) {
		return new LikeIgnoringCase(stringToMatch);
	}

	/**
	 * Numeric greater then
	 * 
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher gt(String stringToMatch) {
		return new GT(stringToMatch);
	}

	/**
	 * Numeric greater then equal
	 * 
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher gte(String stringToMatch) {
		return new GTE(stringToMatch);
	}

	/**
	 * Numeric less then
	 * 
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher lt(String stringToMatch) {
		return new LT(stringToMatch);
	}

	/**
	 * Numeric less then equal
	 * 
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher lte(String stringToMatch) {
		return new LTE(stringToMatch);
	}

	/**
	 * Numeric equal
	 * 
	 * @param stringToMatch
	 * @return
	 */
	public static StringMatcher eq(String stringToMatch) {
		return new EQ(stringToMatch);
	}

	private static class Exact extends StringMatcher {

		Exact(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return stringToMatch.equals(target);
		}

	}

	private static class ExactIgnoringCase extends StringMatcher {
		ExactIgnoringCase(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return stringToMatch.equalsIgnoreCase(target);
		}

	}

	private static class StartsWithIgnoringCase extends StringMatcher {
		StartsWithIgnoringCase(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.toUpperCase().startsWith(stringToMatch.toUpperCase());
		}
	}

	private static class StartsWith extends StringMatcher {
		StartsWith(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.startsWith(stringToMatch);
		}
	}

	private static class EndsWithIgnoringCase extends StringMatcher {
		EndsWithIgnoringCase(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.toUpperCase().endsWith(stringToMatch.toUpperCase());
		}
	}

	private static class EndsWith extends StringMatcher {
		EndsWith(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.endsWith(stringToMatch);
		}
	}

	private static class ContainsIgnoringCase extends StringMatcher {
		ContainsIgnoringCase(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.toUpperCase().contains(stringToMatch.toUpperCase());
		}
	}

	private static class Contains extends StringMatcher {
		Contains(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return target.contains(stringToMatch);
		}
	}

	private static class LikeIgnoringCase extends StringMatcher {
		LikeIgnoringCase(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			Pattern p = Pattern.compile(stringToMatch, Pattern.CASE_INSENSITIVE);
			return p.matcher(target).matches();
		}
	}

	private static class Like extends StringMatcher {
		Like(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			return Pattern.matches(stringToMatch, target);
		}
	}

	private static class EQ extends StringMatcher {
		EQ(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			try {
				double expected = Double.parseDouble(stringToMatch);
				double actual = Double.parseDouble(target);

				return actual == expected;
			} catch (Exception e) {
				return false;
			}
		}
	}

	private static class LT extends StringMatcher {
		LT(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			try {
				double expected = Double.parseDouble(stringToMatch);
				double actual = Double.parseDouble(target);

				return actual < expected;
			} catch (Exception e) {
				return false;
			}
		}
	}

	private static class LTE extends StringMatcher {
		LTE(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			try {
				double expected = Double.parseDouble(stringToMatch);
				double actual = Double.parseDouble(target);

				return actual <= expected;
			} catch (Exception e) {
				return false;
			}
		}
	}

	private static class GT extends StringMatcher {
		GT(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			try {
				double expected = Double.parseDouble(stringToMatch);
				double actual = Double.parseDouble(target);

				return actual > expected;
			} catch (Exception e) {
				return false;
			}
		}
	}

	private static class GTE extends StringMatcher {
		GTE(String stringToMatch) {
			super(stringToMatch);
		}

		@Override
		public boolean match(String target) {
			try {
				double expected = Double.parseDouble(stringToMatch);
				double actual = Double.parseDouble(target);

				return actual >= expected;
			} catch (Exception e) {
				return false;
			}
		}
	}

}
-----------------------------------------------------------------------------------------
"OAuth2": {
  "type": "oauth2",
  "flow": "accessCode",
  "authorizationUrl": "https://your-auth-domain.com/oauth/authorize",
  "tokenUrl": "https://your-auth-domain.com/oauth/token",
  "scopes": {
    "read": "Grants read access to user resources",
    "write": "Grants write access to user resources",
    "admin": "Grants read and write access to administrative information"
  }
}
-----------------------------------------------------------------------------------------
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Use to map Form Bean property with UI form fields.
 * com.qmetry.qaf.automation.core.ui.annotations.UiElement.java
 * 
 * @author chirag
 */

@Target(value = ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface FindBy {

	/**
	 * specify locator in conventional selenium 1 way.
	 * 
	 * @return
	 */
	public String locator();
}

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.qmetry.qaf.automation.data.BaseFormDataBean;
import com.qmetry.qaf.automation.ui.webdriver.QAFExtendedWebElement;

/**
 * Use to map Form Bean property with UI form fields.
 * com.qmetry.qaf.automation.core.ui.annotations.UiElement.java
 * 
 * @author chirag
 */

@Target(value = ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface UiElement {
	public enum Type {

		textbox,
		selectbox,
		checkbox,
		file,
		/**
		 * Radio button(s)
		 */
		optionbox,
		textarea,
		multiselectbox,
		/**
		 * HTML element other than form field
		 */
		text;
	}

	/**
	 * specify locator of form field.
	 * 
	 * @return
	 */
	public String fieldLoc();

	/**
	 * specify type of form field. Default is {@link Type#textbox}
	 * 
	 * @return
	 */
	public Type fieldType() default Type.textbox;

	/**
	 * mapping with data-view : if this form field value reflected in other view
	 * page then specify locator of that field
	 * 
	 * @return
	 */
	public String viewLoc() default "";

	/**
	 * specify type of view element. default is {@link Type#text}
	 * 
	 * @return
	 */
	public Type viewType() default Type.text;

	public String defaultValue() default "";

	/**
	 * specify filed name on which this field is depends. This is use full in
	 * case of parent-child fields where child filed enabled/appears depending
	 * on value of parent field.
	 * 
	 * @return
	 */
	public String dependsOnField() default "";

	/**
	 * Specify value of parent field which enables this field. Used with
	 * {@link #dependsOnField()}. You can use JavaScript notation for value
	 * comparison. Some valid Example:
	 * 
	 * <pre>
	 * <code>	
	 * &#64;UiElement(fieldLoc = DOMAIN_SELECT_LOC, fieldType = Type.selectbox, order = 1)
	 * private String domain;
	 * 	
	 * &#64;UiElement(fieldLoc = NAME_INPUT_LOC, fieldType = Type.selectbox, dependsOnField = "domain", dependingValue = "DUNS", order=3)
	 * public String name;
	 * </code>
	 * <code>		
	 * This can also be written as:
	 * &#64;UiElement(fieldLoc = NAME_INPUT_LOC, fieldType = Type.selectbox, dependsOnField = "domain", dependingValue = "${domain}=='DUNS'", order=3)
	 * public String name;
	 * </code>
	 * &#64;UiElement(fieldLoc = PASSWORD_INPUT_LOC, fieldType = Type.selectbox, dependsOnField = "domain", dependingValue = "${domain}!='DUNS' && ${domain}!='GLN'", order=3)
	 * public String password;
	 * </pre>
	 * 
	 * <br>
	 * Make sure that you have specified {@link #order()} of parent filed less
	 * then child field.
	 * 
	 * @return
	 */
	public String dependingValue() default "";

	/**
	 * specify whether this form field is read-only? Default is false.
	 * 
	 * @return
	 */
	public boolean readonly() default false;

	/**
	 * specify whether is this a required form field? Default is false. It is
	 * used when you want to fill just required form fields.
	 * 
	 * @see BaseFormDataBean#fillUiRequiredElements()
	 * @return
	 */
	public boolean required() default false;

	/**
	 * Specify the order in which form fields should be filled in UI. Default is
	 * {@link Integer#MAX_VALUE}
	 * 
	 * @return
	 */
	public int order() default Integer.MAX_VALUE;

	/**
	 * Specify whether wait for page load required or not, after fill UI data.
	 * Default is false
	 * @deprecated
	 * @return
	 */
	public boolean pagewait() default false;

	/**
	 * Optional, can be used to specify custom component to interact with UI. In case
	 * of custom component, it must have constructor with one argument as string
	 * to accept locator
	 * 
	 * @since 2.1.9
	 * @return
	 */
	public Class<? extends QAFExtendedWebElement> elementClass() default QAFExtendedWebElement.class;

}
-----------------------------------------------------------------------------------------
	/**
	 * 
	 * @param expression
	 * @return
	 * @throws ScriptException
	 */
	public static <T> T eval(String expression) throws ScriptException {
		return eval(expression, new HashMap<String, Object>());
	}

	/**
	 * 
	 * @param expression
	 * @param context
	 * @return
	 * @throws ScriptException
	 */
	@SuppressWarnings("unchecked")
	public static <T> T eval(String expression, Map<? extends String, ? extends Object> context)
			throws ScriptException {
		ScriptEngineManager engineManager = new ScriptEngineManager();
		ScriptEngine jsEngine = engineManager.getEngineByName("JavaScript");
		jsEngine.getBindings(ScriptContext.ENGINE_SCOPE).putAll(context);
		return (T) jsEngine.eval(expression);
	}
-----------------------------------------------------------------------------------------
/**
 * Tiles configuration.
 * 
 * References: http://docs.spring.io/spring/docs/4.0.6.RELEASE/spring-framework-reference/html/view.html#view-tiles-integrate
 * 
 * @author Mark Meany
 */
@Configuration
public class ConfigurationForTiles {

    /**
     * Initialise Tiles on application startup and identify the location of the tiles configuration file, tiles.xml.
     * 
     * @return tiles configurer
     */
    @Bean
    public TilesConfigurer tilesConfigurer() {
        final TilesConfigurer configurer = new TilesConfigurer();
        configurer.setDefinitions(new String[] { "WEB-INF/tiles/tiles.xml" });
        configurer.setCheckRefresh(true);
        return configurer;
    }

    /**
     * Introduce a Tiles view resolver, this is a convenience implementation that extends URLBasedViewResolver.
     * 
     * @return tiles view resolver
     */
    @Bean
    public TilesViewResolver tilesViewResolver() {
        final TilesViewResolver resolver = new TilesViewResolver();
        resolver.setViewClass(TilesView.class);
        return resolver;
    }
}
-----------------------------------------------------------------------------------------
spring.jpa.database-platform=org.hibernate.dialect.MySQL5Dialect

################### DATASOURCE :  数据库 mysql 用于生产中 ##########################
# 默认使用  Tomcat pooling，数据源可以 通过 spring.datasource 进一步设置
spring.datasource.url=jdbc:mysql://localhost:3306/ztree?autoReconnect=true&useSSL=false
spring.datasource.username=ztree
spring.datasource.password=ztree
#spring.datasource.driver-class-name=com.mysql.jdbc.Driver 可以不指定,spring boot 可以自动从 url 分析得到
#
spring.datasource.max-active= 20
spring.datasource.max-idle= 1
spring.datasource.max-wait= 1
spring.datasource.min-idle=1
#  min-evictable-idle-time-millis :配置一个连接在池中最小生存的时间，单位是毫秒
spring.datasource.min-evictable-idle-time-millis= 300000
# time-between-eviction-runs-millis : 配置间隔多久才进行一次检测需要关闭的空闲连接，单位是毫秒
spring.datasource.time-between-eviction-runs-millis= 60000
spring.datasource.test-on-borrow= false
spring.datasource.test-on-return= false
spring.datasource.test-while-idle= true
#默认用的 tomcat jdbc poll,其中 validation-query=
#mysql:  SELECT 1
#oracle : select 1 from dual
#MS Sql Server : SELECT 1
spring.datasource.validation-query=SELECT 1
-----------------------------------------------------------------------------------------

import com.igormaznitsa.meta.annotation.Weight;
import com.igormaznitsa.meta.common.exceptions.MetaErrorListeners;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Auxiliary methods for IO operations.
 *
 * @since 1.0
 */
@ThreadSafe
public final class IOUtils {

  private IOUtils() {
  }

  /**
   * Pack some binary data.
   *
   * @param data data to be packed
   * @return packed data as byte array
   * @since 1.0
   */
  @Nonnull
  @Weight(Weight.Unit.VARIABLE)
  public static byte[] packData(@Nonnull final byte[] data) {
    final Deflater compressor = new Deflater(Deflater.BEST_COMPRESSION);
    compressor.setInput(Assertions.assertNotNull(data));
    compressor.finish();
    final ByteArrayOutputStream resultData = new ByteArrayOutputStream(data.length + 100);

    final byte[] buffer = new byte[1024];
    while (!compressor.finished()) {
      resultData.write(buffer, 0, compressor.deflate(buffer));
    }

    return resultData.toByteArray();
  }

  /**
   * Unpack binary data packed by the packData method.
   *
   * @param data packed data array
   * @return unpacked byte array
   * @throws IllegalArgumentException it will be thrown if the data has wrong format, global error listeners will be also notified
   * @see #packData(byte[])
   * @since 1.0
   */
  @Nonnull
  @Weight(Weight.Unit.VARIABLE)
  public static byte[] unpackData(@Nonnull final byte[] data) {
    final Inflater decompressor = new Inflater();
    decompressor.setInput(Assertions.assertNotNull(data));
    final ByteArrayOutputStream outStream = new ByteArrayOutputStream(data.length * 2);
    final byte[] buffer = new byte[1024];
    try {
      while (!decompressor.finished()) {
        outStream.write(buffer, 0, decompressor.inflate(buffer));
      }
      return outStream.toByteArray();
    } catch (DataFormatException ex) {
      MetaErrorListeners.fireError("Can't unpack data for wrong format", ex);
      throw new IllegalArgumentException("Wrong formatted data", ex);
    }
  }

  /**
   * Closing quetly any closeable object. Any exception will be caught (but global error listeners will be notified)
   *
   * @param closeable object to be closed quetly
   * @return the same object provided in args
   * @since 1.0
   */
  @Weight(Weight.Unit.LIGHT)
  @Nullable
  public static Closeable closeQuetly(@Nullable final Closeable closeable) {
    if (closeable != null) {
      try {
        closeable.close();
      } catch (Exception ex) {
        MetaErrorListeners.fireError("Exception in closeQuetly", ex);
      }
    }
    return closeable;
  }
}
-----------------------------------------------------------------------------------------
TransactionSupportAsyncJobServiceTest.test_async_job_execute:112 
-----------------------------------------------------------------------------------------
paragon.mailingcontour.commons
paragon.mailingcontour.autotests
paragon.mailingcontour.freecoupons
paragon.mailingcontour.crmadapter
paragon.mailingcontour.distributor
paragon.mailingcontour.mailer
paragon.mailingcontour.documents.generator
paragon.mailingcontour.confirmationlink.callback
paragon.mailingcontour.bounceparser
paragon.mailingcontour.crmmailadapter
paragon.mailingcontour.confirmationlink
paragon.mailingcontour.links

{
	"sku": <sku>,
	"name": <name>,
	"versions":
	[{
		"version": <version>,
		"locale": <locale>,
		"changelog": <changelog>,
		"files":
		[{
			"fileName": <file-name>,
			"filePath": <file-path>,
			"filePlatform": <file-platform>
		}]
	}]
}

{
	"sku": <sku>,
	"name": <name>
}

{
	"productId": <product-id>,
	"fileName": <file-name>,
	"filePath": <file-path>
	"platform": <platform>
}

sku=PSG-1770-BSU-SE-TL-1Y&locale=ru&platform=x86
-----------------------------------------------------------------------------------------
	@DeprecatedConfigurationProperty(reason = "replaced to support additional strategies",
			replacement = "server.forward-headers-strategy")
-----------------------------------------------------------------------------------------
import ngSpring.demo.domain.dto.UserProfileDTO;
import ngSpring.demo.domain.entities.User;
import ngSpring.demo.repositories.UserRepository;
import ngSpring.demo.transformer.GenericTransformer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserProfileTransformer extends GenericTransformer<User, UserProfileDTO> {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User transformToEntity(UserProfileDTO dto) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return User.builder()
                .userId(dto.getUserId())
                .username(dto.getUsername())
                .password(dto.getPassword() != null ? passwordEncoder.encode(dto.getPassword()) : this.userRepository.findByUserIdAndDeletedFalse(dto.getUserId()).getPassword())
                .build();
    }

    @Override
    public UserProfileDTO transformToDTO(User user) {
        return UserProfileDTO.builder()
                .userId(user.getUserId())
                .username(user.getUsername())
                .build();
    }
}
-----------------------------------------------------------------------------------------
   @ExceptionHandler(ValidationException.class)
    @ResponseBody
    public ResponseEntity<?> handleBadRequestException(ValidationException ex) {
        LOG.error("Got validation errors", ex);
        if (ex.getValidationMessages() == null || ex.getValidationMessages().isEmpty()) {
            return new ResponseEntity<Message>(new Message(ex.getMessage()), HttpStatus.BAD_REQUEST);
        } else {
            return new ResponseEntity<List<ValidationMessage>>(ex.getValidationMessages(), HttpStatus.BAD_REQUEST);
        }
    }
	
	    private List<ValidationMessage> getValidationErrorResponse(ConstraintViolationException constraintViolationException) {
        final List<ValidationMessage> validationErrors = new ArrayList<>();
        LOG.error("Got validation errors", constraintViolationException);
        for (ConstraintViolation<?> violationSet : constraintViolationException.getConstraintViolations()) {
            List<String> propertyList = new ArrayList<>();
            Iterator<Path.Node> propertyIterator = violationSet
                    .getPropertyPath().iterator();
            while (propertyIterator.hasNext()) {
                propertyList.add(propertyIterator.next().getName());
            }
            // add violations errors in response
            validationErrors.add(ValidationMessage.builder()
                    .entity(violationSet.getRootBeanClass().getName())
                            // remove { and }
                    .messageTemplate(violationSet.getMessageTemplate().replaceAll("^[{]|[}]$", ""))
                    .propertyList(propertyList).build());
        }
        return validationErrors;
    }
-----------------------------------------------------------------------------------------
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.specification.RequestSpecification;
import ngSpring.demo.AngularSpringApplication;
import ngSpring.demo.domain.entities.User;
import ngSpring.demo.repositories.EventRepository;
import ngSpring.demo.repositories.UserRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static com.jayway.restassured.RestAssured.given;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("test")
@SpringApplicationConfiguration(classes = AngularSpringApplication.class)
@WebAppConfiguration
@IntegrationTest("server.port:0")
public abstract class RestITBase {

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private UserRepository userRepository;

    @Value("${local.server.port}")
    protected int port;

    @Before
    public void setUp() throws ParseException {
        RestAssured.port = port;
        userRepository.save(User.builder()
                .enabled(true)
                .username("user")
                .password(new BCryptPasswordEncoder().encode("password"))
                .build());
    }

    @After
    public void clean() {
        try {
            this.userRepository.deleteAll();
            this.eventRepository.deleteAll();
        } catch (Exception ignored) {
        }
    }

    protected UserRepository getUserRepository() {
        return userRepository;
    }

    public EventRepository getEventRepository() {
        return eventRepository;
    }

    protected int getPort() {
        return port;
    }

    protected RequestSpecification login(String user, String password) {
        return given().auth().preemptive().basic(user, password).redirects()
                .follow(false);
    }

    protected String toJSON(Object entity) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(entity);
        } catch (Exception e) {
            return "";
        }
    }

    protected String toJSON(Map<String, String> map) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(map);
        } catch (Exception ignored) {
            return "";
        }
    }

    // HELPERS
    protected RequestSpecification loginWithCorrectCredentials() {
        return login("user", "password");
    }

    protected RequestSpecification loginWithIncorrectCredentials() {
        return login("user", "blub");
    }

    protected RequestSpecification loginWithEmptyCredentials() {
        return given().auth().none().redirects().follow(false);
    }

    public class JSONBuilder {

        private Map<String, String> properties = new HashMap<String, String>();

        public JSONBuilder add(String key, String value) {
            this.properties.put(key, value);
            return this;
        }

        public String build() {
            return toJSON(this.properties);
        }
    }

}

{
	"id": <id>,
	"filepath": <file-path>,
	"filename": <file-name>,
	"downloadStatus": "NEW | DOWNLOADING | FINISHED | INVALID | INTERRUPTED"
}
-----------------------------------------------------------------------------------------
rf mondial
digiton

-----------------------------------------------------------------------------------------
  protected String createJSON(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        SimpleDateFormat outputFormat = new SimpleDateFormat("dd MMM yyyy");
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        mapper.setDateFormat(outputFormat);
        mapper.setSerializationInclusion(Include.NON_EMPTY);
        return mapper.writeValueAsString(object);
    }
	
	
	   protected RequestSpecification login(String user, String password) {
        return given().auth().preemptive().basic(user, password).redirects()
                .follow(false);
    }
-----------------------------------------------------------------------------------------
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;


/**
 * Created by fan.jin on 2016-11-11.
 */
public class TokenBasedAuthentication extends AbstractAuthenticationToken {

    private String token;
    private final UserDetails principle;

    public TokenBasedAuthentication( UserDetails principle ) {
        super( principle.getAuthorities() );
        this.principle = principle;
    }

    public String getToken() {
        return token;
    }

    public void setToken( String token ) {
        this.token = token;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public UserDetails getPrincipal() {
        return principle;
    }

}
 
 
 
 
 
 
import com.bfwg.common.TimeProvider;
import com.bfwg.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;


/**
 * Created by fan.jin on 2016-10-19.
 */

@Component
public class TokenHelper {

    @Value("${app.name}")
    private String APP_NAME;

    @Value("${jwt.secret}")
    public String SECRET;

    @Value("${jwt.expires_in}")
    private int EXPIRES_IN;

    @Value("${jwt.mobile_expires_in}")
    private int MOBILE_EXPIRES_IN;

    @Value("${jwt.header}")
    private String AUTH_HEADER;

    static final String AUDIENCE_UNKNOWN = "unknown";
    static final String AUDIENCE_WEB = "web";
    static final String AUDIENCE_MOBILE = "mobile";
    static final String AUDIENCE_TABLET = "tablet";

    @Autowired
    TimeProvider timeProvider;

    private SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    public Date getIssuedAtDateFromToken(String token) {
        Date issueAt;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            issueAt = claims.getIssuedAt();
        } catch (Exception e) {
            issueAt = null;
        }
        return issueAt;
    }

    public String getAudienceFromToken(String token) {
        String audience;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            audience = claims.getAudience();
        } catch (Exception e) {
            audience = null;
        }
        return audience;
    }

    public String refreshToken(String token, Device device) {
        String refreshedToken;
        Date a = timeProvider.now();
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            claims.setIssuedAt(a);
            refreshedToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate(device))
                .signWith( SIGNATURE_ALGORITHM, SECRET )
                .compact();
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    public String generateToken(String username, Device device) {
        String audience = generateAudience(device);
        return Jwts.builder()
                .setIssuer( APP_NAME )
                .setSubject(username)
                .setAudience(audience)
                .setIssuedAt(timeProvider.now())
                .setExpiration(generateExpirationDate(device))
                .signWith( SIGNATURE_ALGORITHM, SECRET )
                .compact();
    }

    private String generateAudience(Device device) {
        String audience = AUDIENCE_UNKNOWN;
        if (device.isNormal()) {
            audience = AUDIENCE_WEB;
        } else if (device.isTablet()) {
            audience = AUDIENCE_TABLET;
        } else if (device.isMobile()) {
            audience = AUDIENCE_MOBILE;
        }
        return audience;
    }

    private Claims getAllClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    private Date generateExpirationDate(Device device) {
        long expiresIn = device.isTablet() || device.isMobile() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
        return new Date(timeProvider.now().getTime() + expiresIn * 1000);
    }

    public int getExpiredIn(Device device) {
        return device.isMobile() || device.isTablet() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        User user = (User) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getIssuedAtDateFromToken(token);
        return (
                username != null &&
                username.equals(userDetails.getUsername()) &&
                        !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate())
        );
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public String getToken( HttpServletRequest request ) {
        /**
         *  Getting the token from Authentication header
         *  e.g Bearer your_token
         */
        String authHeader = getAuthHeaderFromHeader( request );
        if ( authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }

    public String getAuthHeaderFromHeader( HttpServletRequest request ) {
        return request.getHeader(AUTH_HEADER);
    }

}
 
 
 
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DeviceUtils;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by fanjin on 2017-10-16.
 */
@Component
public class DeviceProvider {

    public Device getCurrentDevice(HttpServletRequest request) {
        return DeviceUtils.getCurrentDevice(request);
    }
}
 
 
 
 
 
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

/**
 * Created by fan.jin on 2016-11-03.
 */

@Entity
@Table(name="AUTHORITY")
public class Authority implements GrantedAuthority {

    @Id
    @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(name="name")
    String name;

    @Override
    public String getAuthority() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @JsonIgnore
    public String getName() {
        return name;
    }

    @JsonIgnore
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

}
 
 
 
import com.bfwg.common.TimeProvider;
import com.bfwg.model.User;
import org.assertj.core.util.DateUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Timestamp;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by fan.jin on 2017-01-08.
 */
public class TokenHelperTest {

    private static final String TEST_USERNAME = "testUser";

    @InjectMocks
    private TokenHelper tokenHelper;

    @Mock
    private TimeProvider timeProviderMock;

    @InjectMocks
    DeviceDummy device;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);

        ReflectionTestUtils.setField(tokenHelper, "EXPIRES_IN", 10); // 10 sec
        ReflectionTestUtils.setField(tokenHelper, "MOBILE_EXPIRES_IN", 20); // 20 sec
        ReflectionTestUtils.setField(tokenHelper, "SECRET", "mySecret");
    }

    @Test
    public void testGenerateTokenGeneratesDifferentTokensForDifferentCreationDates() throws Exception {
        when(timeProviderMock.now())
                .thenReturn(DateUtil.yesterday())
                .thenReturn(DateUtil.now());

        final String token = createToken(device);
        final String laterToken = createToken(device);

        assertThat(token).isNotEqualTo(laterToken);
    }

    @Test
    public void mobileTokenShouldLiveLonger() {
        Date beforeSomeTime = new Date(DateUtil.now().getTime() - 15 * 1000);

        UserDetails userDetails = mock(User.class);
        when(userDetails.getUsername()).thenReturn(TEST_USERNAME);

        when(timeProviderMock.now())
                .thenReturn(beforeSomeTime);
        device.setMobile(true);
        final String mobileToken = createToken(device);
        assertThat(tokenHelper.validateToken(mobileToken, userDetails)).isTrue();
    }

    @Test
    public void mobileTokenShouldExpire() {
        Date beforeSomeTime = new Date(DateUtil.now().getTime() - 20 * 1000);

        when(timeProviderMock.now())
                .thenReturn(beforeSomeTime);

        UserDetails userDetails = mock(User.class);
        when(userDetails.getUsername()).thenReturn(TEST_USERNAME);

        device.setMobile(true);
        final String mobileToken = createToken(device);
        assertThat(tokenHelper.validateToken(mobileToken, userDetails)).isFalse();
    }

    @Test
    public void getUsernameFromToken() throws Exception {
        when(timeProviderMock.now()).thenReturn(DateUtil.now());

        final String token = createToken(device);

        assertThat(tokenHelper.getUsernameFromToken(token)).isEqualTo(TEST_USERNAME);
    }

    @Test
    public void getCreatedDateFromToken() {
        final Date now = DateUtil.now();
        when(timeProviderMock.now()).thenReturn(now);

        final String token = createToken(device);

        assertThat(tokenHelper.getIssuedAtDateFromToken(token)).isInSameMinuteWindowAs(now);
    }

    @Test
    public void expiredTokenCannotBeRefreshed() {
        when(timeProviderMock.now())
                .thenReturn(DateUtil.yesterday());

        String token = createToken(device);
        tokenHelper.refreshToken(token, device);
    }

    @Test
    public void getAudienceFromToken() throws Exception {
        when(timeProviderMock.now()).thenReturn(DateUtil.now());
        device.setNormal(true);
        final String token = createToken(this.device);

        assertThat(tokenHelper.getAudienceFromToken(token)).isEqualTo(tokenHelper.AUDIENCE_WEB);
    }

    @Test
    public void getAudienceFromMobileToken() throws Exception {
        when(timeProviderMock.now()).thenReturn(DateUtil.now());
        device.setMobile(true);
        final String token = createToken(this.device);
        assertThat(tokenHelper.getAudienceFromToken(token)).isEqualTo(tokenHelper.AUDIENCE_MOBILE);
    }

    @Test
    public void changedPasswordCannotBeRefreshed() throws Exception {
        when(timeProviderMock.now())
                .thenReturn(DateUtil.now());

        User user = mock(User.class);
        when(user.getLastPasswordResetDate()).thenReturn(new Timestamp(DateUtil.tomorrow().getTime()));
        String token = createToken(device);
        assertThat(tokenHelper.validateToken(token, user)).isFalse();
    }

    @Test
    public void canRefreshToken() throws Exception {
        when(timeProviderMock.now())
                .thenReturn(DateUtil.now())
                .thenReturn(DateUtil.tomorrow());
        String firstToken = createToken(device);
        String refreshedToken = tokenHelper.refreshToken(firstToken, device);
        Date firstTokenDate = tokenHelper.getIssuedAtDateFromToken(firstToken);
        Date refreshedTokenDate = tokenHelper.getIssuedAtDateFromToken(refreshedToken);
        assertThat(firstTokenDate).isBefore(refreshedTokenDate);
    }

    private String createToken(Device device) {
        return tokenHelper.generateToken(TEST_USERNAME, device);
    }

}
 
 
 
 
 
 
 
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DevicePlatform;
import org.springframework.stereotype.Component;

/**
 * Created by fanjin on 2017-10-07.
 */
@Component
public class DeviceDummy implements Device {
    private boolean normal;
    private boolean mobile;
    private boolean tablet;

    @Override
    public boolean isNormal() {
        return normal;
    }

    @Override
    public boolean isMobile() {
        return mobile;
    }

    @Override
    public boolean isTablet() {
        return tablet;
    }

    @Override
    public DevicePlatform getDevicePlatform() {
        return null;
    }

    public void setNormal(boolean normal) {
        this.normal = normal;
    }

    public void setMobile(boolean mobile) {
        this.mobile = mobile;
    }

    public void setTablet(boolean tablet) {
        this.tablet = tablet;
    }
}
 
 
 
 
 
 
 
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-mobile</artifactId>
		</dependency>
 
 
		<dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.6.0</version>
        </dependency>
 


-----------------------------------------------------------------------------------------
https://www.programcreek.com/java-api-examples/index.php?project_name=hypery2k%2Fangular-spring-boot-sample#
-----------------------------------------------------------------------------------------
EcomPilot.io
-----------------------------------------------------------------------------------------
#!/bin/sh

# restart mysql
/etc/init.d/mysql restart

# run spring boot

java -jar /tmp/ng-spring-boot.jar  --server.port=40080 2> boot-error.log 1> boot-info.log




#!/bin/sh
java -version

serverPort=${server.port}
dbUrl="jdbc:mysql://"$DB_PORT_${mysql.port}_TCP_ADDR"/NGSPRING?useUnicode=true&characterEncoding=utf8"


echo "App name: "$1
echo "Server Port: "$serverPort
echo "DB URL: "$dbUrl

echo "starting app"
java -Djava.security.egd=file:/dev/./urandom -jar /$1.jar --flyway.url=${dbUrl} --spring.datasource.url=${dbUrl} --server.port=${serverPort} 2> /boot-error.log 1> /boot-info.log
-----------------------------------------------------------------------------------------
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public ResponseEntity<?> handleErrors(Exception ex) {
        if (ex.getCause() instanceof RollbackException
                && ex.getCause().getCause() instanceof ConstraintViolationException) {
            ConstraintViolationException constraintViolationException = (ConstraintViolationException) ex.getCause().getCause();
            return new ResponseEntity<List<ValidationMessage>>(getValidationErrorResponse(constraintViolationException), HttpStatus.BAD_REQUEST);
        } else {
            LOG.error("Got unknown error", ex);
            // fallback to server error
            return new ResponseEntity<Message>(new Message(ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
-----------------------------------------------------------------------------------------
import ngSpring.demo.domain.entities.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends CrudRepository<User, String> {

    @Query(nativeQuery = true, value = "select u.user_name from user u where u.customer_id = :customerId and exists (select * from user_roles where user_id = u.user_id and role_id = 2)")
    String findControllerUserNameByCustomerId(
            @Param("customerId") String customerId);


    @Query(nativeQuery = true, value = "select u.user_name from user u, user_branches ub where u.user_id = ub.user_id and ub.branch_id = :branchId")
    String findPlanerUserNameByBranchId(@Param("branchId") String branchId);

    User findByUsernameAndDeletedFalse(String username);

    User findByUserIdAndDeletedFalse(String userId);
}
-----------------------------------------------------------------------------------------
# general
spring.application.name=angular-spring-demo
server.port=9080

# http encoding
spring.http.encoding.charset=UTF-8
spring.http.encoding.enabled=true
spring.http.encoding.force=true

# database: mysql
spring.datasource.driverClassName=com.mysql.jdbc.Driver
spring.datasource.url=jdbc:mysql://localhost/NGSPRING
spring.datasource.username=ngspring
spring.datasource.password=password
spring.jpa.hibernate.ddl-auto=update
hibernate.dialect=mysql

#flyway properties
flyway.url=jdbc:mysql://localhost/NGSPRING
flyway.user=ngspring
flyway.password=password
flyway.enabled=true

# Show or not log for each sql query
spring.jpa.show-sql = false

org.springframework.security.level=DEBUG

# monitoring
management.context-path=/actuator
endpoints.enabled=true

# pretty-print output
spring.jackson.serialization.INDENT_OUTPUT=true
spring.jackson.serialization.write-dates-as-timestamps:false
-----------------------------------------------------------------------------------------
import com.jerry.security.core.config.JerrySecurityProperties;
import com.jerry.security.core.exception.JerrySecurityCodeException;
import com.jerry.security.core.service.JerryUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author jerry
 */
@Component
public class JerrySecurityFilter extends OncePerRequestFilter {
    @Autowired
    JerrySecurityProperties jerrySecurityProperties;
    @Autowired
    RedisTemplate redisTemplate;

    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     *
     * @param request
     * @param response
     * @param filterChain
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String permit = jerrySecurityProperties.getConfig().getPermit();      
        String[] permits = permit.split(",");
		//Start 通配符匹配实现
        AntPathMatcher matcher = new AntPathMatcher();
        Boolean allowed = false;
        for (String path : permits) {
            if (matcher.match(path, request.getRequestURI())) {
                allowed = true;
            }
        }
		//End 通配符匹配实现
        if (!allowed) {
            try {
                securityVali(clientId, sessionId);
            } catch (Exception e) {
                response.sendRedirect(jerrSecurityProperties.getConfig().getLoginUrl());
            }
        }
        filterChain.doFilter(request, response);
    }

    private void securityVali(String clientId, String sessionId) {
        //非public请求，需要验证当前account信息是否存在
        ValueOperations vo = redisTemplate.opsForValue();
        Object userId = vo.get(clientId + sessionId);
        if (null == userId) {
            throw new JerrySecurityCodeException("userId不存在");
        }
        Object user = vo.get(userId);
        if (null == user) {
            throw new JerrySecurityCodeException("user不存在");
        }
        Map<String, JerryUserInfo> clientIdUser = (Map<String, JerryUserInfo>) user;
        Boolean cached = clientIdUser.containsKey(clientId);
        if (!cached) {
            throw new JerrySecurityCodeException("clientId对应user不存在");
        }
    }
}

jerry:
  security:
    config:
      permit: /jerry/user,/actuator/**
-----------------------------------------------------------------------------------------
  @Bean
    public FilterRegistrationBean tokenAuthenticationFilterBean() {
        FilterRegistrationBean registration = new FilterRegistrationBean(tokenAuthenticationFilter);
        registration.addUrlPatterns("/api/**","/ping","/api/*");
        return registration;
    }
-----------------------------------------------------------------------------------------
Yaml yaml = new Yaml();
InputStream inputStream = this.getClass()
 .getClassLoader()
 .getResourceAsStream("yaml/customer_with_type.yaml");
Customer customer = yaml.load(inputStream);


Yaml yaml = new Yaml(new Constructor(Customer.class));

@Test
public void
  whenLoadYAMLDocumentWithTopLevelClass_thenLoadCorrectJavaObjectWithNestedObjects() {
  
    Yaml yaml = new Yaml(new Constructor(Customer.class));
    InputStream inputStream = this.getClass()
      .getClassLoader()
      .getResourceAsStream("yaml/customer_with_contact_details_and_address.yaml");
    Customer customer = yaml.load(inputStream);
  
    assertNotNull(customer);
    assertEquals("John", customer.getFirstName());
    assertEquals("Doe", customer.getLastName());
    assertEquals(31, customer.getAge());
    assertNotNull(customer.getContactDetails());
    assertEquals(2, customer.getContactDetails().size());
     
    assertEquals("mobile", customer.getContactDetails()
      .get(0)
      .getType());
    assertEquals(123456789, customer.getContactDetails()
      .get(0)
      .getNumber());
    assertEquals("landline", customer.getContactDetails()
      .get(1)
      .getType());
    assertEquals(456786868, customer.getContactDetails()
      .get(1)
      .getNumber());
    assertNotNull(customer.getHomeAddress());
    assertEquals("Xyz, DEF Street", customer.getHomeAddress()
      .getLine());
}

<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.21</version>            
</dependency>
-----------------------------------------------------------------------------------------
@RestController
public class UserController {

	@GetMapping("/user")
	@JsonView(User.WithoutPasswordView.class)
	public User getUser() {
		return new User("eric", "7!jd#h23");
	}
}

@Controller
public class UserController extends AbstractController {

	@GetMapping("/user")
	public String getUser(Model model) {
		model.addAttribute("user", new User("eric", "7!jd#h23"));
		model.addAttribute(JsonView.class.getName(), User.WithoutPasswordView.class);
		return "userView";
	}
}
-----------------------------------------------------------------------------------------
@RequestMapping("/quotes")
@ResponseBody
public DeferredResult<String> quotes() {
	DeferredResult<String> deferredResult = new DeferredResult<String>();
	// Save the deferredResult somewhere..
	return deferredResult;
}

// In some other thread...
deferredResult.setResult(data);

@PostMapping
public Callable<String> processUpload(final MultipartFile file) {

	return new Callable<String>() {
		public String call() throws Exception {
			// ...
			return "someView";
		}
	};

}
-----------------------------------------------------------------------------------------
POST /someUrl
Content-Type: multipart/mixed

--edt7Tfrdusa7r3lNQc79vXuhIIMlatb7PQg7Vp
Content-Disposition: form-data; name="meta-data"
Content-Type: application/json; charset=UTF-8
Content-Transfer-Encoding: 8bit

{
	"name": "value"
}
--edt7Tfrdusa7r3lNQc79vXuhIIMlatb7PQg7Vp
Content-Disposition: form-data; name="file-data"; filename="file.properties"
Content-Type: text/xml
Content-Transfer-Encoding: 8bit
... File Data ...
-----------------------------------------------------------------------------------------
@Configuration
@EnableWebMvc
public class WebConfiguration implements WebMvcConfigurer {

	@Override
	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder()
				.indentOutput(true)
				.dateFormat(new SimpleDateFormat("yyyy-MM-dd"))
				.modulesToInstall(new ParameterNamesModule());
		converters.add(new MappingJackson2HttpMessageConverter(builder.build()));
		converters.add(new MappingJackson2XmlHttpMessageConverter(builder.xml().build()));
	}

}
-----------------------------------------------------------------------------------------
Paragon.UserContour.Autotests
-----------------------------------------------------------------------------------------
@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

	@Override
	public void configureViewResolvers(ViewResolverRegistry registry) {
		registry.enableContentNegotiation(new MappingJackson2JsonView());
		registry.freeMarker().cache(false);
	}

	@Bean
	public FreeMarkerConfigurer freeMarkerConfigurer() {
		FreeMarkerConfigurer configurer = new FreeMarkerConfigurer();
		configurer.setTemplateLoaderPath("/WEB-INF/");
		return configurer;
	}

}
-----------------------------------------------------------------------------------------
@Configuration
public class CustomWebConfiguration extends WebMvcConfigurationSupport {
     
    @Bean
    public RequestMappingHandlerMapping 
      requestMappingHandlerMapping() {
  
        RequestMappingHandlerMapping handlerMapping
          = super.requestMappingHandlerMapping();
        handlerMapping.setUseSuffixPatternMatch(false);
        return handlerMapping;
    }
}
-----------------------------------------------------------------------------------------
@RequestMapping(value = "/hello/{value}$", method = RequestMethod.GET)
public String hello(@PathVariable("value") String value, ModelMap model)
-----------------------------------------------------------------------------------------
@Bean
public RequestMappingHandlerMapping requestMappingHandlerMapping() {
    RequestMappingHandlerMapping handlerMapping = super.requestMappingHandlerMapping();
    handlerMapping.setAlwaysUseFullPath(true);
    return handlerMapping;
}
-----------------------------------------------------------------------------------------
@Component
public class IncludeExtensionsInRequestParamPostProcessor implements BeanPostProcessor {
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof RequestMappingHandlerMapping) {
            RequestMappingHandlerMapping mapping = (RequestMappingHandlerMapping)bean;
            mapping.setUseRegisteredSuffixPatternMatch(false);
            mapping.setUseSuffixPatternMatch(false);
        }
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) { return bean; }
}
-----------------------------------------------------------------------------------------
//    @Bean
//    public CommandLineRunner run(final RestTemplate restTemplate) throws Exception {
//        return args -> {
//            final QuoteEntity quoteEntity = restTemplate.getForObject("http://gturnquist-quoters.cfapps.io/api/random", QuoteEntity.class);
//            log.info(quoteEntity.toString());
//        };
//    }
-----------------------------------------------------------------------------------------
   @Bean
    public View jsonTemplate() {
        MappingJackson2JsonView view = new MappingJackson2JsonView();
        view.setPrettyPrint(true);
        return view;
    }
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------
//    //    @Test
////    public void testForbiddenAccess() {
////        given().when().get(getServiceURI() + "/api/users").then().statusCode(401);
////    }
////
////    @Test
////    public void testAuthorizationAccess() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/users").then().statusCode(200);
////    }
////
////    @Test
////    public void testNotFound() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/userss").then().statusCode(404);
////    }
////    @Test
////    public void testVerifyUser2() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/2").then()
////                .body("login", equalTo("user2@gmail.com"))
////                .body("name", equalTo("user2"))
////                .body("createdBy", equalTo("user2@gmail.com"))
////                .body("age", equalTo(26))
////                .body("phone", equalTo("+79211234567"))
////                //.body("gender", equalTo(User.UserGenderType.MALE.toString()))
////                .body("id", equalTo(2))
////                .body("createdAt", equalTo("2017-04-30 00:00:00+0300"))
////                .body("modifiedAt", nullValue())
////                .body("rating", equalTo(1.0f))
////                .body("registeredAt", equalTo("2017-04-30 00:00:00+0300"))
////                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .body(getObjectAsString(user))
////                .when().post(getServiceURI() + "/api/user").then()
////                .statusCode(201);
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/users").then()
////                .body("login", hasItem("user18@gmail.com"))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .body(user1)
////                .when().put(getServiceURI() + "/api/user/{id}", user1.getId()).then()
////                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/4").then()
////                .body("login", equalTo("user18@gmail.com"))
////                .statusCode(200);
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .when().delete(getServiceURI() + "/api/user/4").then()
////                .statusCode(403);
//////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("dba", "dba123")
//////                .when().delete(getServiceURI() + "/api/user/4").then()
//////                .statusCode(200);
//
//    @Override
//    public GetCouponResponse getCoupon(final GetCouponRequest couponRequest) {
//        return given()
//                .log().all()
//                .contentType(ContentType.JSON)
//                .accept(ContentType.JSON)
//                .auth().basic("user", "user123")
//                .when()
//                .get(this.buildFullPath(couponRequest))
//                .then()
//                .log().all()
//                .body("name", equalTo("subscription3"))
//                .statusCode(200)
//                .extract()
//                .as(GetCouponResponse.class);
//    }
//
//    private URI buildFullPath(final GetCouponRequest request) {
//        final EndpointProperty.RouteInfo routeInfo = this.endpointProperty.getRoutes().get("coupons-api");
//        return UriComponentsBuilder
//                .fromUriString(routeInfo.getBasePath())
//                .path(routeInfo.getSegmentPath())
//                .path("/")
//                .path(request.getSerialNumber())
//                .build()
//                .toUri();
//    }
//
//    private RequestSpecification buildRequestSpecification() {
//        return new RequestSpecBuilder()
//                .setBaseUri("http://localhost")
//                .setPort(8080)
//                .setAccept(ContentType.JSON)
//                .setContentType(ContentType.ANY)
//                .log(LogDetail.ALL)
//                .build();
//    }
////
////    private Optional<GetCouponResponse> getEmptyIfNotFoundOrRethrow(final HttpStatusCodeException e) {
////        final HttpStatus statusCode = e.getStatusCode();
////        if (!statusCode.equals(HttpStatus.NOT_FOUND)) {
////            rethrowSpecificException(e);
////        }
////        return Optional.empty();
////    }
////
////    private void rethrowSpecificException(final Exception e) {
////        rethrowRestServiceSpecificException(e, "Authority service is not available!", "Error is occurred when calling Authority service");
////    }
//}
//
//
////    RequestSpecification requestSpec = new RequestSpecBuilder()
////            .setBaseUri("http://localhost")
////            .setPort(8080)
////            .setAccept(ContentType.JSON)
////            .setContentType(ContentType.ANY)
////...
////        .log(LogDetail.ALL)
////        .build();
////
////// можно задать одну спецификацию для всех запросов:
////        RestAssured.requestSpecification = requestSpec;
////
////// или для отдельного:
////        given().spec(requestSpec)...when().get(someEndpoint);
////
////        ResponseSpecification responseSpec = new ResponseSpecBuilder()
////        .expectStatusCode(200)
////        .expectBody(containsString("success"))
////        .build();
////
////// можно задать одну спецификацию для всех ответов:
////        RestAssured.responseSpecification = responseSpec;
////
////// или для отдельного:
////        given()...when().get(someEndpoint).then().spec(responseSpec)...;
//
////// то же самое работает и в обратную сторону:
////SomePojo pojo = given().
////    .when().get(EndPoints.get)
////            .then().extract().body().as(SomePojo.class);
//
////    @Test
////    public void whenLogOnlyIfValidationFailed_thenSuccess() {
////        when().get("/users/eugenp")
////                .then().log().ifValidationFails().statusCode(200);
////
////        given().log().ifValidationFails()
////                .when().get("/users/eugenp")
////                .then().statusCode(200);
////    }
////
////    @Test
////    public void whenLogResponseIfErrorOccurred_thenSuccess() {
////
////        when().get("/users/eugenp")
////                .then().log().ifError();
////        when().get("/users/eugenp")
////                .then().log().ifStatusCodeIsEqualTo(500);
////        when().get("/users/eugenp")
////                .then().log().ifStatusCodeMatches(greaterThan(200));
////    }
//
////    @Test
////    public void whenUpdatePerson_thenStatus200() {
////        long id = createTestPerson("Nick").getId();
////        Person person = new Person("Michail");
////        given().pathParam("id", id).log()
////                .body().contentType("application/json").body(person)
////
////                .when().put("/persons/{id}")
////
////                .then().log().body().statusCode(HttpStatus.OK.value())
////                .and().body("name", equalTo("Michail"));
////    }
////
////    @Test
////    public void givenNoPerson_whenGetPerson_thenStatus500() {
////        given().pathParam("id", 1)
////                .when().get("/persons/{id}")
////
////                .then().log().body()
////                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
////    }

public interface ITaskSubscriptionRepository<E extends TaskSubscriptionEntity, D extends TaskSubscriptionDTO> extends ICoreBaseRepository<E, D>, PagingAndSortingRepository<E, Long> {
    @Query(value="select v.* from Option o, Vote v where o.POLL_ID = ?1 and v.OPTION_ID = o.OPTION_ID", nativeQuery = true)
    public Iterable<E> findByPoll(final Long id);

    @Query(value="select v.* from Option o, Vote v where o.POLL_ID = ?1 and v.OPTION_ID = o.OPTION_ID", nativeQuery = true)
    public Iterable<E> findByPoll(Long pollId);
}
-----------------------------------------------------------------------------------------
//package com.paragon.microservices.autotests.common.client.coupons.service;
//
//import com.jayway.restassured.builder.RequestSpecBuilder;
//import com.jayway.restassured.filter.log.LogDetail;
//import com.jayway.restassured.http.ContentType;
//import com.jayway.restassured.specification.RequestSpecification;
//import com.paragon.microservices.autotests.common.client.coupons.model.GetCouponRequest;
//import com.paragon.microservices.autotests.common.client.coupons.model.GetCouponResponse;
//import com.paragon.microservices.autotests.system.property.EndpointProperty;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Service;
//import org.springframework.validation.annotation.Validated;
//import org.springframework.web.util.UriComponentsBuilder;
//
//import javax.transaction.Transactional;
//import java.net.URI;
//
//import static com.jayway.restassured.RestAssured.given;
//import static org.hamcrest.CoreMatchers.equalTo;
//
//@Slf4j
//@Service
//@Validated
//@Transactional(rollbackOn = Exception.class)
//@RequiredArgsConstructor
//public class CouponClientImpl implements CouponClient {
//    private final EndpointProperty endpointProperty;
//
//    //    @Test
////    public void testForbiddenAccess() {
////        given().when().get(getServiceURI() + "/api/users").then().statusCode(401);
////    }
////
////    @Test
////    public void testAuthorizationAccess() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/users").then().statusCode(200);
////    }
////
////    @Test
////    public void testNotFound() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/userss").then().statusCode(404);
////    }
////    @Test
////    public void testVerifyUser2() {
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/2").then()
////                .body("login", equalTo("user2@gmail.com"))
////                .body("name", equalTo("user2"))
////                .body("createdBy", equalTo("user2@gmail.com"))
////                .body("age", equalTo(26))
////                .body("phone", equalTo("+79211234567"))
////                //.body("gender", equalTo(User.UserGenderType.MALE.toString()))
////                .body("id", equalTo(2))
////                .body("createdAt", equalTo("2017-04-30 00:00:00+0300"))
////                .body("modifiedAt", nullValue())
////                .body("rating", equalTo(1.0f))
////                .body("registeredAt", equalTo("2017-04-30 00:00:00+0300"))
////                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .body(getObjectAsString(user))
////                .when().post(getServiceURI() + "/api/user").then()
////                .statusCode(201);
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/users").then()
////                .body("login", hasItem("user18@gmail.com"))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .body(user1)
////                .when().put(getServiceURI() + "/api/user/{id}", user1.getId()).then()
////                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
////                .statusCode(200);
//
//    //        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/4").then()
////                .body("login", equalTo("user18@gmail.com"))
////                .statusCode(200);
////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
////                .when().delete(getServiceURI() + "/api/user/4").then()
////                .statusCode(403);
//////        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("dba", "dba123")
//////                .when().delete(getServiceURI() + "/api/user/4").then()
//////                .statusCode(200);
//
//    @Override
//    public GetCouponResponse getCoupon(final GetCouponRequest couponRequest) {
//        return given()
//                .log().all()
//                .contentType(ContentType.JSON)
//                .accept(ContentType.JSON)
//                .auth().basic("user", "user123")
//                .when()
//                .get(this.buildFullPath(couponRequest))
//                .then()
//                .log().all()
//                .body("name", equalTo("subscription3"))
//                .statusCode(200)
//                .extract()
//                .as(GetCouponResponse.class);
//    }
//
//    private URI buildFullPath(final GetCouponRequest request) {
//        final EndpointProperty.RouteInfo routeInfo = this.endpointProperty.getRoutes().get("coupons-api");
//        return UriComponentsBuilder
//                .fromUriString(routeInfo.getBasePath())
//                .path(routeInfo.getSegmentPath())
//                .path("/")
//                .path(request.getSerialNumber())
//                .build()
//                .toUri();
//    }
//
//    private RequestSpecification buildRequestSpecification() {
//        return new RequestSpecBuilder()
//                .setBaseUri("http://localhost")
//                .setPort(8080)
//                .setAccept(ContentType.JSON)
//                .setContentType(ContentType.ANY)
//                .log(LogDetail.ALL)
//                .build();
//    }
////
////    private Optional<GetCouponResponse> getEmptyIfNotFoundOrRethrow(final HttpStatusCodeException e) {
////        final HttpStatus statusCode = e.getStatusCode();
////        if (!statusCode.equals(HttpStatus.NOT_FOUND)) {
////            rethrowSpecificException(e);
////        }
////        return Optional.empty();
////    }
////
////    private void rethrowSpecificException(final Exception e) {
////        rethrowRestServiceSpecificException(e, "Authority service is not available!", "Error is occurred when calling Authority service");
////    }
//}
//
//
////    RequestSpecification requestSpec = new RequestSpecBuilder()
////            .setBaseUri("http://localhost")
////            .setPort(8080)
////            .setAccept(ContentType.JSON)
////            .setContentType(ContentType.ANY)
////...
////        .log(LogDetail.ALL)
////        .build();
////
////// можно задать одну спецификацию для всех запросов:
////        RestAssured.requestSpecification = requestSpec;
////
////// или для отдельного:
////        given().spec(requestSpec)...when().get(someEndpoint);
////
////        ResponseSpecification responseSpec = new ResponseSpecBuilder()
////        .expectStatusCode(200)
////        .expectBody(containsString("success"))
////        .build();
////
////// можно задать одну спецификацию для всех ответов:
////        RestAssured.responseSpecification = responseSpec;
////
////// или для отдельного:
////        given()...when().get(someEndpoint).then().spec(responseSpec)...;
//
////// то же самое работает и в обратную сторону:
////SomePojo pojo = given().
////    .when().get(EndPoints.get)
////            .then().extract().body().as(SomePojo.class);
//
////    @Test
////    public void whenLogOnlyIfValidationFailed_thenSuccess() {
////        when().get("/users/eugenp")
////                .then().log().ifValidationFails().statusCode(200);
////
////        given().log().ifValidationFails()
////                .when().get("/users/eugenp")
////                .then().statusCode(200);
////    }
////
////    @Test
////    public void whenLogResponseIfErrorOccurred_thenSuccess() {
////
////        when().get("/users/eugenp")
////                .then().log().ifError();
////        when().get("/users/eugenp")
////                .then().log().ifStatusCodeIsEqualTo(500);
////        when().get("/users/eugenp")
////                .then().log().ifStatusCodeMatches(greaterThan(200));
////    }
//
////    @Test
////    public void whenUpdatePerson_thenStatus200() {
////        long id = createTestPerson("Nick").getId();
////        Person person = new Person("Michail");
////        given().pathParam("id", id).log()
////                .body().contentType("application/json").body(person)
////
////                .when().put("/persons/{id}")
////
////                .then().log().body().statusCode(HttpStatus.OK.value())
////                .and().body("name", equalTo("Michail"));
////    }
////
////    @Test
////    public void givenNoPerson_whenGetPerson_thenStatus500() {
////        given().pathParam("id", 1)
////                .when().get("/persons/{id}")
////
////                .then().log().body()
////                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
////    }
-----------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------
    @Test
    public void testAddUserSubscription() {
        final UserDTO user1 = given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/1").as(UserDTO.class);
        final SubscriptionDTO subscription3 = given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscription/3").as(SubscriptionDTO.class);

        assertTrue(Objects.equals("user1@gmail.com", user1.getLogin()));
        //assertTrue(Objects.equals(User.UserStatusType.UNVERIFIED, user1.getStatus()));
        assertTrue(Objects.equals("subscription3", subscription3.getTitle()));
        assertTrue(Objects.equals(SubscriptionStatusInfo.StatusType.STANDARD, subscription3.getStatus()));

        final UserSubOrderDTO userSubOrder = new UserSubOrderDTO();
        userSubOrder.setUser(user1);
        userSubOrder.setSubscription(subscription3);
        userSubOrder.setCreatedBy(user1.getLogin());
        userSubOrder.setStartedAt(DateUtils.strToDate("2017-05-28 00:00:00+0300"));
        //userSubOrder.setStartedAt("2017-05-28 00:00:00");

        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
                .body(userSubOrder)
                .when().post(getServiceURI() + "/api/user/{id}/subscription", user1.getId()).then()
                .statusCode(201);
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/{id}/subscriptions", user1.getId()).then()
                .body("name", hasItem("subscription3"))
                .statusCode(200);
    }
	
	    @Test
    public void testForbiddenAccess() {
        given().when().get(getServiceURI() + "/api/users").then().statusCode(401);
    }

    @Test
    public void testAuthorizationAccess() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/users").then().statusCode(200);
    }

    @Test
    public void testNotFound() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/userss").then().statusCode(404);
    }

    @Test
    public void testVerifyUser2() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/2").then()
                .body("login", equalTo("user2@gmail.com"))
                .body("name", equalTo("user2"))
                .body("createdBy", equalTo("user2@gmail.com"))
                .body("age", equalTo(26))
                .body("phone", equalTo("+79211234567"))
                //.body("gender", equalTo(User.UserGenderType.MALE.toString()))
                .body("id", equalTo(2))
                .body("createdAt", equalTo("2017-04-30 00:00:00+0300"))
                .body("modifiedAt", nullValue())
                .body("rating", equalTo(1.0f))
                .body("registeredAt", equalTo("2017-04-30 00:00:00+0300"))
                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
                .statusCode(200);
    }
	
	
	    @Test
    public void testUpdateUser() {
        final UserDTO user1 = given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/user/1").as(UserDTO.class);

        assertTrue(Objects.nonNull(user1));
        assertTrue(Objects.equals("user1@gmail.com", user1.getLogin()));
        assertTrue(Objects.equals(UserAccountStatusInfo.StatusType.UNVERIFIED, user1.getStatus()));

        UserActivityStatusInfoDTO status = new UserActivityStatusInfoDTO();
        status.setStatusType(UserActivityStatusInfo.StatusType.CHALLENGING);
        user1.setStatus(status);

        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
                .body(user1)
                .when().put(getServiceURI() + "/api/user/{id}", user1.getId()).then()
                .body("status", equalTo(UserAccountStatusInfo.StatusType.ACTIVE.toString()))
                .statusCode(200);
    }
	
  @Test
    public void testForbiddenAccess() {
        given().when().get(getServiceURI() + "/api/subscriptions").then().statusCode(401);
    }

    @Test
    public void testAuthorizationAccess() {
        //.auth().digest( ADMIN_USERNAME, ADMIN_PASSWORD )
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscriptions").then().statusCode(200);
    }

    @Test
    public void testNotFound() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscriptionss").then().statusCode(404);
    }

    @Test
    public void testVerifySubscription1() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscription/1").then()
                .body("name", equalTo("subscription1"))
                .body("createdBy", equalTo("admin"))
                .body("expiredAt", equalTo(1544562000000L))
                .body("expiredAt", equalTo("2018-12-12 00:00:00+0300"))
                .body("id", equalTo(1))
                .body("createdAt", equalTo("2018-12-12 00:00:00+0300"))
                .body("modifiedAt", nullValue())
                .body("type", equalTo(SubscriptionStatusInfo.StatusType.PREMIUM.toString()))
                .statusCode(200);
    }

    @Test
    public void testAddSubscription() {
        final SubscriptionDTO subscription = new SubscriptionDTO();
        subscription.setExpiredAt(DateUtils.strToDate("2018-08-28 00:00:00+0300"));
        //subscription.setExpireAt("2018-08-28 00:00:00");
        subscription.setCreatedBy("admin");
        subscription.setTitle("Guest Group");
        //subscription.setPrefix('standard');
        subscription.setStatusType(SubscriptionStatusInfo.StatusType.STANDARD);

        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
                .body(getObjectAsString(subscription))
                .when().post(getServiceURI() + "/api/subscription").then()
                .statusCode(201);
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscriptions").then()
                .body("name", hasItem("Guest Group"))
                .statusCode(200);
    }

    @Test
    public void testUpdateSubscription() {
        final SubscriptionDTO subscription1 = given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscription/1").as(SubscriptionDTO.class);

        assertTrue(Objects.nonNull(subscription1));
        assertTrue(Objects.equals("subscription1", subscription1.getTitle()));
        assertTrue(Objects.equals(SubscriptionStatusInfo.StatusType.PREMIUM, subscription1.getStatus()));

        subscription1.setExpiredAt(DateUtils.strToDate("2019-04-18 00:00:00+0300"));
        //subscription1.setExpireAt("2019-04-18 00:00:00");

        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
                .body(subscription1)
                .when().put(getServiceURI() + "/api/subscription/{id}", subscription1.getId()).then()
                //                .body("expireAt", equalTo(1555534800000L))
                .body("expireAt", equalTo("2019-04-18 00:00:00"))
                .statusCode(200);
    }

    @Test
    public void testDeleteSubscription() {
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123").when().get(getServiceURI() + "/api/subscription/4").then()
                .body("name", equalTo("Guest Group"))
                .statusCode(200);
        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("user", "user123")
                .when().delete(getServiceURI() + "/api/subscription/4").then()
                .statusCode(403);
//        given().contentType(ContentType.JSON).accept(ContentType.JSON).auth().basic("dba", "dba123")
//                .when().delete(getServiceURI() + "/api/subscription/4").then()
//                .statusCode(200);
    }
