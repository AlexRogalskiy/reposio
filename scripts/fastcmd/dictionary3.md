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
@echo off
start Brackets.exe %*

-----------------------------------------------------------------------------------------
@SupportedSourceVersion(SourceVersion.RELEASE_8)
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
