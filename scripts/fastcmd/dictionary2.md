--------------------------------------------------------------------------------------------------------
String pricePayload = JacksonJsonHelper.serialize(request.getCurrent_price());
--------------------------------------------------------------------------------------------------------
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.UnknownHostException;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.net.ssl.SSLException;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.curator.utils.CloseableUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HttpClientManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientManager.class);

    @Value("${httpconfig.maxHttpConnections}")
    private transient Integer maxHttpConnections;

    @Value("${httpconfig.maxHttpConnectionsPerRoute}")
    private transient Integer maxHttpConnectionsPerRoute;

    @Value("${httpconfig.connectionTimeout}")
    private transient Integer connectionTimeout;

    @Value("${httpconfig.connectionRequestTimeout}")
    private transient Integer connectionRequestTimeout;

    @Value("${httpconfig.socketTimeout}")
    private transient Integer socketTimeout;

    @Value("${httpconfig.maxHttpRetries}")
    private transient Integer maxHttpRetries;

    CloseableHttpClient client = null;

    @PostConstruct
    public void init() {

        final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(maxHttpConnections);
        connectionManager.setDefaultMaxPerRoute(maxHttpConnectionsPerRoute);

        final RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(connectionTimeout * 1000)
                .setConnectionRequestTimeout(connectionRequestTimeout * 1000).setSocketTimeout(socketTimeout * 1000)
                .build();

        client = HttpClients.custom().setRetryHandler(retryHandler).setDefaultRequestConfig(requestConfig)
                .setConnectionManager(connectionManager).build();
    }

    public String doHttpGet(final String url, final ResponseHandler<? extends Object> handler,
            final Map<String, String> headers) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpGet httpGet = new HttpGet(url);

        LOGGER.debug("Executing request {}", httpGet.getRequestLine());
        if (headers != null && headers.size() > 0) {
            for (final String key : headers.keySet()) {
                httpGet.addHeader(key, headers.get(key));
            }
        }
        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }

        final String responseBody = (String) client.execute(httpGet, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);
        return responseBody;
    }

    public String doHttpDelete(final String url) throws IOException {

        CloseableHttpResponse httpResponse = null;

        try {
            final HttpClientContext context = HttpClientContext.create();
            final HttpDelete httpDelete = new HttpDelete(url);
            LOGGER.debug("Executing Delete request {}", httpDelete.getRequestLine());

            if (client == null) {
                LOGGER.info("Re-initializing the http-client");
                client = httpClient(true);
            }
            httpResponse = client.execute(httpDelete, context);
            final String content = EntityUtils.toString(httpResponse.getEntity());

            final StatusLine statusLine = httpResponse.getStatusLine();

            LOGGER.debug("Server Response for delete: {}", statusLine, content);

            final String response = String.valueOf(statusLine.getStatusCode());

            return response;
        } finally {
            CloseableUtils.closeQuietly(httpResponse);
        }
    }

    public CloseableHttpResponse doHttpGet(final String uri, final Header[] headers) throws Exception {
        CloseableHttpResponse closeableresponse = null;
        final HttpGet httpget = new HttpGet(uri);
        httpget.setHeaders(headers);
        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        closeableresponse = client.execute(httpget);
        LOGGER.debug("Response Status line :" + closeableresponse.toString());
        LOGGER.debug("HTTP status " + closeableresponse.getStatusLine().getStatusCode());
        if (closeableresponse.getStatusLine().getStatusCode() == 202
                || closeableresponse.getStatusLine().getStatusCode() == 200) {

            return closeableresponse;
        } else {
            throw new Exception("cannot get records using anchor id and query. status code: "
                    + closeableresponse.getStatusLine().getStatusCode());
        }
    }

    public String doHttpPost(final String url, final String payload, final Header[] headers,
            final ResponseHandler<String> handler) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpPost post = new HttpPost(url);
        post.setEntity(new StringEntity(payload));
        post.setHeaders(headers);
        LOGGER.debug("Executing request {} with payload {}", post.getRequestLine(), payload);

        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        final String responseBody = client.execute(post, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);

        return responseBody;
    }

    public String doHttpPut(final String url, final String payload, final Header[] headers,
            final ResponseHandler<String> handler) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpPut post = new HttpPut(url);
        post.setEntity(new StringEntity(payload));
        post.setHeaders(headers);
        LOGGER.debug("Executing request {} with payload {}", post.getRequestLine(), payload);
        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        final String responseBody = client.execute(post, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);

        return responseBody;
    }

    public String doHttpPut(final String url, final String payload, final Map<String, String> headers,
            final ResponseHandler<String> handler) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpPut put = new HttpPut(url);
        put.setEntity(new StringEntity(payload));

        if (headers != null && headers.size() > 0) {
            for (final String key : headers.keySet()) {
                put.addHeader(key, headers.get(key));
            }
        }

        LOGGER.debug("Executing request {} with payload {}", put.getRequestLine(), payload);
        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        final String responseBody = client.execute(put, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);

        return responseBody;
    }

    public String doHttpPost(final String url, final String payload, final Map<String, String> headers,
            final ResponseHandler<String> handler) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpPost post = new HttpPost(url);
        post.setEntity(new StringEntity(payload));

        if (headers != null && headers.size() > 0) {
            for (final String key : headers.keySet()) {
                post.addHeader(key, headers.get(key));
            }
        }

        LOGGER.debug("Executing request {} with payload {}", post.getRequestLine(), payload);

        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        final String responseBody = client.execute(post, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);

        return responseBody;
    }

    public String doHttpPut(final String url, final byte[] payload, final Map<String, String> headers,
            final ResponseHandler<String> handler) throws IOException {

        final HttpClientContext context = HttpClientContext.create();
        final HttpPut put = new HttpPut(url);
        put.setEntity(new ByteArrayEntity(payload));

        if (headers != null && headers.size() > 0) {
            for (final String key : headers.keySet()) {
                put.addHeader(key, headers.get(key));
            }
        }

        LOGGER.debug("Executing request {}", put.getRequestLine());
        if (client == null) {
            LOGGER.info("Re-initializing the http-client");
            client = httpClient(true);
        }
        final String responseBody = client.execute(put, handler, context);
        LOGGER.debug("Server Response: {}", responseBody);

        return responseBody;
    }

    private CloseableHttpClient httpClient(final boolean useRetryHandler) {

        HttpClientBuilder builder = HttpClientBuilder.create();

        final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(maxHttpConnections);
        connectionManager.setDefaultMaxPerRoute(maxHttpConnectionsPerRoute);

        if (useRetryHandler) {
            builder = builder.setRetryHandler(retryHandler);
        }
        final RequestConfig config = RequestConfig.custom().setConnectTimeout(connectionTimeout * 1000)
                .setConnectionRequestTimeout(connectionRequestTimeout * 1000).setSocketTimeout(socketTimeout * 1000)
                .build();
        final CloseableHttpClient httpClient = builder.setDefaultRequestConfig(config)
                .setConnectionManager(connectionManager).build();

        return httpClient;
    }

    private final HttpRequestRetryHandler retryHandler = new HttpRequestRetryHandler() {

        @Override
        public boolean retryRequest(final IOException exception, final int executionCount, final HttpContext context) {
            LOGGER.warn(
                    "Exception occoured while performing REST operation. Retrying the operation {} times for every 5 seconds and execution count is {}/{}  ",
                    maxHttpRetries, executionCount, maxHttpRetries);
            try {
                Thread.sleep(5000);
            } catch (final Exception e) {
                LOGGER.error("Thread interrupted occured while waiting for next iteration ", e);
            }

            // Do not retry if over max retry count
            if (executionCount >= maxHttpRetries) { return false; }

            // Timeout
            if (exception instanceof InterruptedIOException || exception instanceof UnknownHostException
                    || exception instanceof ConnectTimeoutException || exception instanceof HttpHostConnectException
                    || exception instanceof SSLException) {

            return false; }

            final HttpClientContext clientContext = HttpClientContext.adapt(context);
            final HttpRequest request = clientContext.getRequest();
            final boolean idempotent = !(request instanceof HttpEntityEnclosingRequest);
            LOGGER.info("idempotent {}", idempotent);
            // Retry if the request is considered idempotent
            if (idempotent) { return true; }
            return false;
        }

    };

    public void shutdown() {
        LOGGER.info("Shutting down http connection manager.");
        CloseableUtils.closeQuietly(client);
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.redsky.client.exception.ResourceValidationException;
import com.redsky.client.pojo.RequestPayload;

@Component
public class InputRequestValidator implements RequestValidator<RequestPayload> {

    @Autowired
    private BeanValidator validator;

    @Autowired
    private NameValidator nameValidator;

    @Override
    public boolean validate(final RequestPayload bean) throws ResourceValidationException {
        boolean result = false;
        if (bean != null) {
            result = validator.validate(bean);
        }
        if (result) {
            result = nameValidator.isValidName(bean.getProduct().getName());
        }

        return result;
    }
}
--------------------------------------------------------------------------------------------------------
tring jsonCarArray = 
  "[{ \"color\" : \"Black\", \"type\" : \"BMW\" }, { \"color\" : \"Red\", \"type\" : \"FIAT\" }]";
ObjectMapper objectMapper = new ObjectMapper();
objectMapper.configure(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY, true);
Car[] cars = objectMapper.readValue(jsonCarArray, Car[].class);
// print cars
--------------------------------------------------------------------------------------------------------
String jsonCarArray = 
  "[{ \"color\" : \"Black\", \"type\" : \"BMW\" }, { \"color\" : \"Red\", \"type\" : \"FIAT\" }]";
ObjectMapper objectMapper = new ObjectMapper();
List<Car> listCar = objectMapper.readValue(jsonCarArray, new TypeReference<List<Car>>(){});
// print cars
--------------------------------------------------------------------------------------------------------
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

@Component
public class NameValidator {

    private static final String NAME_PATTERN = "^[a-zA-Z0-9\\._\\s\\-]+$";

    public boolean isValidName(final String name) {
        final Pattern pattern = Pattern.compile(NAME_PATTERN);
        final Matcher matcher = pattern.matcher(name);
        return matcher.matches();
    }
}
--------------------------------------------------------------------------------------------------------
-- create a keyspace
create keyspace if not exists target with replication = {'class':'SimpleStrategy','replication_factor':1};

-- use keyspace
use target;

-- create table
create table product(productid bigint primary key, price double);

-- insert products
insert into product(productid, price) values(22222111, 243.87);
insert into product(productid, price) values(1234567, 243.87);
--------------------------------------------------------------------------------------------------------
from flask import Flask, request, Response
import json

""""
Product name webservice to get and post product name
endpoints:
    GET   /products/<id> gives product json with id and name if product exists in dictionary
    POST  /products  adds a product id and its corresponding name to the dictionary
"""
app = Flask(__name__)
products = dict()


@app.route("/products/<id>")
def get_product(id):
    """
    api method to get a product details by its id from products dictionary
    :param id: product id
    :type id: int
    :return: json
    :returns : product id and name if product exists / 404 not found if id is empty /
               id and None if product is not found
    """
    if not products.get(id, None):
        return Response(status=404)
    _product = dict()
    _product["id"] = id
    _product["name"] = products.get(id, None)
    return json.dumps(_product)


@app.route("/products", methods=['POST'])
def add_product():
    """
    api method to add a product and its name to products dictionary
    :return: Response object
    :returns Response 200 on success / Response 400 for missing or invalid data
    """
    if not request.data:
        return Response(status=400)
    id = None
    name = ""
    data = json.loads(request.data)
    for key, val in data.items():
        if key == "id":
            id = val
        if key == "name":
            name = val
    if not name or not id:
        return Response(status=400)
    products[id] = name
    print("adding product {0} {1}".format(id, name))
    return Response(status=201)


if __name__ == "__main__":
    app.run(port=8100)
	
Flask==0.12.2
Jinja2==2.10
MarkupSafe==1.0
Werkzeug==0.12.2
click==6.7
itsdangerous==0.24
wsgiref==0.1.2

cassandra.contactpoints=localhost
cassandra.port=9042
cassandra.keyspace=target
--------------------------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.data.cassandra.config.CassandraClusterFactoryBean;
import org.springframework.data.cassandra.config.java.AbstractCassandraConfiguration;
import org.springframework.data.cassandra.mapping.BasicCassandraMappingContext;
import org.springframework.data.cassandra.mapping.CassandraMappingContext;
import org.springframework.data.cassandra.repository.config.EnableCassandraRepositories;

/**
 * Created by pranith macha on 12/3/17.
 */
@Configuration
@PropertySource(value = {"classpath:cassandra.properties"})
@EnableCassandraRepositories(basePackages = {"com.boot.docker.SpringBootDocker"})
public class CassandraConfig extends AbstractCassandraConfiguration {

    @Autowired
    private Environment environment;

    @Bean
    public CassandraClusterFactoryBean cluster() {
        CassandraClusterFactoryBean cluster = new CassandraClusterFactoryBean();
        cluster.setContactPoints(environment.getProperty("cassandra.contactpoints"));
        cluster.setPort(Integer.parseInt(environment.getProperty("cassandra.port")));
        return cluster;
    }

    @Override
    protected String getKeyspaceName() {
        return environment.getProperty("cassandra.keyspace");
    }

    @Bean
    public CassandraMappingContext cassandraMapping() throws ClassNotFoundException {
        return new BasicCassandraMappingContext();
    }
}
--------------------------------------------------------------------------------------------------------

import com.retail.target.data.ProductDAO;
import org.springframework.data.cassandra.repository.CassandraRepository;
import org.springframework.stereotype.Repository;

/**
 * Created by pranith macha on 12/3/17.
 */

@Repository
public interface ProductRepository extends CassandraRepository<ProductDAO> {
}
--------------------------------------------------------------------------------------------------------
import org.springframework.cassandra.core.Ordering;
import org.springframework.cassandra.core.PrimaryKeyType;
import org.springframework.data.cassandra.mapping.Column;
import org.springframework.data.cassandra.mapping.PrimaryKeyColumn;
import org.springframework.data.cassandra.mapping.Table;

/**
 * Created by pranith macha on 11/30/17.
 */

@Table(value = "product")
public class ProductDAO {


    @PrimaryKeyColumn(name = "productid", type = PrimaryKeyType.PARTITIONED, ordering = Ordering.DESCENDING)
    private long productid;

    @Column(value = "price")
    private double price;

    public long getProductid() {
        return productid;
    }

    public void setProductid(long productid) {
        this.productid = productid;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }
}


--------------------------------------------------------------------------------------------------------
	String fileName = "C:/Users/eo903e/contentModerator-master/ContentModeratorAPI/src/main/resources/objectionable_content.txt";
		Path path = Paths.get(fileName);
		byte[] bytes = Files.readAllBytes(path);
		List<String> langList = Files.readAllLines(path, StandardCharsets.UTF_8);
		return langList;
--------------------------------------------------------------------------------------------------------
version: "3"
services:
  mysql:
    build: mysql
    ports:
      - "3306:3306"
    environment:
        MYSQL_ROOT_PASSWORD: password
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10
--------------------------------------------------------------------------------------------------------
FROM mysql:5.6

# 確認用
# ENV TZ=Asia/Tokyo
# RUN echo $TZ | tee /etc/timezone && dpkg-reconfigure --frontend noninteractive tzdata

ADD my.cnf /etc/mysql/conf.d/my.cnf
ADD dbinit.sql /docker-entrypoint-initdb.d/

RUN chmod 644 /etc/mysql/conf.d/my.cnf /docker-entrypoint-initdb.d/*
--------------------------------------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS workdb;
CREATE DATABASE IF NOT EXISTS tododb;
CREATE USER 'user'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' WITH GRANT OPTION;
--------------------------------------------------------------------------------------------------------
[mysqld]
character_set_server=utf8mb4
collation_server=utf8mb4_general_ci
autocommit=0
transaction-isolation=READ-COMMITTED
--------------------------------------------------------------------------------------------------------
spring.data.rest.base-path=/api
--------------------------------------------------------------------------------------------------------
    @RequestMapping(value="/login", method=RequestMethod.POST)
    public AuthenticationToken login(

            @RequestBody AuthenticationRequest authenticationRequest, HttpSession session ) {
        String username = authenticationRequest.getUsername();
        String password = authenticationRequest.getPassword();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = authenticationManager.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        UserDetails user = customUserDetailsService.loadUserByUsername(username);  // 예제에선 유저 객체에서 직접 이름과 authorities와 id를 가져왔는데 details에서 가져오면 상관없지않을까?

        return new AuthenticationToken(user.getUsername(), user.getAuthorities(), session.getId());
    }
--------------------------------------------------------------------------------------------------------
    @PostMapping("")
    public String create(Member member) {
        MemberRole role = new MemberRole();
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        member.setUpw(passwordEncoder.encode(member.getUpw()));
        role.setRoleName("BASIC");
        member.setRoles(Arrays.asList(role));
        memberRepository.save(member);
        return "redirect:/";
    }
--------------------------------------------------------------------------------------------------------
import com.example.demo.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    //스프링 시큐리티에서 로그인 처리를 구현하려면 SecurityConfig에서
    // AuthenticationManagerBuilder를 주입해서 인증에 대한 처리를 해야 한다.

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        //method 를 autowired할때는 그 return 값을 객체로 빈에 저장하는것이 아니었나?
        auth.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean  // . authenticationManagerBean 메소드의 경우에는 SpringSecurity에서 사용되는 인증객체를 Bean으로 등록할 때 사용합니다.
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean(); }


    @Override
    public void configure(WebSecurity web) throws Exception
    {
        web.ignoring().antMatchers("/css/**", "/script/**", "image/**", "/fonts/**", "lib/**");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/user/login")
                .permitAll() .antMatchers("/user")
                .hasAuthority("USER") .antMatchers("/admin")
                .hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and().logout();

    }



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
--------------------------------------------------------------------------------------------------------
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

public class RegionCountryMap {
	
	private static RegionCountryMap instance = new RegionCountryMap();
	private Logger logger = Logger.getLogger(RegionCountryMap.class);
	
	private Properties prop;
	
	private RegionCountryMap(){
		
		InputStream  input = null;
		 
		try { 
			URL url = RegionCountryMap.class.getClassLoader().getResource("region_to_country.dat");
			String file = url.getPath();
			prop = new Properties();
			input = new FileInputStream(file);
			prop.load(input);
	 
		} catch (IOException ex) {
			logger.error(ex);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					logger.error(e);
				}
			}
		}
		
	}
	
	public static RegionCountryMap getInstance(){
		return instance;
	}
	
	public String getCountry(String region){
		return prop.getProperty(region);
	}
	
	public boolean hasCountry(String region){
		if(prop.getProperty(region) != null){
			return true;
		}
		return false;
	}

	public Set<Object> getKeys() {
		return prop.keySet();
	}
	

}
--------------------------------------------------------------------------------------------------------
public enum States {
	// US states
	AL("Alabama"), AK("Alaska"), AZ("Arizona"), AR("Arkansas"), CA("California"), CO("Colorado"),
	CT("Connecticut"), DE("Delaware"), FL("Florida"), GA("Georgia"), HI("Hawaii"), ID("Idaho"), 
	IL("Illinois"), IN("Indiana"), IA("Iowa"), KS("Kansas"), KY("Kentucky"), LA("Louisiana"),
	ME("Maine"), MD("Maryland"), MA("Massachusetts"), MI("Michigan"), MN("Minnesota"), MS("Mississippi"), 
	MO("Missouri"), MT("Montana"), NE("Nebraska"), NV("Nevada"), NH("New Hampshire"), NJ("New Jersey"),
	NM("New Mexico"), NY("New York"), NC("North Carolina"), ND("North Dakota"), OH("Ohio"), OK("Oklahoma"),
	OR("Oregon"), PA("Pennsylvania"), RI("Rhode Island"), SC("South Carolina"), SD("South Dakota"), 
	TN("Tennessee"), TX("Texas"), UT("Utah"), VT("Vermont"), VA("Virginia"), WA("Washington"), 
	WV("West Virginia"), WI("Wisconsin"), WY("Wyoming"), DC("District of Columbia"), AS("American Samoa"), 
	GU("Guam"), MP("Northern Mariana Islands"), PR("Puerto Rico"), VI("U.S. Virgin Islands"),
	// Canada states
	NB("New Brunswick"), NU("Nunavut"), NL("Newfoundland and Labrador"), MB("Manitoba"), YT("Yukon"),
	BC("British Columbia"), PE("Prince Edward Island"), NT("Northwest Territories"), QC("Quebec"), 
	NS("Nova Scotia"), AB("Alberta"), SK("Saskatchewan"), ON("Ontario");
	
	private String keyword;
	
	private States(String k) {
		this.keyword = k;
	}
	
	public static States getEnum(String state) {
		for (States c : States.values()) {
			if (c.name().equalsIgnoreCase(state)) {
				return c;
			}
		}
		return null;
	}
	
	public String getKeyword(){
		return keyword;
	}

}
--------------------------------------------------------------------------------------------------------
public enum Platform {
	ANDROID("android"),IOS("ios"),WINDOWS("windows");
	
	private String keyword;
	
	private Platform(String key) {
		this.keyword = key;
	}
	
	public static Platform matchText(String text){
		text = text.toLowerCase();
		for(Platform a:Platform.values()){
			if(text.contains(a.keyword)){
				return a;
			}
		}
		return null;
	}

	public static Platform getEnum(String val){
		for(Platform key: Platform.values()){
			if(key.keyword.equalsIgnoreCase(val)){
				return key;
			}
		}
		return null;
	}
}
--------------------------------------------------------------------------------------------------------

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.hadoop.hbase.util.Bytes;


//written by Robin Li for HBase key optimization

public class HBaseUtil {
	
	public static byte[] constructKey (int token_i, String udid_s){
		byte[] udid = udid_s.getBytes();
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
			udid = md.digest(udid); 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		int salt = ((int) udid[0])<<29 | (token_i);

		byte[] key = Bytes.add(Bytes.toBytes(salt), udid);
		return key;
	}
	
}
--------------------------------------------------------------------------------------------------------
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.hadoop.hbase.client.Result;
import org.apache.log4j.Logger;

public class HBaseThreadPool {
	
	private ExecutorService service = Executors.newFixedThreadPool(10);
	
	private static HBaseThreadPool instance = new HBaseThreadPool();
	private static Logger logger = Logger.getLogger(HBaseThreadPool.class);
	
	private HBaseThreadPool(){
		
	}
	
	public static HBaseThreadPool getInstance(){
		return instance;
	}
	
	public List<Future<Result>> submitHBaseTaskList(List<HBaseTask> tasks){
		try {
			List<Future<Result>> results = service.invokeAll(tasks);
			return results;
		} catch (InterruptedException e) {
			logger.error(e);
			e.printStackTrace();
		}
		return null;
	}

}
--------------------------------------------------------------------------------------------------------
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.ZooKeeperConnectionException;
import org.apache.hadoop.hbase.client.HConnection;
import org.apache.hadoop.hbase.client.HConnectionManager;
import org.apache.log4j.Logger;

public class HBaseDataSource {
	
	private Configuration config;
	private Logger logger = Logger.getLogger(HBaseDataSource.class);
	
	private static HBaseDataSource instance = new HBaseDataSource();
	
	private HBaseDataSource() {
		config = HBaseConfiguration.create(); 
	}
	
	public static HBaseDataSource getInstance(){
		return instance;
	}
	
	public HConnection getConnection(){
		try {
			return HConnectionManager.createConnection(config);
		} catch (ZooKeeperConnectionException e) {
			logger.error(e);
			e.printStackTrace();
		}
		return null;
	}
}
--------------------------------------------------------------------------------------------------------
#
# This file configures the New Relic Agent.  New Relic monitors
# Java applications with deep visibility and low overhead.  For more
# information, visit www.newrelic.com.
#
# This configuration file is custom generated for Tapjoy
#
# This section is for settings common to all environments.
# Do not add anything above this next line.
common: &default_settings
  #
  # ============================== LICENSE KEY ===============================

  # You must specify the license key associated with your New Relic
  # account.  This key binds your Agent's data to your account in the
  # New Relic service.
  license_key: 'bb8353602ba48d962a5db59ac4e1468d2da7fb8d'
  
  # Agent Enabled
  # Use this setting to force the agent to run or not run.
  # Default is true.
  # agent_enabled: true
  
  # Set to true to enable support for auto app naming.
  # The name of each web app is detected automatically
  # and the agent reports data separately for each one.
  # This provides a finer-grained performance breakdown for
  # web apps in New Relic.
  # Default is false.
  enable_auto_app_naming: false
  
  # Set to true to enable component-based transaction naming.
  # Set to false to use the URI of a web request as the name of the transaction.
  # Default is true.
  enable_auto_transaction_naming: true
 
  # Set the name of your application as you'd like it show up in New Relic.
  # if enable_auto_app_naming is false, the agent reports all data to this application.
  # Otherwise, the agent reports only background tasks (transactions for non-web applications) to this application.
  # To report data to more than one application, separate the application names with ";".
  # For example, to report data to"My Application" and "My Application 2" use this:
  # app_name: My Application;My Application 2
  # This setting is required.
  app_name: Reach Service

  # The agent uses its own log file to keep its logging
  # separate from that of your application.  Specify the log level here.
  # This setting is dynamic, so changes do not require restarting your application.
  # The levels in increasing order of verboseness are: off, severe, warning, info, fine, finer, finest
  # Default is info.
  log_level: info
  
  # Log all data to and from New Relic in plain text.
  # This setting is dynamic, so changes do not require restarting your application.
  # Default is false.
  #audit_mode: true
  
  # The number of log files to use.
  # Default is 1.
  #log_file_count: 1
  
  # The maximum number of bytes to write to any one log file.
  # Default is 0 (no limit).
  #log_limit_in_kbytes: 0

  # The name of the log file.
  # Default is newrelic_agent.log.
  #log_file_name: newrelic_agent.log
  
  # The log file directory.
  # Default is the logs directory in the newrelic.jar parent directory.
  #log_file_path:
  
  # The agent communicates with New Relic via https by
  # default.  If you want to communicate with newrelic via http,
  # then turn off SSL by setting this value to false.
  # This work is done asynchronously to the threads that process your
  # application code, so response times will not be directly affected
  # by this change.
  # Default is true.
  ssl: true
  
  # Proxy settings for connecting to the New Relic server.
  #
  # If a proxy is used, the host setting is required.  Other settings
  # are optional.  Default port is 8080.  The username and password
  # settings will be used to authenticate to Basic Auth challenges
  # from a proxy server.
  #
  # proxy_host: hostname
  # proxy_port: 8080
  # proxy_user: username
  # proxy_password: password

  # Tells transaction tracer and error collector (when enabled)
  # whether or not to capture HTTP params.  When true, frameworks can
  # exclude HTTP parameters from being captured.
  # Default is false.
  capture_params: false
  
  # Tells transaction tracer and error collector to not to collect
  # specific http request parameters. 
  # ignored_params: credit_card, ssn, password

  # Transaction tracer captures deep information about slow
  # transactions and sends this to the New Relic service once a
  # minute. Included in the transaction is the exact call sequence of
  # the transactions including any SQL statements issued.
  transaction_tracer:
  
    # Transaction tracer is enabled by default. Set this to false to
    # turn it off. This feature is only available at the higher product levels.
    # Default is true.
    enabled: true
    
    # Threshold in seconds for when to collect a transaction
    # trace. When the response time of a controller action exceeds
    # this threshold, a transaction trace will be recorded and sent to
    # New Relic. Valid values are any float value, or (default) "apdex_f",
    # which will use the threshold for the "Frustrated" Apdex level
    # (greater than four times the apdex_t value).
    # Default is apdex_f.
    transaction_threshold: apdex_f
 
    # When transaction tracer is on, SQL statements can optionally be
    # recorded. The recorder has three modes, "off" which sends no
    # SQL, "raw" which sends the SQL statement in its original form,
    # and "obfuscated", which strips out numeric and string literals.
    # Default is obfuscated.
    record_sql: obfuscated
    
    # Obfuscate only occurrences of specific SQL fields names.
    # This setting only applies if "record_sql" is set to "raw".
    #obfuscated_sql_fields: credit_card, ssn, password

    # Set this to true to log SQL statements instead of recording them.
    # SQL is logged using the record_sql mode.
    # Default is false.
    log_sql: false

    # Threshold in seconds for when to collect stack trace for a SQL
    # call. In other words, when SQL statements exceed this threshold,
    # then capture and send to New Relic the current stack trace. This is
    # helpful for pinpointing where long SQL calls originate from.
    # Default is 0.5 seconds.
    stack_trace_threshold: 0.5

    # Determines whether the agent will capture query plans for slow
    # SQL queries. Only supported for MySQL and PostgreSQL.
    # Default is true.
    explain_enabled: true

    # Threshold for query execution time below which query plans will not 
    # not be captured.  Relevant only when `explain_enabled` is true.
    # Default is 0.5 seconds.
    explain_threshold: 0.5
    
    # Use this setting to control the variety of transaction traces.
    # The higher the setting, the greater the variety.
    # Set this to 0 to always report the slowest transaction trace.
    # Default is 20.
    top_n: 20
    
  
  # Error collector captures information about uncaught exceptions and
  # sends them to New Relic for viewing
  error_collector:
    
    # Error collector is enabled by default. Set this to false to turn
    # it off. This feature is only available at the higher product levels.
    # Default is true.
    enabled: true
        
    # To stop specific exceptions from reporting to New Relic, set this property
    # to a comma separated list of full class names.
    #
    # ignore_errors:

    # To stop specific http status codes from being reporting to New Relic as errors, 
    # set this property to a comma separated list of status codes to ignore.
    # When this property is commented out it defaults to ignoring 404s.
    #
    # ignore_status_codes: 404

  # Cross Application Tracing adds request and response headers to
  # external calls using the Apache HttpClient libraries to provided better
  # performance data when calling applications monitored by other New Relic Agents.
  #
  cross_application_tracer:
    # Set to true to enable cross application tracing.
    # Default is true.
    enabled: true

  # Thread profiler measures wall clock time, CPU time, and method call counts
  # in your application's threads as they run.
  thread_profiler:

    # Set to false to disable the thread profiler.
    # Default is true.
    enabled: true
  
  #============================== Browser Monitoring ===============================
  # New Relic Real User Monitoring gives you insight into the performance real users are
  # experiencing with your website. This is accomplished by measuring the time it takes for
  # your users' browsers to download and render your web pages by injecting a small amount
  # of JavaScript code into the header and footer of each page. 
  browser_monitoring:
    # By default the agent automatically inserts API calls in compiled JSPs to
    # inject the monitoring JavaScript into web pages.
    # Set this attribute to false to turn off this behavior.
    auto_instrument: true
    # Set this attribute to false to prevent injection of the monitoring JavaScript.
    # Default is true.
    enabled: true
    
# Application Environments
# ------------------------------------------
# Environment specific settings are in this section.
# You can use the environment to override the default settings.
# For example, to change the app_name setting.
# Use -Dnewrelic.environment=<environment> on the Java command line
# to set the environment.
# The default environment is production.

# NOTE if your application has other named environments, you should
# provide configuration settings for these environments here.

development:
  <<: *default_settings
  app_name: My Application (Development)

test:
  <<: *default_settings
  app_name: My Application (Test)

production:
  <<: *default_settings

staging:
  <<: *default_settings
  app_name: My Application (Staging)
--------------------------------------------------------------------------------------------------------
#!/bin/bash

# Set up classpath and invoke 'java' with it ...


cp=".:./../resources:./../dist/ReachService.jar"

cp=$cp:$(echo ./../lib/*.jar | tr ' ' :)
echo "classpath are: $cp"

ja="-javaagent:./../newrelic/newrelic.jar"
#ja="-javaagent:/home/tjopt/GIT_opt/tapjoyoptimization/opt_server/newrelic/newrelic.jar"
#echo "Javaagent: $ja"

exec java "$ja" -cp $cp com.tapjoy.reach.service.ReachService 
echo $! > pid
--------------------------------------------------------------------------------------------------------
@Configuration
@ComponentScan("com.concretepage")
@EnableWebMvc
public class AppConfig implements WebMvcConfigurer {
    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.indentOutput(true);
        converters.add(new MappingJackson2HttpMessageConverter(builder.build()));
    }
} 

--------------------------------------------------------------------------------------------------------
//    @Bean
//    public FilterRegistrationBean httpsOnlyFilter() {
//        FilterRegistrationBean registration = new FilterRegistrationBean();
//        registration.setFilter(new HttpsOnlyFilter());
//        registration.addUrlPatterns("/*");
//        return registration;
//    }
--------------------------------------------------------------------------------------------------------
//import org.springframework.context.annotation.Configuration;
//import org.springframework.data.mongodb.core.convert.DefaultMongoTypeMapper;
//
///**
// *
// * Custom Mongo Type Mapper
// *
// * @author Alex
// * @version 1.0.0
// * @since 2017-08-08
// */
//@Configuration("publicationAppConfiguration")
//public class AppConfiguration2 extends DefaultMongoTypeMapper {
//    //implement custom type mapping here
//}

--------------------------------------------------------------------------------------------------------
    @Bean
    public HazelcasetInstance getInstance() {
        return HazelcasetClient.newHazelCastClient();
    }
--------------------------------------------------------------------------------------------------------
private class SwaggerInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!authHeaderValid(request.getHeader("Authorization"))) {
            response.addHeader("Access-Control-Allow-Origin", "null");
            response.addHeader("WWW-Authenticate", "Basic realm=\"\"");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().println("HTTP Status " + HttpServletResponse.SC_UNAUTHORIZED);

            return false;
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception { }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception { }

    private boolean authHeaderValid(String authorization) {
        if (authorization != null && authorization.startsWith("Basic ")) {
            final String[] values = new String(Base64.getDecoder().decode(authorization.substring("Basic ".length()))).split(":");

            return values[0].equals("username") && values[1].equals("password");
        }

        return false;
    }
}
--------------------------------------------------------------------------------------------------------
//public static class CustomizedViewResolver extends UrlBasedViewResolver {
//    @Override
//    protected AbstractUrlBasedView buildView(final String viewName) throws Exception {
//        String newViewName;
//        if (viewName.equals("index.html")) {
//            newViewName = "swagger-ui.html";
//        } else {
//            newViewName = viewName;
//        }
//        return super.buildView(newViewName);
//    }
//
//    @Nullable
//    protected Class<?> getViewClass() {
//        return InternalResourceView.class;
//    }
//}

/*
 @Controller
 public class HomeController {

 @RequestMapping(value = "/", method = RequestMethod.GET)
 public ModelAndView home(Locale locale, Model model) {
 // (...)

 return new ModelAndView("/someurl/resources/home.html"); // NOTE here there is /someurl/resources
 }

 }

 */

/*
@Configuration
@EnableWebMvc
public class WebConfig extends WebMvcConfigurerAdapter {
  @Autowired
  @Qualifier("jstlViewResolver")
  private ViewResolver jstlViewResolver;

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/someurl/resources/**").addResourceLocations("/resources/");

  }

  @Bean
  @DependsOn({ "jstlViewResolver" })
  public ViewResolver viewResolver() {
    return jstlViewResolver;
  }

  @Bean(name = "jstlViewResolver")
  public ViewResolver jstlViewResolver() {
    UrlBasedViewResolver resolver = new UrlBasedViewResolver();
    resolver.setPrefix(""); // NOTE: no preffix here
    resolver.setViewClass(JstlView.class);
    resolver.setSuffix(""); // NOTE: no suffix here
    return resolver;
  }

// NOTE: you can use InternalResourceViewResolver it does not matter
//  @Bean(name = "internalResolver")
//  public ViewResolver internalViewResolver() {
//    InternalResourceViewResolver resolver = new InternalResourceViewResolver();
//    resolver.setPrefix("");
//    resolver.setSuffix("");
//    return resolver;
//  }
}
--------------------------------------------------------------------------------------------------------
////    @Bean
////    public SSLContextParameters sslContextParameters(@Value("${horweb.javamail.keystore.location}") final String location,
////                                                     @Value("${horweb.javamail.keystore.password}") final String password) {
////        final KeyStoreParameters store = new KeyStoreParameters();
////        store.setResource(location);
////        store.setPassword(password);
////
////        final TrustManagersParameters trust = new TrustManagersParameters();
////        trust.setKeyStore(store);
////
////        final SSLContextParameters parameters = new SSLContextParameters();
////        parameters.setTrustManagers(trust);
////        return parameters;
////    }
--------------------------------------------------------------------------------------------------------
@Configuration
@ConditionalOnClass({ DispatcherHandler.class, HttpHandler.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnMissingBean(HttpHandler.class)
@AutoConfigureAfter({ WebFluxAutoConfiguration.class })
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE + 10)
--------------------------------------------------------------------------------------------------------
@Configuration
public class HandlerConfiguration {

    /*
     * Create required HandlerMapping, to avoid several default HandlerMapping instances being created
     */
    @Bean
    public HandlerMapping handlerMapping() {
        return new RequestMappingHandlerMapping();
    }

    /*
     * Create required HandlerAdapter, to avoid several default HandlerAdapter instances being created
     */
    @Bean
    public HandlerAdapter handlerAdapter() {
        return new RequestMappingHandlerAdapter();
    }

    /*
     * optimization - avoids creating default exception resolvers; not required as the serverless container handles
     * all exceptions
     *
     * By default, an ExceptionHandlerExceptionResolver is created which creates many dependent object, including
     * an expensive ObjectMapper instance.
     */
    @Bean
    public HandlerExceptionResolver handlerExceptionResolver() {
        return (request, response, handler, ex) -> null;
    }
}
--------------------------------------------------------------------------------------------------------
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Profile;
//import org.springframework.hateoas.config.EnableHypermediaSupport;
//import org.springframework.hateoas.config.EnableHypermediaSupport.HypermediaType;
//
///**
// * Separate configuration class to enable Spring Hateoas functionality if the {@code hateoas} profile is activated.
// *
// */
//@Configuration
//@Profile("hateoas")
//@EnableHypermediaSupport(type = HypermediaType.HAL)
//public class HyperMediaConfiguration {
//}
--------------------------------------------------------------------------------------------------------
//import com.mongodb.MongoClient;
//import com.mongodb.MongoClientOptions;
//
//import com.wildbeeslabs.api.rest.common.service.interfaces.IPropertiesConfiguration;
//import java.util.HashSet;
//import java.util.Properties;
//import java.util.Set;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
//import org.springframework.data.mongodb.MongoDbFactory;
//import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
//import org.springframework.data.mongodb.config.EnableMongoAuditing;
//import org.springframework.data.mongodb.core.MongoTemplate;
//import org.springframework.data.mongodb.core.SimpleMongoDbFactory;
//import org.springframework.data.mongodb.core.convert.MappingMongoConverter;
//import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
//import org.springframework.scheduling.annotation.EnableAsync;
//import org.springframework.transaction.annotation.EnableTransactionManagement;
//import org.springframework.data.mongodb.core.convert.DefaultMongoTypeMapper;
//import org.springframework.data.mongodb.core.convert.MongoTypeMapper;
//import org.springframework.data.mongodb.core.mapping.event.LoggingEventListener;
//import org.springframework.data.mongodb.gridfs.GridFsTemplate;
//
///**
// *
// * Mongo DB Configuration
// *
// * @author Alex
// * @version 1.0.0
// * @since 2017-08-08
// */
//@Configuration("publicationMongoConfiguration")
//@EnableAutoConfiguration
//@EnableAsync
//@EnableMongoAuditing
//@EnableTransactionManagement
//@EnableMongoRepositories(basePackages = "com.wildbeeslabs.api.rest.publication.repository")
////@ComponentScan(basePackages = {"com.wildbeeslabs.api.rest.publication.*"})
//class MongoConfiguration extends AbstractMongoConfiguration {
//
//    @Autowired
//    private IPropertiesConfiguration propertyConfig;
//
////    @Value("${datasource.publicationapp.mongodb.url}")
////    private String mongodbUrl;
////
////    @Value("${datasource.publicationapp.mongodb.db}")
////    private String defaultDb;
//    @Bean
//    public GridFsTemplate gridFsTemplate() throws Exception {
//        return new GridFsTemplate(mongoDbFactory(), mappingMongoConverter());
//    }
//
//    @Override
//    protected String getDatabaseName() {
//        return propertyConfig.getProperty("datasource.publicationapp.mongodb.db");
//    }
//
////    @Override
////    public String getMappingBasePackage() {
////        return "com.wildbeeslabs.api.rest.publication.model";
//////        return propertyConfig.getProperty("datasource.publicationapp.mongodb.basePackage");
////    }
//
//    @Bean
//    @Override
//    public MongoClient mongo() throws Exception {
//        MongoClientOptions mongoOptions = new MongoClientOptions.Builder().maxWaitTime(propertyConfig.getProperty("datasource.publicationapp.mongodb.timeout", Integer.class)).build();
//        MongoClient mongo = new MongoClient(propertyConfig.getProperty("datasource.publicationapp.mongodb.url"), mongoOptions);
//        return mongo;
//    }
//
//    @Bean
//    @Override
//    public MongoDbFactory mongoDbFactory() throws Exception {
//        MongoDbFactory mongoDbFactory = new SimpleMongoDbFactory(mongo(), propertyConfig.getProperty("datasource.publicationapp.mongodb.db"));//new MongoClient()
//        return mongoDbFactory;
//    }
//
//    @Bean
//    @Override
//    public MappingMongoConverter mappingMongoConverter() throws Exception {
//        MappingMongoConverter converter = super.mappingMongoConverter();
//        converter.setTypeMapper(customTypeMapper());
//        return converter;
//    }
//
//    @Bean
//    public MongoTypeMapper customTypeMapper() {
//        return new DefaultMongoTypeMapper(null);
//    }
//
//    @Bean
//    @Override
//    public MongoTemplate mongoTemplate() throws Exception {
//        return new MongoTemplate(mongoDbFactory());
//    }
//
////    @Bean
////    public MongoTemplate mongoTemplate(MongoDbFactory mongoDbFactory, MongoMappingContext context) {
////        MappingMongoConverter converter = new MappingMongoConverter(new DefaultDbRefResolver(mongoDbFactory), context);
////        converter.setTypeMapper(new DefaultMongoTypeMapper(null));
////        MongoTemplate mongoTemplate = new MongoTemplate(mongoDbFactory, converter);
////        return mongoTemplate;
////    }
//    @Bean
//    public static PropertySourcesPlaceholderConfigurer propertyConfigInDev() {
//        return new PropertySourcesPlaceholderConfigurer();
//    }
//
//    @Bean
//    public LoggingEventListener mappingEventsListener() {
//        return new LoggingEventListener();
//    }
//
//    /**
//     * Get Mongo properties configuration
//     *
//     * @return Mongo properties configuration
//     */
//    private Properties mongoProperties() {
//        final Properties properties = new Properties();
//        properties.put("mongo.url", propertyConfig.getMandatoryProperty("datasource.publicationapp.mongodb.url"));
//        properties.put("mongo.db", propertyConfig.getProperty("datasource.publicationapp.mongodb.db"));
//        properties.put("mongo.port", propertyConfig.getProperty("datasource.publicationapp.mongodb.port"));
//        properties.put("mongo.timeout", propertyConfig.getProperty("datasource.publicationapp.mongodb.timeout"));
//        return properties;
//    }
//}

//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.data.mongodb.core.mapping.event.ValidatingMongoEventListener;
//import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
//
//@Configuration
//public class MongoValidationConfig {
//
//    @Bean
//    public ValidatingMongoEventListener validatingMongoEventListener() {
//        return new ValidatingMongoEventListener(validator());
//    }
//
//    @Bean
//    public LocalValidatorFactoryBean validator() {
//        return new LocalValidatorFactoryBean();
//    }
//}
--------------------------------------------------------------------------------------------------------
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * Utility class which provides utility methods for managing json content from a
 * path.
 *
 * @author giuliana.bezerra
 *
 */
public class JSONPathUtil {

	private JSONPathUtil() {
		// DO NOTHING.
	}

	public static String getJSONFromPath(String jsonPath) {
		try {
			return handleJsonPath(jsonPath);
		} catch (Exception e) {
			throw new RestRuntimeException(e.getMessage());
		}
	}

	private static String handleJsonPath(String jsonPath) throws RestException {
		try {
			if (isPathNotEmpty(jsonPath))
				return getJSONFileContent(jsonPath);
			else
				return null;
		} catch (Exception e) {
			throw new RestException(e);
		}
	}

	private static boolean isPathNotEmpty(String jsonPath) {
		return jsonPath != null && !jsonPath.trim().isEmpty();
	}

	private static String getJSONFileContent(String jsonPath) throws RestException {
		FileReader fileReader = null;
		BufferedReader bufferedReader = null;

		try {
			fileReader = new FileReader(jsonPath);
			bufferedReader = new BufferedReader(fileReader);
			String line;
			StringBuilder json = new StringBuilder();
			while ((line = bufferedReader.readLine()) != null) {
				json.append(line);
			}
			return json.toString();
		} catch (Exception e) {
			throw new RestException(e);
		} finally {
			closeResources(fileReader, bufferedReader);
		}
	}

	private static void closeResources(FileReader fileReader, BufferedReader bufferedReader) {
		try {
			if (fileReader != null)
				fileReader.close();
			if (bufferedReader != null)
				bufferedReader.close();
		} catch (IOException e) {
			// DO NOTHING.
		}
	}
}
--------------------------------------------------------------------------------------------------------
//@SpringBootApplication(exclude={com.github.torlight.sbex.User.class})
public class MyTypeExcludeFilter extends TypeExcludeFilter {

    @Override
    public boolean match(final MetadataReader metadataReader, final MetadataReaderFactory metadataReaderFactory) throws IOException {
        return StringUtils.equalsAnyIgnoreCase("com.github.torlight.sbex.User", metadataReader.getClassMetadata().getClassName());
    }
}
--------------------------------------------------------------------------------------------------------
//@Configuration
//@EnableWebMvc
//@EnableSpringDataWebSupport
//public class PaginationConfig extends SpringDataWebConfiguration {
//
//    @Override
//    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
//        PageableHandlerMethodArgumentResolver resolver = new PageableHandlerMethodArgumentResolver(sortResolver());
//        resolver.setFallbackPageable(new PageRequest(0, 50));
//        resolver.setSizeParameterName("p");
//        resolver.setPageParameterName("s");
//        argumentResolvers.add(resolver);
//        super.addArgumentResolvers(argumentResolvers);
//    }
//}
--------------------------------------------------------------------------------------------------------
import retrofit.Call;
import retrofit.Retrofit;
import retrofit.http.Body;
import retrofit.http.GET;
import retrofit.http.POST;
import retrofit.http.Query;

public interface Apiservice {

    @GET("curators.json")
    Call<Freemusicpojo> getDataset(@Query("api_key")  String api_key);

}
--------------------------------------------------------------------------------------------------------

import java.lang.Math;
import java.util.Queue;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.HashMap;

public class ChessKnight {
    private static int[] row = { 2, 2, -2, -2, 1, 1, -1, -1 };
    private static int[] column = { -1, 1, 1, -1, 2, -2, 2, -2 };

    public static int getYCoordinate(String position) {
        for (int i = position.length() - 1; i >= 0; i--) {
            if (Character.isLetter(position.charAt(i))) {
                return Integer.valueOf(position.substring(i + 1)) - 1;
            }
        }

        return -1;
    }

    public static int getXCoordinate(String position) {
        int result = 0, stop = 0;

        for (int i = 0; i < position.length(); i++) {
            if (Character.isDigit(position.charAt(i))) {
                stop = i - 1;
                break;
            }
        }

        for (int i = 0, j = stop; i <= stop; i++, j--) {
            result += ((int) Character.toLowerCase(position.charAt(i)) - 96) * Math.pow(26.0, j);
        }

        return result - 1;
    }

    public static int count(int x1, int y1, int x2, int y2, int width, int height) {
        return bfs(new Node(x1, y1), new Node(x2, y2), width, height);
    }

    public static boolean valid(int x, int y, int width, int height) {
        if (x < 0 || y < 0 || x >= width || y >= height)
            return false;

        return true;
    }

    public static int bfs(Node start, Node end, int width, int height) {
        Map<Node, Boolean> visited = new HashMap<>();
        Queue<Node> q = new ArrayDeque<>();

        q.add(start);

        while (!q.isEmpty()) {
            Node node = q.poll();

            int x = node.x;
            int y = node.y;
            int distance = node.distance;

            if (x == end.x && y == end.y)
                return distance;

            if (visited.get(node) == null) {
                visited.put(node, true);

                for (int i = 0; i < 8; i++) {
                    int x1 = x + row[i];
                    int y1 = y + column[i];

                    if (valid(x1, y1, width, height))
                        q.add(new Node(x1, y1, distance + 1));
                }
            }
        }

        return -1;
    }
}

public class Node {
    int x, y, distance;

    public Node(int x, int y) {
        this.x = x;
        this.y = y;
    }

    public Node(int x, int y, int distance) {
        this.x = x;
        this.y = y;
        this.distance = distance;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Node node = (Node) o;

        if (x != node.x) return false;
        if (y != node.y) return false;
        return distance == node.distance;
    }

    @Override
    public int hashCode() {
        int result = x;
        result = 31 * result + y;
        result = 31 * result + distance;
        return result;
    }
}
--------------------------------------------------------------------------------------------------------
import java.io.PrintStream;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import com.netiq.websockify.PortUnificationHandler;
import com.netiq.websockify.WebsockifyServer;
import com.netiq.websockify.WebsockifyServer.SSLSetting;
import com.netiq.websockify.WebsockifySslContext;



public class ExternalVNCRepeater
{   
   @Option(name="--help",usage="show this help message and quit")
   private boolean showHelp = false;
   
   @Option( name = "--enable-ssl", usage = "enable SSL" )
   private boolean       enableSSL  = false;

   @Option( name = "--ssl-only", usage = "disallow non-encrypted connections" )
   private boolean       requireSSL = false;
   
   @Option(name="--keystore",usage="path to a java keystore file. Required for SSL.")
   private String keystore = null;
   
   @Option(name="--keystore-password",usage="password to the java keystore file. Required for SSL.")
   private String keystorePassword = null;
   
   @Option(name="--keystore-key-password",usage="password to the private key in the java keystore file. If not specified the keystore-password value will be used.")
   private String keystoreKeyPassword = null;
   
   @Option(name="--direct-proxy-timeout",usage="connection timeout before a direct proxy connection is established in milliseconds. Default is 5000 (5 seconds). With the VNC protocol the server sends the first message. This means that a client that wants a direct proxy connection will connect and not send a message. The external VNC repeater will wait the specified number of milliseconds for an incoming connection to send a message. If no message is recieved it initiates a direct proxy connection. Setting this value too low will cause connection attempts that aren't direct proxy connections to fail. Set this to 0 to disable direct proxy connections.")
   private int directProxyTimeout = 5000;

   @Argument( index = 0, metaVar = "source_port", usage = "(required) local port the external repeater will listen on", required = true )
   private int           sourcePort;

   @Argument( index = 1, metaVar = "cmas_base_url", usage = "(required) the base URL of the CMAS server.  For example http://ncmdev.netiq.com:8182", required = true )
   private String        cmasBaseUrl;

   private CmdLineParser parser;


   public ExternalVNCRepeater()
   {
      parser = new CmdLineParser ( this );
   }


   public void printUsage( PrintStream out )
   {
      out.println ( "Usage:" );
      out.println ( " java -jar external-vnc-repeater.jar [options] source_port cmas_base_url" );
      out.println ( );
      out.println ( "Options:" );
      parser.printUsage ( out );
      out.println ( );
      out.println ( "Example:" );
      out.println ( " java -jar external-vnc-repeater.jar 5900 https://cloud.acmecloud.demo" );
   }
   
   public static void main(String[] args) throws Exception {
     new ExternalVNCRepeater().doMain(args);
   }
   
   public void doMain(String[] args) throws Exception
   {
      parser.setUsageWidth ( 80 );

      // parse the command line arguments
      try
      {
         parser.parseArgument ( args );
      }
      // if there's a problem show the error and command line usage help
      catch ( CmdLineException e )
      {
         System.err.println ( e.getMessage ( ) );
         printUsage ( System.err );
         return;
      }

      // if we were asked for help show it and exit
      if ( showHelp )
      {
         printUsage ( System.out );
         return;
      }
      
      // set the SSL setting based on the command line params
      SSLSetting sslSetting = SSLSetting.OFF;
      if ( requireSSL ) sslSetting = SSLSetting.REQUIRED;
      else if ( enableSSL ) sslSetting = SSLSetting.ON;

      // if we are doing SSL
      if ( sslSetting != SSLSetting.OFF ) {
         // make sure there is a keystore path specified
          if (keystore == null || keystore.isEmpty()) {
              System.err.println("No keystore specified.");
          printUsage(System.err);
              System.exit(1);
          }

          // and make sure there is a keystore password specified
          if (keystorePassword == null || keystorePassword.isEmpty()) {
              System.err.println("No keystore password specified.");
          printUsage(System.err);
              System.exit(1);
          }
          
          // if there's no keystore key password, use the keystore password
          if (keystoreKeyPassword == null || keystoreKeyPassword.isEmpty()) {
             keystoreKeyPassword = keystorePassword;
          }
          
          // and validate the keystore settings - this actually starts up an SSL
          // context and lets us know if there were exceptions starting it
          // this doesn't happen in the current thread when the server is started
          // so we only know about it in worker threads and put it out to the logger
          try
          {
             WebsockifySslContext.validateKeystore(keystore, keystorePassword, keystoreKeyPassword);
          }
          catch ( Exception e )
          {
             System.err.println("Error validating keystore: " + e.getMessage() );
             printUsage(System.err);
             System.exit(2);
          }
      }

      System.out.println ( "Proxying *:" + sourcePort + " to workloads defined by CMAS at " + cmasBaseUrl + " ..." );
      if(sslSetting != SSLSetting.OFF) System.out.println("SSL is " + (sslSetting == SSLSetting.REQUIRED ? "required." : "enabled."));
      
      PortUnificationHandler.setConnectionToFirstMessageTimeout(directProxyTimeout);

      WebsockifyServer ws = new WebsockifyServer ( );
      ws.connect ( sourcePort, new CMASRestResolver ( cmasBaseUrl ), sslSetting, keystore, keystorePassword, keystoreKeyPassword, null );

   }
}

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;

public class ClientHelper {
	
	public static ClientConfig configureClient() {
		TrustManager[ ] certs = new TrustManager[ ] {
	            new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					public void checkServerTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
					public void checkClientTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
				}
	    };
	    SSLContext ctx = null;
	    try {
	        ctx = SSLContext.getInstance("TLS");
	        ctx.init(null, certs, new SecureRandom());
	    } catch (java.security.GeneralSecurityException ex) {
	    }
	    HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
	    
	    ClientConfig config = new DefaultClientConfig();
	    try {
		    config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(
		        new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
		        }, 
		        ctx
		    ));
	    } catch(Exception e) {
	    }
	    return config;
	}
	
	public static Client createClient() {
	    return Client.create(ClientHelper.configureClient());
	}
}
--------------------------------------------------------------------------------------------------------
# See http://docs.spring.io/spring-boot/docs/current/reference/html/common-application-properties.html
spring.thymeleaf.cache=false
spring.main.show-banner=false
logging.level.jdbc=OFF
logging.level.jdbc.sqltiming=DEBUG
logging.level.jdbc.resultsettable=DEBUG
--------------------------------------------------------------------------------------------------------
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
        <plugin>
            <artifactId>maven-jar-plugin</artifactId>
            <executions>
                <execution>
                    <id>lib</id>
                    <phase>package</phase>
                    <goals>
                        <goal>jar</goal>
                    </goals>
                    <configuration>
                        <classifier>lib</classifier>
                        <excludes>
                            <exclude>application.yml</exclude>
                        </excludes>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
--------------------------------------------------------------------------------------------------------
package com.paragon.microservices.crmmailadapter.system.property;

import com.paragon.mailingcontour.commons.databus.model.NameValueEntry;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@Validated
@Component
@ConfigurationProperties(prefix = "rest.registry", ignoreInvalidFields = true)
public class RestRegistryProperty {
    @NotBlank(message = "{property.rest.registry.base-path.notBlank}")
    private String basePath;

    /**
     * Get user path {@link Paths}
     */
    @Valid
    @NestedConfigurationProperty
    @NotNull(message = "{property.rest.registry.get-user-path.notNull}")
    private ParamsPaths getUserPath;

    /**
     * Create user path {@link Paths}
     */
    @Valid
    @NestedConfigurationProperty
    @NotNull(message = "{property.rest.registry.create-user-path.notNull}")
    private Paths createUserPath;

    @Data
    @Validated
    public static class Paths {
        @NotBlank(message = "{property.rest.registry.user-path.notBlank}")
        private String userPath;
    }

    @Data
    @Validated
    @EqualsAndHashCode(callSuper = true)
    @ToString(callSuper = true)
    public static class ParamsPaths extends Paths {
        @Valid
        @NestedConfigurationProperty
        @NotNull(message = "{property.rest.registry.params.notNull}")
        private Params params;
    }

    @Data
    @Validated
    public static class Params {
        @NestedConfigurationProperty
        @NotNull(message = "{property.rest.registry.params.email.notNull}")
        private NameValueEntry email;
    }
}

--------------------------------------------------------------------------------------------------------
        <dependency>
            <groupId>com.jayway.restassured</groupId>
            <artifactId>rest-assured</artifactId>
            <version>${rest.assured.version}</version>
        </dependency>
		
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>springloaded</artifactId>
                        <version>${spring-loaded.version}</version>
                    </dependency>
                </dependencies>
            </plugin>
--------------------------------------------------------------------------------------------------------
/**
 * Syntax highlighting styles
 */
.highlight {
    background: #fff;
    @extend %vertical-rhythm;

    .c     { color: #998; font-style: italic } // Comment
    .err   { color: #a61717; background-color: #e3d2d2 } // Error
    .k     { font-weight: bold } // Keyword
    .o     { font-weight: bold } // Operator
    .cm    { color: #998; font-style: italic } // Comment.Multiline
    .cp    { color: #999; font-weight: bold } // Comment.Preproc
    .c1    { color: #998; font-style: italic } // Comment.Single
    .cs    { color: #999; font-weight: bold; font-style: italic } // Comment.Special
    .gd    { color: #000; background-color: #fdd } // Generic.Deleted
    .gd .x { color: #000; background-color: #faa } // Generic.Deleted.Specific
    .ge    { font-style: italic } // Generic.Emph
    .gr    { color: #a00 } // Generic.Error
    .gh    { color: #999 } // Generic.Heading
    .gi    { color: #000; background-color: #dfd } // Generic.Inserted
    .gi .x { color: #000; background-color: #afa } // Generic.Inserted.Specific
    .go    { color: #888 } // Generic.Output
    .gp    { color: #555 } // Generic.Prompt
    .gs    { font-weight: bold } // Generic.Strong
    .gu    { color: #aaa } // Generic.Subheading
    .gt    { color: #a00 } // Generic.Traceback
    .kc    { font-weight: bold } // Keyword.Constant
    .kd    { font-weight: bold } // Keyword.Declaration
    .kp    { font-weight: bold } // Keyword.Pseudo
    .kr    { font-weight: bold } // Keyword.Reserved
    .kt    { color: #458; font-weight: bold } // Keyword.Type
    .m     { color: #099 } // Literal.Number
    .s     { color: #d14 } // Literal.String
    .na    { color: #008080 } // Name.Attribute
    .nb    { color: #0086B3 } // Name.Builtin
    .nc    { color: #458; font-weight: bold } // Name.Class
    .no    { color: #008080 } // Name.Constant
    .ni    { color: #800080 } // Name.Entity
    .ne    { color: #900; font-weight: bold } // Name.Exception
    .nf    { color: #900; font-weight: bold } // Name.Function
    .nn    { color: #555 } // Name.Namespace
    .nt    { color: #000080 } // Name.Tag
    .nv    { color: #008080 } // Name.Variable
    .ow    { font-weight: bold } // Operator.Word
    .w     { color: #bbb } // Text.Whitespace
    .mf    { color: #099 } // Literal.Number.Float
    .mh    { color: #099 } // Literal.Number.Hex
    .mi    { color: #099 } // Literal.Number.Integer
    .mo    { color: #099 } // Literal.Number.Oct
    .sb    { color: #d14 } // Literal.String.Backtick
    .sc    { color: #d14 } // Literal.String.Char
    .sd    { color: #d14 } // Literal.String.Doc
    .s2    { color: #d14 } // Literal.String.Double
    .se    { color: #d14 } // Literal.String.Escape
    .sh    { color: #d14 } // Literal.String.Heredoc
    .si    { color: #d14 } // Literal.String.Interpol
    .sx    { color: #d14 } // Literal.String.Other
    .sr    { color: #009926 } // Literal.String.Regex
    .s1    { color: #d14 } // Literal.String.Single
    .ss    { color: #990073 } // Literal.String.Symbol
    .bp    { color: #999 } // Name.Builtin.Pseudo
    .vc    { color: #008080 } // Name.Variable.Class
    .vg    { color: #008080 } // Name.Variable.Global
    .vi    { color: #008080 } // Name.Variable.Instance
    .il    { color: #099 } // Literal.Number.Integer.Long
}
--------------------------------------------------------------------------------------------------------
version: 2
jobs:

  build-caches:
    machine: true
    steps:
      # restore_cache.keys does not work, so multiple restore_cache.key is used
      - restore_cache:
          key: m2-cache
      - checkout
      - run:
          name: skip_ci creation
          command: |
            mkdir -p .ci-temp
            echo -n ".github|appveyor.yml|.travis.yml|\.ci/" >> .ci-temp/skip_ci_files
            echo -n "|distelli-manifest.yml|fast-forward-merge.sh" >> .ci-temp/skip_ci_files
            echo -n "|LICENSE|LICENSE.apache20|README.md|release.sh" >> .ci-temp/skip_ci_files
            echo -n "|RIGHTS.antlr|shippable.yml|codeship" >> .ci-temp/skip_ci_files
            echo -n "|shippable.sh|wercker.yml|wercker.sh" >> .ci-temp/skip_ci_files
            echo -n "|intellij-idea-inspections.xml" >> .ci-temp/skip_ci_files
            echo -n "|org.eclipse.jdt.core.prefs" >> .ci-temp/skip_ci_files
            echo -n "|Jenkinsfile" >> .ci-temp/skip_ci_files
            SKIP_CI=false;
            if [ $(git diff --name-only HEAD HEAD~1 \
                   | grep -vE $(cat .ci-temp/skip_ci_files) | wc -c) -gt 0 ] ; then
                SKIP_CI=false;
              else
                SKIP_CI=true;
            fi
            echo $SKIP_CI > .ci-temp/skip_ci
      - run:
          name: download all maven dependencies and groovy
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              pwd
              ls -la
              java -version
              mvn --version
              mvn -Ppitest-metrics dependency:go-offline
            else
              echo "build is skipped ..."
            fi
      - persist_to_workspace:
          root: /home/circleci/
          paths:
            - .m2
            - project
            - contribution

  pitest1:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-coding"  >> commands.txt
              echo "./.ci/pitest.sh pitest-common"  >> commands.txt
              echo "./.ci/pitest.sh pitest-imports" >> commands.txt
              echo "./.ci/pitest.sh pitest-ant"     >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest2:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-main"        >> commands.txt
              echo "./.ci/pitest.sh pitest-javadoc"     >> commands.txt
              echo "./.ci/pitest.sh pitest-indentation" >> commands.txt
              echo "./.ci/pitest.sh pitest-xpath"       >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest3:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-misc"    >> commands.txt
              echo "./.ci/pitest.sh pitest-design"  >> commands.txt
              echo "./.ci/pitest.sh pitest-api"     >> commands.txt
              echo "./.ci/pitest.sh pitest-utils"   >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest4:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-whitespace" >> commands.txt
              echo "./.ci/pitest.sh pitest-filters"    >> commands.txt
              echo "./.ci/pitest.sh pitest-header"     >> commands.txt
              echo "./.ci/pitest.sh pitest-annotation" >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest5:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-packagenamesloader" >> commands.txt
              echo "./.ci/pitest.sh pitest-tree-walker"        >> commands.txt
              echo "./.ci/pitest.sh pitest-naming"             >> commands.txt
              echo "./.ci/pitest.sh pitest-metrics"            >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest6:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-blocks"   >> commands.txt
              echo "./.ci/pitest.sh pitest-sizes"    >> commands.txt
              echo "./.ci/pitest.sh pitest-modifier" >> commands.txt
              echo "./.ci/pitest.sh pitest-regexp"   >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
  pitest7:
    machine: true
    parallelism: 4
    steps:
      - attach_workspace:
          at: /home/circleci/
      - run:
          command: |
            SKIP_CI=`cat .ci-temp/skip_ci`
            echo "SKIP_CI="$SKIP_CI
            if [[ $SKIP_CI == 'false' ]]; then
              echo "./.ci/pitest.sh pitest-gui"   >> commands.txt
              CMD="$(circleci tests split commands.txt)"
              echo "Command: $CMD"
              eval $CMD
            else
              echo "build is skipped ..."
            fi
workflows:
  version: 2
  pitest-testing:
    jobs:
      - build-caches
      - pitest1:
          requires:
            - build-caches
      - pitest2:
          requires:
            - build-caches
      - pitest3:
          requires:
            - build-caches
      - pitest4:
          requires:
            - build-caches
      - pitest5:
          requires:
            - build-caches
      - pitest6:
          requires:
            - build-caches
      # we do not do thorough testing of gui part
      # - pitest7:
      #     requires:
      #       - build-caches
--------------------------------------------------------------------------------------------------------
language: java

matrix:
    include:
        - os: linux
          sudo: false
          jdk: oraclejdk8
          before_install:
            # codecov.io
            - pip install --user codecov
          script: >
            if [ "${COVERITY_SCAN_BRANCH}" != 1 ]; then
            ./gradlew build jacocoTestReport javadoc versionEyeSecurityAndLicenseCheck artifactoryPublish codacyUpload
            -PbuildInfo.build.number=$TRAVIS_BUILD_NUMBER
            -PbuildInfo.buildUrl=https://travis-ci.org/${TRAVIS_REPO_SLUG}/builds/${TRAVIS_JOB_ID}
            -PbuildInfo.principal=$USER
            --continue --stacktrace --no-daemon --profile --scan ;
            fi
          after_success:
            - ./publish-docs-to-github.sh
            # codecov.io
            - if [ "${COVERITY_SCAN_BRANCH}" != 1 ]; then codecov ; fi
            - cat ./cov-int/build-log*.txt
          addons:
            coverity_scan:
              project:
                name: ddimtirov/nuggets
                version: 0.3.0-SNAPSHOT
                description: nuggets is (yet another) utility library for Java Edit
              notification_email: dimitar.dimitrov@gmail.com
              build_command_prepend: rm -rf ./build
              build_command: ./gradlew --no-daemon --info jar
              branch_pattern: coverity_scan
        - os: osx
          osx_image: xcode8.2
          script: ./gradlew build javadoc --continue --stacktrace --no-daemon --profile --scan
        - os: linux
          sudo: required
          jdk: oraclejdk9
          dist: trusty
          script:
             - export GRADLE_OPTS=--add-opens java.base/java.lang=ALL-UNNAMED
             - ./gradlew build javadoc --continue --stacktrace --no-daemon --profile --scan
    allow_failures:
        - jdk: oraclejdk9


env:
  global:
    # GH_TOKEN for ddimtirov/nuggets
    - secure: u0YEKxdx3cEbtJAZU9xeh7X+8ix3MZNirUor+i/u5WPflXmqAe32BO7Oh92lfM46h7b2e/AVSeA4UQUsRcz2HMWDLy3jVjIxpS4bIc4Lfpf06UH9ZSxmN3qfAVp6W8sN/YII0h9WfAaNLX5VxY91LmloTdtvS3zgRFoaBL+W0nVicu/O4yPBn8o5DGyf8q83gmx2jNI3RTMyvMrliQbS+jtzgCPDrW/KqKPHmiaEl7yuXShZnRlxrjDa65fkDPnCRbexklmbnaF2ssjVB3sKofvmzFQKIp+44Jvgpm93eXqFYOfcrma8+8J2g9u/WL9uOIy7lE7bCf098QmoOthyvL3lUGgRPIbuiPygrFPEUpb74zyLZB6BpIXG8VjTlqZtoVddQNyglU5Kiyh/2ZNK1nQPssxo/y868gl2QWn9ZB0N9EU2MLJf1kVsJMHVEeDMyKzoHQW1fjeLvPJkDBFJtOuLltB0kfWkOzGcdJHtznNWGZoLAEa6Yr8A0OZAEqrxG81sttDL/dYQJDhJdGn1U/Q6adk2MTa6HXjJgQbuACDw8TpmFp8Lv13d907ZmJFojjzUJS9TxTKIXQKzCZoCGFhWxajZdDI9jOq3Ypt4rZ/zXea9YlIDx4Op3immdbcW8mNiS2bJg1kw53a2CiCHYS7rKHyMKAXY/SkR6D81jZI=
    # VERSIONEYE_API_KEY
    - secure: seO01Lxrkxn09Mbf/4Io6VMpwGFhpaRVZfCL25/xEqiKhDgQLaKzI/SLVT3Kv4D30KABngWPLcPiAGOxleSjKMEPdOA5XO2yQanO54Q4yXinbJO9WBZn6ok7OvWNLZIS1vR1SJhP51pHEde+dcYvHd+Om1Uio4yMIZrhv2XJjUHZvkyi+ZGc8XErElLrIc5UWC/2bRnddZKdP/sE8Euqc4MvES8G1DjoWLbgAPy3+Jj7XMBTDxqpGEDdafgxzWC1GpiwKhefqvqSPeHO1CH5rXVzS4IXALugYgCoO7G0YVeEw1YLmhMqLnjpkXrUKDeEuuL0uJvYdpDDqCVynPvW3aDH7nTznXb3OoaIQjoQfN9OaS/DNAZ4DmuBt8orDYYZZ9O5Z/5M50QPBks46UucSNcUfoet/p1PrqQWwxtIPgjcWnnz7vWMT7g9IntuAwXwUrtzvhAgd0aF+/5Ivptq8Aq2tOfuULH0Wbk+htiW2/FTQ7g7UED9iPCas0JVDPNT2B09Gx1wWKpt8XIC4k6U8iTCcMGphI/2lyiDA21do9AuRGGrm72fGHGPQyUG0VGTudF9xvV06ChmvGQxcGRNZ09AlhLEPaQdlLZlKhZM7ufBz6y9qg83y1zIzS/+KYOFhmYxuj5OyKmNlvoFJKrh6ACcgg+3rA8r+NYMnbklNu0=
    # BINTRAY_USER & BINTRAY_KEY
    - secure: HF19auHUTRaUgbPykpnsloFCreDFQ8Cr09kZaEZKgXuQnQU9AWNlvCzh3bBBIhnbCMaa2EB0BOWWpmtZ/cbs1qWuCejri0wgLcGIJfW+I9OisY/cMxac7qR/8oXY9Ng702QSyxWHzMCa24KiQdvLSfPgcdcJs4468YGk0w8j5IpclOBoc2pphEv6M7GlEyu8b6iWo9e+1W5LV8TuF8Twe0MNfPrJpU3pSb8/Df6YKnF7h+Fm++LHuKAw+m1IvuSxla2klcySjXzC2HdlaIXcfRgHCFA96y5gqSSn704kRDIF2TVARVbJH0MvkjHQTuusZemyV8kZ7NCDSG9eS6FxgwteAV9hQa4gTHOBrTO2LP/KVLJgUgGKfyZIKCpr5FCRReYnOtkkxwW6X1tgXcNO03VtOkmyVcMfAp6CZ1KTOWs1nefRIqZnfEr7V9amI8xBojt8wVnTdhDtFlDG69za2OH1yoNxY6O5bmaNCZ0sMXW/KjrePZWh9pfPSeBaH8d5Q9rxxUd+m0h6TMuJ7uOAiU2tjfvlkS2U8KdWUKzzF8h8Bn/ukBnlsVEA1/wFOZiWsQOwDxfsC9VVn49cjejVn8uoPokvsse5lHxnPEktrWfUuVSBF3VNsH+EGT8su5tyN4KARQ61O/jaWPtW4swrU1QGmd/3h7PGJuya1tnO30c=
    - secure: TuOf/FL4ISdG6FRMHVxA9UPxHDqJGvZRKu13H/8z1gxLGFGFNUsWlr1LekjUfBxGjjTKa9xpTBR1af3CRyotd5Yn6gspQnqr9vVrfPdboRwu1xLYtVD8amrPEBM7BKZ8HxxVR5RRaxkMMHeOPKYIF05P9V381pjRPgOBUolEVUyBfmSipzVX+eid6hdn2ePWZYL2FM+Ge23aIPkvwedafmiRItWX42cqYeLou3fsYXFukGVFGRvjj7PaM9mSLcu4hHru5WvxrELb/DxGdxphPNhHCkK4bWaN3H8HTpf6rKNpqplMYxClfN+n8Ciw68BFSS7eH/ns7H0pr/vYNQ/xjvteCDaoy9XJfdyTYH3BcrECll278W2r07X6kdkLQLqIqNsrUEC1ck75sRCVxwzQpZJ4FJZcfR5rw4CxdouHJXxWvCACkJ6tX48mtVX8JDUNkMPywgmdrAMjr7FYcKqf3RQtp1LPW/GYQmZbyLpOGhNOv6CTCH6D8Y/T+EeWmCvUvEWqLjBBdu6uEnuboYs/wCQWueqaKfZohb94KQ7c4UUG0yHxDgdWUC7bukA6txnE/xonWOVv7xbG2mRsG4Jt6ynwnBhfEhjG1LH5xhkkHpqdEfRwZNy/O2npbCaanBhvKIk85b0J8vp6uRNHMXZsy1ouLX5iknxi7wSmranO2wg=
    # Codacy
    - secure: od/L5mnmQZ0DDbcleQbq8ZiRxPvc3AsCW+6IiMlIt7dMd4Hg4OkNQ2mIXOKYZRF1IwYG2e1rW7TcNyOZiAP7S0ih7XzlzSpW7U3P//j3u1MVLWbWLcI9bhNNiJaO54nydytUFKI5N4H3sR2BRnuIx2MI4WsZFsyxs2x2RIOz6uPvnCMkrq4GKYHkgFAbW0g0zo5Bmgs6fIFGLo5N6l4HJemGVCRVdGM6VApFzagPMbjQCuC+TyV8Agi6X3jq932qeHz69kVNT28TN5xTUA8i2X1EpI7vXudJ3v60ZJZxyBs4G5pE0A/faPMhvpDzxsVYPDR5IfMQMjjhYrjUf14/r3Ubj2uEAM82NjnkAz9Mn+N++HJ1/1HqvnyURmpeEnydrAWl8wIIgPIKHJybg5lJvcgUjvPctrySZagRrgvwRMZZng8C7WsWtbTbdNwjCU4bfuesine0shN2encXMcXL1eD1A81FoJSQshcpghYpBU/SNr0wsnApHHSDrm0AnJx7952YvBbK0J4NruXp1IVvmAgu1tRDkj8mlIutr4QRrEFU080JzaVhpAEkD17aR8ifuMTRfpR47Uzb6hwB0wp8NBU2Dto5bm9dXwLBJA/6WDyF6HiId+mWEJLg4boHXfSddQniyqK2P/jaHGuH4EawmoT01b+wmV62Yp1gbQiUJ9E=
    # COVERITY_SCAN_TOKEN
    - secure: MOCopiLQt8tiR3S7iJyLxj5eg7Akcs9pVBH81dpyeUzTErzq3NNP8lpZ9xZsR7epAE3PcxauoSIgEXPbe57rijH15mm8Cy5UXBbg+q5htjElwrZsaFfySBDi4WSCDm4jYcDF26JH9Cj3JAnlVMpgIthyxRfjnaCROFYIc42blsw+5FehcE0Wuj1PVYOFhgxOY5qLBfwcG+A+3Yr4jkiQ3S8SHC2tn2hv/Dpwq/jizRsQc0lLIoQRujBDrGiBN5dREcL6A0QTFIZolHQC/lhRc5nTDP2zxeUiGnOZ1njFzX8qniZVtqUx1KGnBdv1Rm72nlf8/JvedJP24TPVaGV8Xgorz6tL49vwjjJ0l64CZgU5TqiJ7ugwU2HcczLZN0vVRVDadN0letGJBfT+f/YQMSXFtQcE3gc3eORzy9V0WXY9RFXfQU8d708okLCP0UK7zxQyUUBV6Np04STSYTyeUJa4Mm6XOqEz8cNuM8lx9i5vFRaVrZ75FxHcU7kT0QaFcoQSR/tsE0MJ0kAvGRIwRNPKnAShD0eiNP2bqeV2lo96FIC4FwPlEtBi14i7wneyZ+pEyKSxc29nW17X0PRhzlgLdPxbKlvXblKKY7jJa6Fwl/mzPCpUiRX1BWLP4TrXxMDms2ptlqfO1vtclYcCnDsr/Fs1qkNUSl0tRq1s3qs=

# see https://docs.travis-ci.com/user/languages/java/#Projects-Using-Gradle
before_cache:
  - rm -f  $HOME/.gradle/caches/modules-2/modules-2.lock
  - rm -fr $HOME/.gradle/caches/*/plugin-resolution/
  - rm -f  $HOME/.cache/pip/log/debug.log

cache:
  directories:
    - $HOME/.gradle/caches/
    - $HOME/.gradle/wrapper/
    - $HOME/.cache/pip
--------------------------------------------------------------------------------------------------------
@Configuration
public class AppConfig {
    @Autowired
    DataSourceProperties dataSourceProperties;

    @Bean
    @ConfigurationProperties(prefix = DataSourceProperties.PREFIX)
    DataSource realDataSource() {
        DataSource dataSource = DataSourceBuilder
                .create(this.dataSourceProperties.getClassLoader())
                .url(this.dataSourceProperties.getUrl())
                .username(this.dataSourceProperties.getUsername())
                .password(this.dataSourceProperties.getPassword())
                .build();
        return dataSource;
    }

    @Bean
    @Primary
    DataSource dataSource() {
        return new DataSourceSpy(realDataSource());
    }
}
--------------------------------------------------------------------------------------------------------
//    @Option(names = {"-h", "--help"}, help = true, description = "Shows help message and exits")
//    private boolean helpRequested;

init-test-suite run --single-test --config=config --log
--------------------------------------------------------------------------------------------------------
           <!--<exclusions>-->
                <!--<exclusion>-->
                    <!--<groupId>org.springframework.boot</groupId>-->
                    <!--<artifactId>spring-boot-starter-data-redis</artifactId>-->
                <!--</exclusion>-->
                <!--<exclusion>-->
                    <!--<groupId>org.springframework.data</groupId>-->
                    <!--<artifactId>spring-data-redis</artifactId>-->
                <!--</exclusion>-->
                <!--<exclusion>-->
                    <!--<groupId>org.springframework.boot</groupId>-->
                    <!--<artifactId>spring-boot-starter-data-jpa</artifactId>-->
                <!--</exclusion>-->
            <!--</exclusions>-->
--------------------------------------------------------------------------------------------------------
    public static <T> @Nullable T defaultValue(@NotNull Class<T> c) {
        try {
            Constructor<?> constructor = c.getConstructor();
            if (constructor !=null) return c.cast(constructor.newInstance());
        } catch (Exception ignored) { }

        if (c.isPrimitive()) {
            @SuppressWarnings("unchecked")
            Class<T> boxedEquivalent = (Class<T>) boxClass(c);
            c = boxedEquivalent;
        }

        if (c.isArray())                            return c.cast(Array.newInstance(c.getComponentType(), 0));
        if (BigDecimal.class.isAssignableFrom(c))   return c.cast(BigDecimal.ZERO);
        if (BigInteger.class.isAssignableFrom(c))   return c.cast(BigInteger.ZERO);
        if (Boolean.class.equals(c))                return c.cast(Boolean.FALSE);
        if (Byte.class.equals(c))                   return c.cast((byte) 0);
        if (Character.class.equals(c))              return c.cast('\0');
        if (Double.class.equals(c))                 return c.cast(0d);
        if (Float.class.equals(c))                  return c.cast(0f);
        if (Integer.class.equals(c))                return c.cast(0);
        if (Long.class.equals(c))                   return c.cast(0L);
        if (Short.class.equals(c))                  return c.cast((short) 0);

        if (Map.class.isAssignableFrom(c))          return c.cast(new LinkedHashMap<>());
        if (Set.class.isAssignableFrom(c))          return c.cast(new LinkedHashSet<>());
        if (List.class.isAssignableFrom(c))         return c.cast(new ArrayList<>());
        if (Collection.class.isAssignableFrom(c))   return c.cast(new ArrayList<>());

        return null; // void, classes without default constructor, etc.
    }
--------------------------------------------------------------------------------------------------------
   @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
        return args -> {
            System.out.println("Let's inspect the beans provided by Spring Boot:");
            String[] beanNames = ctx.getBeanDefinitionNames();
            Arrays.sort(beanNames);
            for (String beanName : beanNames) {
                System.out.println(beanName);
            }
        };
    }
--------------------------------------------------------------------------------------------------------
import com.justynsoft.simplerecon.core.worker.CSVFileReconWorker;
import com.justynsoft.simplerecon.core.worker.DatabaseReconWorker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration
public class TradeConfig {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Bean
    public DatabaseReconWorker TradeAllocationDatabaseReconWorker(){
        DatabaseReconWorker databaseWorker = new DatabaseReconWorker();
        databaseWorker.setSQL("SELECT * FROM allocation");
        databaseWorker.setJdbcTemplate(this.jdbcTemplate);
        databaseWorker.setClazz(TradeAllocation.class);
        return databaseWorker;
    }

    @Bean
    public CSVFileReconWorker TradeAllocationCSVReconWorker(){
        CSVFileReconWorker csvFileReconWorker = new CSVFileReconWorker();
        csvFileReconWorker.setClazz(TradeAllocation.class);
        csvFileReconWorker.setFileName("/com/justynsoft/simplerecon/traderecon/data.csv");
        return csvFileReconWorker;
    }
}
--------------------------------------------------------------------------------------------------------
   @Bean
    public JdbcTemplate getJdbcTemplate(){
        return new JdbcTemplate(dataSource);
    }
--------------------------------------------------------------------------------------------------------
// Comment to get more information during initialization
logLevel := Level.Warn

// The Typesafe repository
resolvers += "Typesafe repository" at "http://repo.typesafe.com/typesafe/releases/"

// Use the Play sbt plugin for Play projects
addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.2.3")
--------------------------------------------------------------------------------------------------------
<resources>
    <!--
    TODO: Before you run your application, you need a Google Maps API key.
    To get one, follow this link, follow the directions and press "Create" at the end:
    https://console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=B6:CA:08:B3:82:8C:4D:7D:81:2F:E4:E6:99:5E:7B:04:E2:BA:F2:8A%3Bbreathe.inventerous.com.breathe
    You can also add your credentials to an existing key, using these values:
    Package name:
    B6:CA:08:B3:82:8C:4D:7D:81:2F:E4:E6:99:5E:7B:04:E2:BA:F2:8A
    SHA-1 certificate fingerprint:
    B6:CA:08:B3:82:8C:4D:7D:81:2F:E4:E6:99:5E:7B:04:E2:BA:F2:8A
    Alternatively, follow the directions here:
    https://developers.google.com/maps/documentation/android/start#get-key
    Once you have your key (it starts with "AIza"), replace the "google_maps_key"
    string in this file.
    -->
    <string name="google_maps_key" templateMergeStrategy="preserve" translatable="false">AIzaSyABDlQcs7xlKmsvbp_XIktPtGQVSWl8wAw</string>
</resources>
--------------------------------------------------------------------------------------------------------
import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("breathe.inventerous.com.breathe", appContext.getPackageName());
    }
}
--------------------------------------------------------------------------------------------------------
spring.datasource.initialization-mode=always
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.Database;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

@SpringBootApplication//(exclude = { SecurityAutoConfiguration.class })
@EnableJpaRepositories(basePackages = {"com.exercise.dao", "com.exercise.conf"} )
public class Application {

    public static void main(String... args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
    }

    @Bean
    public JpaVendorAdapter jpaVendorAdapter() {
        HibernateJpaVendorAdapter bean = new HibernateJpaVendorAdapter();
        bean.setDatabase(Database.H2);
        bean.setGenerateDdl(true);
        bean.setShowSql(true);
        return bean;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource,
                                                                       JpaVendorAdapter jpaVendorAdapter) {
        LocalContainerEntityManagerFactoryBean bean = new LocalContainerEntityManagerFactoryBean();
        bean.setDataSource(dataSource);
        bean.setJpaVendorAdapter(jpaVendorAdapter);
        bean.setPackagesToScan("com.exercise.domain");
        return bean;

    }

    @Bean
    public JpaTransactionManager transactionManager(EntityManagerFactory emf) {
        return new JpaTransactionManager(emf);
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
--------------------------------------------------------------------------------------------------------
//import javax.sql.DataSource;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
//
//@Configuration
//public class PersistenceConfig {
//
//    @Bean
//    public DataSource dataSource() {
//        EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
//        EmbeddedDatabase db = builder.setType(EmbeddedDatabaseType.H2).addScript("mySchema.sql").addScript("myData.sql").build();
//        return db;
//    }
//
//}
--------------------------------------------------------------------------------------------------------
//	@Override
//	public void addCorsMappings(CorsRegistry registry) {
//		registry.addMapping("/**").maxAge(3600).allowedHeaders("Content-type", "Authorization").allowedMethods("*")
//				.allowCredentials(true).allowedOrigins(origin);
//	}

//    @Override
//    protected void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
//        argumentResolvers.add(
//            new ServletWebArgumentResolverAdapter(new PageableArgumentResolver()));
//    }
--------------------------------------------------------------------------------------------------------
	static {
		// Eagerly load the NestedExceptionUtils class to avoid classloader deadlock
		// issues on OSGi when calling getMessage(). Reported by Don Brown; SPR-5607.
		NestedExceptionUtils.class.getName();
	}
--------------------------------------------------------------------------------------------------------
  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
--------------------------------------------------------------------------------------------------------
@Bean(name = “userCacheManager”)
public RedisCacheManager userCacheManager(RedisConnectionFactory connectionFactory, UserService userService) {
RedisCacheConfiguration redisCacheConfiguration = RedisCacheConfiguration.defaultCacheConfig();
DefaultFormattingConversionService conversionService = (DefaultFormattingConversionService) redisCacheConfiguration.getConversionService();
conversionService.addConverter(UserCacheKey.class, String.class, new UserCacheKeyConverter(userService));
redisCacheConfiguration
.entryTtl(Duration.ofSeconds(1800)).withConversionService(conversionService)
.disableCachingNullValues();
return RedisCacheManager.builder(connectionFactory)
.cacheDefaults(redisCacheConfiguration)
.withInitialCacheConfigurations(Collections.singletonMap(“user-cache”, redisCacheConfiguration))
.build();
}
--------------------------------------------------------------------------------------------------------
@WritingConverter
public class AddressToMapConverter implements Converter<Address, Map<String,byte[]>> {

  @Override
  public Map<String,byte[]> convert(Address source) {
    return singletonMap("ciudad", source.getCity().getBytes());
  }
}

@ReadingConverter
public class MapToAddressConverter implements Converter<Address, Map<String, byte[]>> {

  @Override
  public Address convert(Map<String,byte[]> source) {
    return new Address(new String(source.get("ciudad")));
  }
}
--------------------------------------------------------------------------------------------------------
/*
@RunWith(SpringRunner.class)
@SpringBootTestConfiguration(
        activeClasses = {
                FileToUploadRequestConverter.class
        })
@EnableAutoConfiguration(
        exclude = {
                TaskExecutionAutoConfiguration.class,
                IntegrationAutoConfiguration.class,
                KafkaAutoConfiguration.class,
                MetricsAutoConfiguration.class,
                WebMvcMetricsAutoConfiguration.class,
                RestTemplateAutoConfiguration.class
        }
)
public class FileToUploadRequestConverterTest extends AbstractBaseTest {
    private static final String FILE_TYPE = "pdf";
    private static final String FILE_NAME = "test";
    private static final long FILE_SIZE = 20L;

    @Autowired
    private ConversionService conversionService;

    @Test
    public void test_valid_File_to_UploadFileRequest_ByConverter() {
        // given
        final File file = this.getFile(new byte[]{0, 1, 3}, FILE_NAME, FILE_SIZE, FILE_TYPE);

        // when
        final UploadFileRequest request = this.conversionService.convert(file, UploadFileRequest.class);

        // then
        assertThat(request, is(not(nullValue())));
        assertThat(request.getContent(), equalTo(file.getContent()));
        assertThat(request.getMediaType(), equalTo(file.getType()));
        assertThat(request.getName(), equalTo(file.getDispositionName()));
        assertThat(request.getSize(), equalTo(file.getSize()));
        assertThat(request.getLastModified(), equalTo(0L));
    }

    @Test
    public void test_invalid_File_to_UploadFileRequest_ByConverter() {
        // given
        final File file = this.getFile(null, EMPTY, 0L, FILE_TYPE);

        // when
        final UploadFileRequest request = this.conversionService.convert(file, UploadFileRequest.class);

        // then
        assertThat(request, is(not(nullValue())));
        assertThat(request.getContent(), equalTo(file.getContent()));
        assertThat(request.getMediaType(), equalTo(file.getType()));
        assertThat(request.getName(), equalTo(file.getDispositionName()));
        assertThat(request.getSize(), equalTo(file.getSize()));
        assertThat(request.getLastModified(), equalTo(0L));
    }
}
 */
--------------------------------------------------------------------------------------------------------
http://localhost:8089/api/v0/distributor/download/c108cda3-8b4b-483d-a987-d65e6bfe3024/lombok.config

    @Autowired
    private SessionService sessionService;

    @GetMapping("/created")
    public ResponseEntity init() {
        final Session session = new Session();
        session.setId("c108cda3-8b4b-483d-a987-d65e6bfe3024");
        session.setFilepath("C:\\git-project\\paragon.microservices.distributor");
        session.setFilename("lombok.config");
        session.setDownloadStatus(DownloadStatus.NEW);
        this.sessionService.save(session);

        final Session session2 = new Session();
        session2.setId("c108cda3-8b4b-483d-a987-d65e6bfe3025");
        session2.setFilepath("C:\\git-project\\paragon.microservices.distributor");
        session2.setFilename("lombok.config2");
        session2.setDownloadStatus(DownloadStatus.NEW);
        this.sessionService.save(session2);
        return ResponseEntity.ok().build();
    }
--------------------------------------------------------------------------------------------------------
    @Bean
    public MappingRedisConverter redisConverter(final RedisMappingContext mappingContext,
                                                final List<RedisConverter> customConversions,
                                                final ReferenceResolver referenceResolver
    ) {
        final MappingRedisConverter mappingRedisConverter = new MappingRedisConverter(mappingContext, null, referenceResolver);
        mappingRedisConverter.setCustomConversions(new RedisCustomConversions(customConversions));
        return mappingRedisConverter;
    }
--------------------------------------------------------------------------------------------------------
    @Bean
    public MappingRedisConverter redisConverter(final RedisMappingContext mappingContext, final RedisCustomConversions customConversions, final ReferenceResolver referenceResolver) {
        final MappingRedisConverter mappingRedisConverter = new MappingRedisConverter(mappingContext, null, referenceResolver, customTypeMapper());
        mappingRedisConverter.setCustomConversions(customConversions);
        mappingRedisConverter.afterPropertiesSet();
        return mappingRedisConverter;
    }

    @Bean
    public RedisTypeMapper customTypeMapper() {
        return new DefaultRedisTypeMapper("data");
    }
--------------------------------------------------------------------------------------------------------
@Configuration
class SampleRedisConfiguration {

  @Bean
  public MappingRedisConverter redisConverter(RedisMappingContext mappingContext,
        RedisCustomConversions customConversions, ReferenceResolver referenceResolver) {

    MappingRedisConverter mappingRedisConverter = new MappingRedisConverter(mappingContext, null, referenceResolver,
            customTypeMapper());

    mappingRedisConverter.setCustomConversions(customConversions);

    return mappingRedisConverter;
  }

  @Bean
  public RedisTypeMapper customTypeMapper() {
    return new CustomRedisTypeMapper();
  }
}
--------------------------------------------------------------------------------------------------------
@WritingConverter
public class AddressToBytesConverter implements Converter<Address, byte[]> {

  private final Jackson2JsonRedisSerializer<Address> serializer;

  public AddressToBytesConverter() {

    serializer = new Jackson2JsonRedisSerializer<Address>(Address.class);
    serializer.setObjectMapper(new ObjectMapper());
  }

  @Override
  public byte[] convert(Address value) {
    return serializer.serialize(value);
  }
}

@ReadingConverter
public class BytesToAddressConverter implements Converter<byte[], Address> {

  private final Jackson2JsonRedisSerializer<Address> serializer;

  public BytesToAddressConverter() {

    serializer = new Jackson2JsonRedisSerializer<Address>(Address.class);
    serializer.setObjectMapper(new ObjectMapper());
  }

  @Override
  public Address convert(byte[] value) {
    return serializer.deserialize(value);
  }
}
--------------------------------------------------------------------------------------------------------
//package de.pearl.pem.common.system;
//
//public class SpringSprungConfig extends DelegatingWebMvcConfiguration {
//
//    // Delegate resource requests to default servlet
//    @Bean
//    protected DefaultServletHttpRequestHandler defaultServletHttpRequestHandler() {
//        DefaultServletHttpRequestHandler dsrh = new DefaultServletHttpRequestHandler();
//        return dsrh;
//    }
//
//    //map static resources by extension
//    @Bean
//    public SimpleUrlHandlerMapping resourceServletMapping() {
//        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
//
//        //make sure static resources are mapped first since we are using
//        //a slightly different approach
//        mapping.setOrder(0);
//        Properties urlProperties = new Properties();
//        urlProperties.put("/**/*.css", "defaultServletHttpRequestHandler");
//        urlProperties.put("/**/*.js", "defaultServletHttpRequestHandler");
//        urlProperties.put("/**/*.png", "defaultServletHttpRequestHandler");
//        urlProperties.put("/**/*.html", "defaultServletHttpRequestHandler");
//        urlProperties.put("/**/*.woff", "defaultServletHttpRequestHandler");
//        urlProperties.put("/**/*.ico", "defaultServletHttpRequestHandler");
//        mapping.setMappings(urlProperties);
//        return mapping;
//    }
//
//    @Override
//    @Bean
//    public RequestMappingHandlerMapping requestMappingHandlerMapping() {
//        RequestMappingHandlerMapping handlerMapping = super.requestMappingHandlerMapping();
//
//        //controller mappings must be evaluated after the static resource requests
//        handlerMapping.setOrder(1);
//        handlerMapping.setInterceptors(this.getInterceptors());
//        handlerMapping.setPathMatcher(this.getPathMatchConfigurer().getPathMatcher());
//        handlerMapping.setRemoveSemicolonContent(false);
//        handlerMapping.setUseSuffixPatternMatch(false);
//        //set other options here
//        return handlerMapping;
//    }
//}


/*
    @Override
    public void addViewControllers(final ViewControllerRegistry registry) {
        registry.addRedirectViewController("/swagger", "/swagger-ui.html");
    }

    @Override
    public void configurePathMatch(final PathMatchConfigurer configurer) {
        configurer.setUseTrailingSlashMatch(true);
    }

//    @Override
//    public void addInterceptors(final InterceptorRegistry registry) {
//        registry.addInterceptor(new SwaggerInterceptor()).addPathPatterns("/swagger");
//    }
//
//    private class SwaggerInterceptor extends HandlerInterceptorAdapter {
//
//        @Override
//        public void afterCompletion(final HttpServletRequest request, final HttpServletResponse response, final Object handler, @Nullable final Exception ex) throws IOException {
//            response.sendRedirect("/swagger-ui.html");
//        }
//    }

//    @Bean
//    public Docket newsApi(final ServletContext servletContext) {
//        return new Docket(DocumentationType.SWAGGER_2)
//                .select()
//                .apis(RequestHandlerSelectors.basePackage("com.paragon.microservices.crmadapter.controller"))
//                .paths(PathSelectors.any())
//                .build()
//                .enable(true)
//                .pathProvider(new RelativePathProvider(servletContext) {
//                    @Override
//                    public String getApplicationBasePath() {
//                        return join("/swagger", super.getApplicationBasePath());
//                    }
//                }).host("newhost:8095");
//    }
 */

--------------------------------------------------------------------------------------------------------//package de.pearl.pem.common.system.property;
//
//import javax.inject.Inject;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import com.mangofactory.swagger.configuration.SpringSwaggerConfig;
//import com.mangofactory.swagger.models.dto.ApiInfo;
//import com.mangofactory.swagger.models.dto.builder.ApiInfoBuilder;
//import com.mangofactory.swagger.plugin.EnableSwagger;
//import com.mangofactory.swagger.plugin.SwaggerSpringMvcPlugin;
//
//@Configuration
//@EnableSwagger
//public class SwaggerConfiguration {
//
//    @Inject
//    private SpringSwaggerConfig springSwaggerConfig;
//
//    private ApiInfo getApiInfo() {
//
//        ApiInfo apiInfo = new ApiInfoBuilder()
//                .title("QuickPoll REST API")
//                .description("QuickPoll Api for creating and managing polls")
//                .termsOfServiceUrl("http://example.com/terms-of-service")
//                .contact("info@example.com")
//                .license("MIT License")
//                .licenseUrl("http://opensource.org/licenses/MIT")
//                .build();
//
//        return apiInfo;
//    }
//
//    @Bean
//    public SwaggerSpringMvcPlugin v1APIConfiguration() {
//        SwaggerSpringMvcPlugin swaggerSpringMvcPlugin = new SwaggerSpringMvcPlugin(this.springSwaggerConfig);
//        swaggerSpringMvcPlugin
//                .apiInfo(getApiInfo()).apiVersion("1.0")
//                .includePatterns("/v1/*.*").swaggerGroup("v1");
//        swaggerSpringMvcPlugin.useDefaultResponseMessages(false);
//        return swaggerSpringMvcPlugin;
//    }
//
//    @Bean
//    public SwaggerSpringMvcPlugin v2APIConfiguration(){
//        SwaggerSpringMvcPlugin swaggerSpringMvcPlugin = new SwaggerSpringMvcPlugin(this.springSwaggerConfig);
//        swaggerSpringMvcPlugin
//                .apiInfo(getApiInfo()).apiVersion("2.0")
//                .includePatterns("/v2/*.*").swaggerGroup("v2");
//        swaggerSpringMvcPlugin.useDefaultResponseMessages(false);
//        return swaggerSpringMvcPlugin;
//    }
//
//    @Bean
//    public SwaggerSpringMvcPlugin v3APIConfiguration(){
//        SwaggerSpringMvcPlugin swaggerSpringMvcPlugin = new SwaggerSpringMvcPlugin(this.springSwaggerConfig);
//        swaggerSpringMvcPlugin
//                .apiInfo(getApiInfo()).apiVersion("3.0")
//                .includePatterns("/v3/*.*").swaggerGroup("v3");
//        swaggerSpringMvcPlugin.useDefaultResponseMessages(false);
//        return swaggerSpringMvcPlugin;
//    }
//}
import com.kodedu.controller.ApplicationController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

import java.util.Base64;

@Configuration
@EnableWebSocket
@ComponentScan(basePackages = "com.kodedu.**")
@EnableAutoConfiguration
public class SpringAppConfig extends SpringBootServletInitializer implements WebSocketConfigurer {

    @Autowired
    private ApplicationController applicationController;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(applicationController, "/ws", "/ws**", "/ws/**").withSockJS();
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(SpringAppConfig.class);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public Base64.Encoder base64Encoder() {
        return Base64.getEncoder();
    }
}

--------------------------------------------------------------------------------------------------------
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.PropertySource;
//import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
//import org.springframework.scheduling.annotation.EnableScheduling;
//import org.springframework.scheduling.annotation.SchedulingConfigurer;
//import org.springframework.scheduling.config.ScheduledTaskRegistrar;
//
//import java.util.concurrent.Executor;
//import java.util.concurrent.Executors;
//
//import static com.sportics.principal.hor.horweb.configs.SchedulerConfig.DEFAULT_SCHEDULER_PACKAGE;
//
//@Configuration
//@EnableScheduling
//@ComponentScan(DEFAULT_SCHEDULER_PACKAGE)
//@PropertySource("classpath:cron")
//public class SchedulerConfiguration implements SchedulingConfigurer {
//
//    /**
//     * Default scheduler packages
//     */
//    public static final String DEFAULT_SCHEDULER_PACKAGE = "com.sportics.principal.hor.horweb.scheduler";
//
//    // Default scheduling pool size
//    private static final int DEFAULT_SCHEDULER_POOL_SIZE = 10;
//
//    @Bean
//    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
//        return new PropertySourcesPlaceholderConfigurer();
//    }
//
//    @Override
//    public void configureTasks(ScheduledTaskRegistrar scheduledTaskRegistrar) {
//        scheduledTaskRegistrar.setScheduler(taskExecutor());
//    }
//
//    @Bean(destroyMethod = "shutdown")
//    public Executor taskExecutor() {
//        return Executors.newScheduledThreadPool(DEFAULT_SCHEDULER_POOL_SIZE);
//    }
//}
--------------------------------------------------------------------------------------------------------
//SET DATABASE UNIQUE NAME HSQLDB4D3A66AE30
//    SET DATABASE GC 0
//    SET DATABASE DEFAULT RESULT MEMORY ROWS 0
//    SET DATABASE EVENT LOG LEVEL 0
//    SET DATABASE TRANSACTION CONTROL LOCKS
//    SET DATABASE DEFAULT ISOLATION LEVEL READ COMMITTED
//    SET DATABASE TRANSACTION ROLLBACK ON CONFLICT TRUE
//    SET DATABASE TEXT TABLE DEFAULTS ''
//    SET DATABASE SQL NAMES FALSE
//    SET DATABASE SQL REFERENCES FALSE
//    SET DATABASE SQL SIZE TRUE
//    SET DATABASE SQL TYPES FALSE
//    SET DATABASE SQL TDC DELETE TRUE
//    SET DATABASE SQL TDC UPDATE TRUE
//    SET DATABASE SQL TRANSLATE TTI TYPES TRUE
//    SET DATABASE SQL CONCAT NULLS TRUE
//    SET DATABASE SQL UNIQUE NULLS TRUE
//    SET DATABASE SQL CONVERT TRUNCATE TRUE
//    SET DATABASE SQL AVG SCALE 0
//    SET DATABASE SQL DOUBLE NAN TRUE
//    SET FILES WRITE DELAY 500 MILLIS
//    SET FILES BACKUP INCREMENT TRUE
//    SET FILES CACHE SIZE 10000
//    SET FILES CACHE ROWS 50000
//    SET FILES SCALE 32
//    SET FILES LOB SCALE 32
//    SET FILES DEFRAG 0
//    SET FILES NIO TRUE
//    SET FILES NIO SIZE 256
//    SET FILES LOG TRUE
//    SET FILES LOG SIZE 50
//    CREATE USER SA PASSWORD DIGEST 'c12e01f2a13ff5587e1e9e4aedb8242d'
//    ALTER USER SA SET LOCAL TRUE
//    CREATE SCHEMA PUBLIC AUTHORIZATION DBA
//    ALTER SEQUENCE SYSTEM_LOBS.LOB_ID RESTART WITH 1
//    SET DATABASE DEFAULT INITIAL SCHEMA PUBLIC
//    GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.SQL_IDENTIFIER TO PUBLIC
//    GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.YES_OR_NO TO PUBLIC
//    GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.TIME_STAMP TO PUBLIC
//    GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CARDINAL_NUMBER TO PUBLIC
//    GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CHARACTER_DATA TO PUBLIC
//    GRANT DBA TO SA
//    SET SCHEMA SYSTEM_LOBS
//    INSERT INTO BLOCKS VALUES(0,2147483647,0)
--------------------------------------------------------------------------------------------------------
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.env.redis.RedisPropertySource;
import org.springframework.web.context.ConfigurableWebApplicationContext;

public class XmlConfigPropertySourceInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {
    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {
        MutablePropertySources propertySources = applicationContext.getEnvironment().getPropertySources();
        propertySources.addFirst(getPropertySource());
    }

    private PropertySource getPropertySource() {
        ClassPathXmlApplicationContext propertySourceContext =
                new ClassPathXmlApplicationContext("classpath:/META-INF/spring/property-source-context.xml");

        return propertySourceContext.getBean(RedisPropertySource.class);
    }
}
--------------------------------------------------------------------------------------------------------
JacksonAutoConfiguration
--------------------------------------------------------------------------------------------------------
import java.util.TreeMap;

public class RomanNumberUtils {
    private final static TreeMap<Long, String> map = new TreeMap<Long, String>();

    static {
        map.put(1000L, "M");
        map.put(900L, "CM");
        map.put(500L, "D");
        map.put(400L, "CD");
        map.put(100L, "C");
        map.put(90L, "XC");
        map.put(50L, "L");
        map.put(40L, "XL");
        map.put(10L, "X");
        map.put(9L, "IX");
        map.put(5L, "V");
        map.put(4L, "IV");
        map.put(1L, "I");
    }

    public final static String toRoman(Long number) {
        Long l =  map.floorKey(number);
        if ( number == l ) {
            return map.get(number);
        }
        return map.get(l) + toRoman(number-l);
    }
}
--------------------------------------------------------------------------------------------------------

import com.exercise.domain.enumeration.Permission;
import com.exercise.service.ConverterService;
import com.exercise.service.utils.DecimalNumberUtils;
import com.exercise.service.utils.RomanNumberUtils;
import com.exercise.web.response.ConverterResponse;
import org.springframework.stereotype.Component;

import com.exercise.exception.NumberConvertException;

@Component
public class ConverterServiceImpl implements ConverterService {

	@Override
	public ConverterResponse hexaToBinario(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.hexaToDecimal(number);
		String result = toBinario(value);
		return new ConverterResponse(number, result, Permission.BINARIO);
	}

	@Override
	public ConverterResponse hexaToHexa(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.hexaToDecimal(number);
		String result = toHexa(value);
		return new ConverterResponse(number, result, Permission.HEXADECIMAL);
	}

	@Override
	public ConverterResponse hexaToRomano(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.hexaToDecimal(number);
		String result = toRomano(value);
		return new ConverterResponse(number, result, Permission.ROMANO);
	}

	@Override
	public ConverterResponse hexaToDecimal(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.hexaToDecimal(number);
		String result = toDecimal(value);
		return new ConverterResponse(number, result, Permission.DECIMAL);
	}

	@Override
	public ConverterResponse binarioToBinario(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.binaryToDecimal(number);
		String result = toBinario(value);
		return new ConverterResponse(number, result, Permission.BINARIO);
	}

	@Override
	public ConverterResponse binarioToHexa(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.binaryToDecimal(number);
		String result = toHexa(value);
		return new ConverterResponse(number, result, Permission.HEXADECIMAL);
	}

	@Override
	public ConverterResponse binarioToRomano(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.binaryToDecimal(number);
		String result = toRomano(value);
		return new ConverterResponse(number, result, Permission.ROMANO);
	}

	@Override
	public ConverterResponse binarioToDecimal(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.binaryToDecimal(number);
		String result = toDecimal(value);
		return new ConverterResponse(number, result, Permission.DECIMAL);
	}

	@Override
	public ConverterResponse decimalToBinario(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.stringToDecimal(number);
		String result = toBinario(value);
		return new ConverterResponse(number, result, Permission.BINARIO);
	}

	@Override
	public ConverterResponse decimalToHexa(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.stringToDecimal(number);
		String result = toHexa(value);
		return new ConverterResponse(number, result, Permission.HEXADECIMAL);
	}

	@Override
	public ConverterResponse decimalToRomano(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.stringToDecimal(number);
		String result = toRomano(value);
		return new ConverterResponse(number, result, Permission.ROMANO);
	}

	@Override
	public ConverterResponse decimalToDecimal(String number) throws NumberConvertException {
		Long value = DecimalNumberUtils.stringToDecimal(number);
		String result = toDecimal(value);
		return new ConverterResponse(number, result, Permission.DECIMAL);
	}

	private String toBinario(Long value) throws NumberConvertException {
		if (value != null) {
			return Long.toBinaryString(value);
		}

		throw new NumberConvertException("cant convert");
	}

	private String toHexa(Long value) throws NumberConvertException {
		if (value != null) {
			return Long.toHexString(value).toUpperCase();
		}

		throw new NumberConvertException("cant convert");
	}

	private String toRomano(Long value) throws NumberConvertException {
		if (value != null) {
			return RomanNumberUtils.toRoman(value);
		}

		throw new NumberConvertException("cant convert");
	}

	private String toDecimal(Long value) throws NumberConvertException {
		if (value != null) {
			return String.valueOf(value);
		}

		throw new NumberConvertException("cant convert");
	}
}
--------------------------------------------------------------------------------------------------------
import com.exercise.security.user.DummyUser;
import com.exercise.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authManager;
    private UserService userService;

    /**
     * Listen for auth path on url
     * @param authManager
     */
    public AuthenticationFilter(AuthenticationManager authManager,
                                UserService userService) {
        this.authManager = authManager;
        this.userService = userService;
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return true;
    }

    /**
     *  Get credentials from request
     *  Create auth object (contains credentials) which will be used by auth manager
     *  Authentication manager authenticate the user, and use UserDetialsServiceImpl::loadUserByUsername() method to load the user
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        DummyUser creds = readBasicAuthorization(request);
        String username = creds.getUsername();
        String password = creds.getPassword();
        Authentication authToken = new UsernamePasswordAuthenticationToken(username, password, Collections.EMPTY_LIST);
        try {
            return authManager.authenticate(authToken);
        } catch (AuthenticationException ex) {
            throw ex;
        }
    }

    /**
     * Generate token if success auth
     * @param request
     * @param response
     * @param chain
     * @param auth
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication auth)
            throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(auth);
        chain.doFilter(request, response);
    }

    private DummyUser readBasicAuthorization(HttpServletRequest request) {
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        DummyUser creds = new DummyUser();

        if (authorization != null && authorization.toLowerCase().startsWith("basic")) {
            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring("Basic".length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded, StandardCharsets.UTF_8);
            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            if (values.length > 1) {
                creds.setUsername(values[0]);
                creds.setPassword(values[1]);
            }
        }

        return creds;
    }
}
--------------------------------------------------------------------------------------------------------
@Test(expected = UnsupportedOperationException.class)
public void encodableMimeTypesIsImmutable() {
  MimeType textJavascript = new MimeType("text", "javascript", StandardCharsets.UTF_8);
  Jackson2JsonEncoder encoder = new Jackson2JsonEncoder(new ObjectMapper(), textJavascript);
  encoder.getMimeTypes().add(new MimeType("text", "ecmascript"));
}
--------------------------------------------------------------------------------------------------------
import com.exercise.exception.NumberConvertException;

import javax.persistence.Entity;
import java.util.Arrays;

/**
 * The Permission enumeration.
 */
public enum Permission {
    BINARIO("BINARIO"),
    HEXADECIMAL("HEXADECIMAL"),
    DECIMAL("DECIMAL"),
    ROMANO("ROMANO"),
    MASTER("MASTER");

    private String code;

    Permission(String code) {
        this.code = code;
    }

    @Override
    public String toString() {
        return name().toUpperCase();
    }

    public static Permission byCode(String code) throws NumberConvertException {
        return Arrays.stream(Permission.values())
                .filter(e -> e.code.equalsIgnoreCase(code))
                .findFirst()
                .orElseThrow(() -> new NumberConvertException(String.format("Unsupported type %s.", code)));
    }
}
--------------------------------------------------------------------------------------------------------
User-agent: *
Allow: /*.js
Allow: /*.css
Disallow: /bitrix/
Disallow: /bitrix/tools/
Disallow: /_exploits/
Disallow: /_download/
Disallow: /blog/search.php
Disallow: /bitrix/exturl.php
Disallow: /begun/
Disallow: /admin/
Disallow: /software/download/
Disallow: /tools/_services/download/
Disallow: /bitrix/tools/
Disallow: /search/
Disallow: /forum/view_profile.php
Disallow: /forum/search/
Disallow: /forum/topic/new/
Disallow: /forum/topic/add/
Disallow: /forum/subscr_list.php
Disallow: /forum/send_message.php 
Disallow: /forum/search.php
Disallow: /forum/search/
Disallow: /forum/new_topic.php 
Disallow: /forum/move.php
Disallow: /forum/active.php
Disallow: /forum/forum_auth.php
Disallow: /forum/forum_posts.asp
Disallow: /blog/video/
Disallow: /blog/company/search.php
Disallow: /blog/personal/search.php
Disallow: /bitrix/tools

User-agent: yandex
Disallow: /bitrix/
Disallow: /bitrix/tools/
Disallow: /_exploits/
Disallow: /_download/
Disallow: /blog/search.php
Disallow: /bitrix/exturl.php
Disallow: /begun/
Disallow: /admin/
Disallow: /software/download/
Disallow: /tools/_services/download/
Disallow: /bitrix/tools/
Disallow: /search/
Disallow: /forum/view_profile.php
Disallow: /forum/search/
Disallow: /forum/topic/new/
Disallow: /forum/topic/add/
Disallow: /forum/subscr_list.php
Disallow: /forum/send_message.php 
Disallow: /forum/search.php
Disallow: /forum/search/
Disallow: /forum/new_topic.php 
Disallow: /forum/move.php
Disallow: /forum/active.php
Disallow: /forum/forum_auth.php
Disallow: /forum/forum_posts.asp
Disallow: /blog/video/
Disallow: /blog/company/search.php
Disallow: /blog/personal/search.php
Disallow: /bitrix/tools
Clean-param: rules
Clean-param: user_list
Clean-param: register
Clean-param: auth 
Clean-param: backurl 
Clean-param: order 
Clean-param: set_filter 
Clean-param: arrFilter 
Clean-param: ACTION
Clean-param: el_id
Clean-param: back_url
Clean-param: sec_id
Clean-param: utm_source
Clean-param: utm_medium
Clean-param: post
Clean-param: x
Clean-param: MARK
Clean-param: rate
Clean-param: y
Clean-param: r2
Clean-param: r1
Clean-param: TB_iframe
Clean-param: goto
Clean-param: cof
Clean-param: cx
Clean-param: height
Clean-param: width
Clean-param: year
Clean-param: month
Clean-param: R2
Clean-param: R1
Clean-param: category
Clean-param: country
Clean-param: login
Clean-param: delete_trackback_id
Clean-param: sessid
Clean-param: auth_service_id
Clean-param: auth_service_error

Host: https://www.securitylab.ru

User-agent: Mozilla/4.0 (compatible; Netcraft Web Server Survey)  
Disallow: /

User-agent: Exabot
Disallow: /

User-agent: NetCraft
Disallow: /

User-agent: Aport
Disallow: /

User-agent: Flexum
Disallow: /

User-agent: OmniExplorer_Bot
Disallow: /

User-agent: FreeFind
Disallow: /

User-agent: BecomeBot
Disallow: /

User-agent: Nutch
Disallow: /

User-agent: Jetbot/1.0
Disallow: /

User-agent: Jetbot
Disallow: /

User-agent: WebVac
Disallow: /

User-agent: Stanford
Disallow: /

User-agent: naver
Disallow: /

User-agent: dumbot
Disallow: /

User-agent: Hatena Antenna
Disallow: /

User-agent: grub-client
Disallow: /

User-agent: grub
Disallow: /

User-agent: looksmart
Disallow: /

User-agent: WebZip
Disallow: /

User-agent: larbin
Disallow: /

User-agent: b2w/0.1
Disallow: /

User-agent: Copernic
Disallow: /

User-agent: psbot
Disallow: /

User-agent: Python-urllib
Disallow: /

User-agent: NetMechanic
Disallow: /

User-agent: URL_Spider_Pro
Disallow: /

User-agent: CherryPicker
Disallow: /

User-agent: EmailCollector
Disallow: /

User-agent: EmailSiphon
Disallow: /

User-agent: WebBandit
Disallow: /

User-agent: EmailWolf
Disallow: /

User-agent: ExtractorPro
Disallow: /

User-agent: CopyRightCheck
Disallow: /

User-agent: Crescent
Disallow: /

User-agent: SiteSnagger
Disallow: /

User-agent: ProWebWalker
Disallow: /

User-agent: CheeseBot
Disallow: /

User-agent: LNSpiderguy
Disallow: /

User-agent: ia_archiver
Disallow: /

User-agent: ia_archiver/1.6
Disallow: /

User-agent: Gigabot
Disallow: /

User-agent: Gigbase
Disallow: /

User-agent: Yanga
Disallow: /
  
User-agent: Indy Library
Disallow: /

User-agent: WebCopier	
Disallow: /

User-agent: Netcraft
Disallow: /

User-agent: dotbot
Disallow: /

Sitemap: http://www.securitylab.ru/sitemap_index.xml

User-agent: ProCogSEOBot
Disallow: /

User-agent: MeMoNewsBot
Disallow: /

User-agent: TweetedTimes Bot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: PaperLiBot
Disallow: /

User-agent: rogerbot
Disallow: /

User-agent: TweetmemeBot
Disallow: /

User-agent: Socialradarbot
Disallow: /

User-agent: BazQuxBot
Disallow: /

User-agent: CompSpyBot
Disallow: /

User-agent: imrbot
Disallow: /

User-agent: Diffbot
Disallow: /

User-agent: msnbot  
Crawl-delay: 5 
 
User-agent: bingbot 
Crawl-delay: 5

User-agent: AhrefsBot
Disallow: /
--------------------------------------------------------------------------------------------------------


server.tomcat.basedir=my-tomcat
server.tomcat.accesslog.enabled=true
server.tomcat.accesslog.pattern=%t %a "%r" %s (%D ms)

server.tomcat.remote-ip-header=x-your-remote-ip-header
server.tomcat.protocol-header=x-your-protocol-header
--------------------------------------------------------------------------------------------------------
@Bean
public ServletWebServerFactory servletContainer() {
    TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
    tomcat.addAdditionalTomcatConnectors(createSslConnector());
    return tomcat;
}

private Connector createSslConnector() {
    Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
    Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
    try {
        File keystore = new ClassPathResource("keystore").getFile();
        File truststore = new ClassPathResource("keystore").getFile();
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(8443);
        protocol.setSSLEnabled(true);
        protocol.setKeystoreFile(keystore.getAbsolutePath());
        protocol.setKeystorePass("changeit");
        protocol.setTruststoreFile(truststore.getAbsolutePath());
        protocol.setTruststorePass("changeit");
        protocol.setKeyAlias("apitester");
        return connector;
    }
    catch (IOException ex) {
        throw new IllegalStateException("can't access keystore: [" + "keystore"
                + "] or truststore: [" + "keystore" + "]", ex);
    }
}
--------------------------------------------------------------------------------------------------------


server.tomcat.mbeanregistry.enabled=true


--------------------------------------------------------------------------------------------------------
@Bean
public UndertowServletWebServerFactory servletWebServerFactory() {
    UndertowServletWebServerFactory factory = new UndertowServletWebServerFactory();
    factory.addBuilderCustomizers(new UndertowBuilderCustomizer() {

        @Override
        public void customize(Builder builder) {
            builder.addHttpListener(8080, "0.0.0.0");
        }

    });
    return factory;
}

@Bean
public ServerEndpointExporter serverEndpointExporter() {
    return new ServerEndpointExporter();
}
--------------------------------------------------------------------------------------------------------
@Component
public class JerseyConfig extends ResourceConfig {

    public JerseyConfig() {
        register(Endpoint.class);
        setProperties(Collections.singletonMap("jersey.config.server.response.setStatusOverSendError", true));
    }

}
--------------------------------------------------------------------------------------------------------
static class ProxyCustomizer implements RestTemplateCustomizer {

    @Override
    public void customize(RestTemplate restTemplate) {
        HttpHost proxy = new HttpHost("proxy.example.com");
        HttpClient httpClient = HttpClientBuilder.create().setRoutePlanner(new DefaultProxyRoutePlanner(proxy) {

            @Override
            public HttpHost determineProxy(HttpHost target, HttpRequest request, HttpContext context)
                    throws HttpException {
                if (target.getHostName().equals("192.168.0.5")) {
                    return null;
                }
                return super.determineProxy(target, request, context);
            }

        }).build();
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory(httpClient));
    }

}
--------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <include resource="org/springframework/boot/logging/logback/defaults.xml" />
    <property name="LOG_FILE" value="${LOG_FILE:-${LOG_PATH:-${LOG_TEMP:-${java.io.tmpdir:-/tmp}}/}spring.log}"/>
    <include resource="org/springframework/boot/logging/logback/file-appender.xml" />
    <root level="INFO">
        <appender-ref ref="FILE" />
    </root>
</configuration>
--------------------------------------------------------------------------------------------------------
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
    <exclusions>
        <exclusion>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-logging</artifactId>
        </exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-log4j2</artifactId>
</dependency>
--------------------------------------------------------------------------------------------------------
dependencies {
    compile 'org.springframework.boot:spring-boot-starter-web'
    compile 'org.springframework.boot:spring-boot-starter-log4j2'
}

configurations {
    all {
        exclude group: 'org.springframework.boot', module: 'spring-boot-starter-logging'
    }
}
--------------------------------------------------------------------------------------------------------
@Bean
@ConfigurationProperties("app.datasource")
public DataSource dataSource() {
    return DataSourceBuilder.create().build();
}



app.datasource.jdbc-url=jdbc:mysql://localhost/test
app.datasource.username=dbuser
app.datasource.password=dbpass
app.datasource.maximum-pool-size=30

@Bean
@ConfigurationProperties("app.datasource")
public HikariDataSource dataSource() {
    return DataSourceBuilder.create().type(HikariDataSource.class).build();
}

@Bean
@Primary
@ConfigurationProperties("app.datasource")
public DataSourceProperties dataSourceProperties() {
    return new DataSourceProperties();
}

@Bean
@ConfigurationProperties("app.datasource.configuration")
public HikariDataSource dataSource(DataSourceProperties properties) {
    return properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
}
--------------------------------------------------------------------------------------------------------
@Bean
@Primary
@ConfigurationProperties("app.datasource.first")
public DataSourceProperties firstDataSourceProperties() {
    return new DataSourceProperties();
}

@Bean
@Primary
@ConfigurationProperties("app.datasource.first.configuration")
public HikariDataSource firstDataSource() {
    return firstDataSourceProperties().initializeDataSourceBuilder().type(HikariDataSource.class).build();
}

@Bean
@ConfigurationProperties("app.datasource.second")
public BasicDataSource secondDataSource() {
    return DataSourceBuilder.create().type(BasicDataSource.class).build();
}
--------------------------------------------------------------------------------------------------------
public class HibernateAwareObjectMapper extends ObjectMapper {
    public HibernateAwareObjectMapper() {
        // This for Hibernate 5; change 5 to 4 or 3 if you need to support
        // Hibernate 4 or Hibernate 3 instead
        registerModule(new Hibernate5Module());
    }
}
--------------------------------------------------------------------------------------------------------
@Entity
@Table(name = "ta_trainee", uniqueConstraints = {@UniqueConstraint(columnNames = {"id"})})
@JsonIdentityInfo(generator=ObjectIdGenerators.IntSequenceGenerator.class, property="@traineeId")
public class Trainee extends BusinessObject {

@Entity
@Table(name = "ta_bodystat", uniqueConstraints = {@UniqueConstraint(columnNames = {"id"})})
@JsonIdentityInfo(generator=ObjectIdGenerators.IntSequenceGenerator.class, property="@bodyStatId")
public class BodyStat extends BusinessObject {
--------------------------------------------------------------------------------------------------------
@ManyToOne
@JoinColumn(name="Key")
@JsonBackReference
private LgcyIsp Key;


@OneToMany(mappedBy="LgcyIsp ")
@JsonManagedReference
private List<Safety> safety;
--------------------------------------------------------------------------------------------------------
@Bean
public LocalContainerEntityManagerFactoryBean customerEntityManagerFactory(
        EntityManagerFactoryBuilder builder) {
    return builder
            .dataSource(customerDataSource())
            .packages(Customer.class)
            .persistenceUnit("customers")
            .build();
}
--------------------------------------------------------------------------------------------------------
@Configuration(proxyBeanMethods = false)
public class HibernateSecondLevelCacheExample {

    @Bean
    public HibernatePropertiesCustomizer hibernateSecondLevelCacheCustomizer(JCacheCacheManager cacheManager) {
        return (properties) -> properties.put(ConfigSettings.CACHE_MANAGER, cacheManager.getCacheManager());
    }
}
--------------------------------------------------------------------------------------------------------
@Bean
@Primary
@ConfigurationProperties("app.datasource.first")
public DataSourceProperties firstDataSourceProperties() {
    return new DataSourceProperties();
}

@Bean
@Primary
@ConfigurationProperties("app.datasource.first.configuration")
public HikariDataSource firstDataSource() {
    return firstDataSourceProperties().initializeDataSourceBuilder().type(HikariDataSource.class).build();
}

@Bean
@ConfigurationProperties("app.datasource.second")
public DataSourceProperties secondDataSourceProperties() {
    return new DataSourceProperties();
}

@Bean
@ConfigurationProperties("app.datasource.second.configuration")
public BasicDataSource secondDataSource() {
    return secondDataSourceProperties().initializeDataSourceBuilder().type(BasicDataSource.class).build();
}



app.datasource.first.url=jdbc:mysql://localhost/first
app.datasource.first.username=dbuser
app.datasource.first.password=dbpass
app.datasource.first.configuration.maximum-pool-size=30

app.datasource.second.url=jdbc:mysql://localhost/second
app.datasource.second.username=dbuser
app.datasource.second.password=dbpass
app.datasource.second.max-total=30

@Configuration(proxyBeanMethods = false)
@EnableAutoConfiguration
@EntityScan(basePackageClasses=City.class)
public class Application {
    //...
}
--------------------------------------------------------------------------------------------------------
    /**
     * Specifies what kind of numbers to return. <br>
     * <p>
     * To specify the return type of decimal numbers parsed from the json, use the following:
     * <ul>
     * <li>FLOAT_AND_DOUBLE</li> <li>BIG_DECIMAL</li> <li>DOUBLE</li>
     * </ul>
     * To specify the return type of non-decimal numbers in the json, use the following:
     * <ul>
     * <li>BIG_INTEGER</li>
     * </ul>
     */
    public enum NumberReturnType {
        /**
         * Convert all non-integer numbers to floats and doubles (depending on the size of the number)
         */
        FLOAT_AND_DOUBLE,
        /**
         * Convert all non-integer numbers to BigDecimal
         */
        BIG_DECIMAL,
        /**
         * Convert all non-integer numbers to doubles
         */
        DOUBLE,
        /**
         * Converts all non-decimal numbers to BigInteger
         */
        BIG_INTEGER;

        /**
         * Returns a boolean indicating whether this type is included in those that deal with floats
         * or doubles exclusive of BigDecimal.
         *
         * @return <code>true</code> if value is {@link #FLOAT_AND_DOUBLE} or {@link #DOUBLE}, <code>false</code> otherwise.
         */
        public final boolean isFloatOrDouble() {
            return this.equals(FLOAT_AND_DOUBLE)
                    || this.equals(DOUBLE);
        }
    }
--------------------------------------------------------------------------------------------------------
20:09:28.575: [paragon.microservices.distributor] git -c core.quotepath=false -c log.showSignature=false add --ignore-errors -A -f -- service/src/test/java/com/paragon/microservices/distributor/repository/VersionRepositoryTest.java service/src/test/java/com/paragon/microservices/distributor/repository/SessionRepositoryTest.java service/src/main/java/com/paragon/microservices/distributor/model/entity/FileEntity.java service/src/main/java/com/paragon/microservices/distributor/model/entity/LocaleEntity.java service/src/main/java/com/paragon/microservices/distributor/model/entity/VersionEntity.java service/src/test/java/com/paragon/microservices/distributor/repository/FileRepositoryTest.java service/src/main/java/com/paragon/microservices/distributor/model/entity/PlatformEntity.java service/src/test/java/com/paragon/microservices/distributor/repository/LocaleRepositoryTest.java service/src/test/java/com/paragon/microservices/distributor/repository/ProductRepositoryTest.java service/src/main/java/com/paragon/microservices/distributor/model/entity/ProductEntity.java service/src/test/java/com/paragon/microservices/distributor/repository/PlatformRepositoryTest.java service/src/main/java/com/paragon/microservices/distributor/model/entity/FileInfoEntity.java
20:09:28.972: [paragon.microservices.distributor] git -c core.quotepath=false -c log.showSignature=false commit -F C:\Users\rogalski\AppData\Local\Temp\git-commit-msg-.txt --
git -c core.quotepath=false -c log.showSignature=false fetch origin --progress --prune
--------------------------------------------------------------------------------------------------------
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;

public class Main {
  public static void main(String[] argv) throws Exception {
    try {
    } catch (Exception e) {
      e.printStackTrace(getErrorLoggerPrintStream());
    }
  }

  public static PrintStream getErrorLoggerPrintStream() {
    try {
      PrintStream s = new PrintStream(new FileOutputStream(new File("c:\\log.txt"), true));
      return s;
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    return null;
  }
}
--------------------------------------------------------------------------------------------------------
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.slf4j.Logger;

public class LoggingOutputStream extends OutputStream {
    
	public static void redirectSysOutAndSysErr(Logger logger) {
		System.setOut(new PrintStream(new LoggingOutputStream(logger, LogLevel.INFO)));
		System.setErr(new PrintStream(new LoggingOutputStream(logger, LogLevel.ERROR)));
	}

	private final ByteArrayOutputStream baos = new ByteArrayOutputStream(1000);
	private final Logger logger;
	private final LogLevel level;

	public enum LogLevel {
		TRACE, DEBUG, INFO, WARN, ERROR,
	}

	public LoggingOutputStream(Logger logger, LogLevel level) {
		this.logger = logger;
		this.level = level;
	}

	@Override
	public void write(int b) {
		if (b == '\n') {
			String line = baos.toString();
			baos.reset();

			switch (level) {
			case TRACE:
				logger.trace(line);
				break;
			case DEBUG:
				logger.debug(line);
				break;
			case ERROR:
				logger.error(line);
				break;
			case INFO:
				logger.info(line);
				break;
			case WARN:
				logger.warn(line);
				break;
			}
		} else {
			baos.write(b);
		}
	}
}

/*
 * Jacareto Copyright (c) 2002-2005
 * Applied Computer Science Research Group, Darmstadt University of
 * Technology, Institute of Mathematics & Computer Science,
 * Ludwigsburg University of Education, and Computer Based
 * Learning Research Group, Aachen University. All rights reserved.
 *
 * Jacareto is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * Jacareto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with Jacareto; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

package jacareto.toolkit.log4j;


import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.OutputStream;

/**
 * This class logs all bytes written to it as output stream with a specified logging level.
 *
 * @author <a href="mailto:cspannagel@web.de">Christian Spannagel</a>
 * @version 1.0
 */
public class LogOutputStream extends OutputStream {
    /** The logger where to log the written bytes. */
    private Logger logger;

    /** The level. */
    private Level level;

    /** The internal memory for the written bytes. */
    private String mem;

    /**
     * Creates a new log output stream which logs bytes to the specified logger with the specified
     * level.
     *
     * @param logger the logger where to log the written bytes
     * @param level the level
     */
    public LogOutputStream (Logger logger, Level level) {
        setLogger (logger);
        setLevel (level);
        mem = "";
    }

    /**
     * Sets the logger where to log the bytes.
     *
     * @param logger the logger
     */
    public void setLogger (Logger logger) {
        this.logger = logger;
    }

    /**
     * Returns the logger.
     *
     * @return DOCUMENT ME!
     */
    public Logger getLogger () {
        return logger;
    }

    /**
     * Sets the logging level.
     *
     * @param level DOCUMENT ME!
     */
    public void setLevel (Level level) {
        this.level = level;
    }

    /**
     * Returns the logging level.
     *
     * @return DOCUMENT ME!
     */
    public Level getLevel () {
        return level;
    }

    /**
     * Writes a byte to the output stream. This method flushes automatically at the end of a line.
     *
     * @param b DOCUMENT ME!
     */
    public void write (int b) {
        byte[] bytes = new byte[1];
        bytes[0] = (byte) (b & 0xff);
        mem = mem + new String(bytes);

        if (mem.endsWith ("\n")) {
            mem = mem.substring (0, mem.length () - 1);
            flush ();
        }
    }

    /**
     * Flushes the output stream.
     */
    public void flush () {
        logger.log (level, mem);
        mem = "";
    }
}
--------------------------------------------------------------------------------------------------------
    <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-javadoc-plugin</artifactId>
            <!-- <version>3.0.0</version> -->
            <configuration>
                <!-- Silence error javax.interceptor.InterceptorBinding not found -->
                <additionalDependencies>
                    <additionalDependency>
                        <groupId>javax.interceptor</groupId>
                        <artifactId>javax.interceptor-api</artifactId>
                        <version>1.2</version>
                    </additionalDependency>
                </additionalDependencies>
            </configuration>
        </plugin>
--------------------------------------------------------------------------------------------------------
//package de.pearl.pem.common.system.configuration;
//
//@SpringBootApplication
//@EnableAutoConfiguration(exclude = {ResourceServerTokenServicesConfiguration.class},
//        excludeName = {"org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration$JwtTokenServicesConfiguration"})
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, proxyTargetClass = true)
//public class Elephant
//{
//    public static void main(String[] args) {
//        SpringApplication.run(Elephant.class, args);
//    }
//
//    @Configuration
//    @EnableResourceServer
//    protected static class SecurityConfiguration extends ResourceServerConfigurerAdapter
//    {
//
//        @Autowired
//        @Qualifier("customJwtTokenEnhancer")
//        JwtAccessTokenConverter customJwtTokenEnhancer;
//
//        @Autowired
//        @Qualifier("customJwtTokenStore")
//        TokenStore customJwtTokenStore;
//
//        @Autowired
//        @Qualifier("customJwtTokenServices")
//        ResourceServerTokenServices customJwtTokenServices;
//
//        @Override
//        public void configure(ResourceServerSecurityConfigurer resources) throws Exception
//        {
//            resources.tokenServices(customJwtTokenServices);
//        }
//
//        @Bean
//        public ResourceServerTokenServices customJwtTokenServices() {
//            DefaultTokenServices services = new DefaultTokenServices();
//            services.setTokenStore(customJwtTokenStore);
//            return services;
//        }
//
//        @Bean
//        public TokenStore customJwtTokenStore() {
//            return new JwtTokenStore(customJwtTokenEnhancer);
//        }
//
//        @Bean
//        @Autowired
//        public JwtAccessTokenConverter customJwtTokenEnhancer(
//                @Value("${security.oauth2.resource.jwt.keyValue}") String keyValue) {
//            JwtAccessTokenConverter converter = new JwtAccessTokenConverter(){
//                @Override
//                public OAuth2Authentication extractAuthentication(Map<String, ?> map)
//                {
//                    OAuth2Authentication authentication = super.extractAuthentication(map);
//                    Map<String, String> details = new HashMap<>();
//                    details.put("account_id", (String) map.get("account_id"));
//                    authentication.setDetails(details);
//                    return authentication;
//                }
//            };
//            if (keyValue != null) {
//                converter.setVerifierKey(keyValue);
//            }
//            return converter;
//        }
//    }
//}
//
//
///*
//server.port = 8081
//
//logging.level.org.springframework.security=DEBUG
//security.sessions=stateless
//security.oauth2.resource.jwt.keyValue=-----BEGIN PUBLIC KEY-----[[MY KEY]]-----END PUBLIC KEY-----
// */
--------------------------------------------------------------------------------------------------------
//    @Bean
//    public FilterRegistrationBean<RequestResponseLoggingFilter> loggingFilter(){
//        final FilterRegistrationBean<RequestResponseLoggingFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(new RequestResponseLoggingFilter());
//        registrationBean.addUrlPatterns("/users/*");
//        return registrationBean;
//    }

    @Bean
    public FilterRegistrationBean encodingFilter() {
        CharacterEncodingFilter encodingFilter = new CharacterEncodingFilter("UTF-8", true);
        FilterRegistrationBean filterRegBean = new FilterRegistrationBean();
        filterRegBean.setUrlPatterns(getRootPathUrls());
        filterRegBean.setFilter(encodingFilter);
        filterRegBean.setOrder(1);
        return filterRegBean;
    }
	
////    @Bean
////    public FilterRegistrationBean getFilterRegistrationBean() {
////        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
////        filterRegistrationBean.setFilter(new CharacterEncodingFilter());
////        return filterRegistrationBean;
////    }


    OutputStream output = new OutputStream()
    {
        private StringBuilder string = new StringBuilder();
        @Override
        public void write(int b) throws IOException {
            this.string.append((char) b );
        }

        //Netbeans IDE automatically overrides this toString()
        public String toString(){
            return this.string.toString();
        }
    };
--------------------------------------------------------------------------------------------------------
/**
 * The type of event received by the listener.
 *
 * @author Greg Luck
 * @since 1.0
 */
public enum EventType {

  /**
   * An event type indicating that the cache entry was created.
   */
  CREATED,

  /**
   * An event type indicating that the cache entry was updated. i.e. a previous
   * mapping existed
   */
  UPDATED,


  /**
   * An event type indicating that the cache entry was removed.
   */
  REMOVED,


  /**
   * An event type indicating that the cache entry has expired.
   */
  EXPIRED

}
--------------------------------------------------------------------------------------------------------
spring.datasource.continue-on-error
spring.batch.initialize-schema=always
--------------------------------------------------------------------------------------------------------
@Configuration(proxyBeanMethods = false)
public class SslWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Customize the application security
        http.requiresChannel().anyRequest().requiresSecure();
    }
}
--------------------------------------------------------------------------------------------------------
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <version>2.2.0.RELEASE</version>
            <executions>
                <execution>
                    <goals>
                        <goal>build-info</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
--------------------------------------------------------------------------------------------------------
    /**
     * Returns generated identifier {@link String}
     *
     * @param length - initial input identifier length
     * @return generated identifier {@link String}
     */
    public static String generateId(final int length) {
        assert length > 0 : "Length should be positive number";
        final StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < length; i++) {
            char next = (char) ('a' + (int) Math.floor(Math.random() * 26));
            if (Math.random() < 0.5) {
                next = Character.toUpperCase(next);
            }
            buffer.append(next);
        }
        return buffer.toString();
    }
--------------------------------------------------------------------------------------------------------
package de.pearl.pem.common.config;

import java.util.List;
 
import javax.sql.DataSource;
 
import static org.junit.Assert.*;
 
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
 
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@Sql({ "drop_schema.sql", "schema.sql", "data.sql" })
public class DBConfigTest {
     
    @Autowired
    private JdbcTemplate jdbcTemplate;
     
    @Rule
    public TestName testName = new TestName();
     
    @Before
    public void printTestName() {
        System.out.println(testName.getMethodName());
    }
 ERROR: cannot serialize input date: Sat May 05 11:50:55 MSK 2018 by format: yyyy-MM-dp, locale: en_US, message: Illegal pattern character 'p'
    @Test
    public void printRows() {
        List empNames = jdbcTemplate.queryForList("select name from employee",
                String.class);
        assertEquals(2, empNames.size());
        System.out.println(empNames);
    }
     
    @Configuration
    static class Config {
 
        @Bean
        public DataSource dataSource() {
            return new EmbeddedDatabaseBuilder()//
            .setName("empty-sql-scripts-without-tx-mgr-test-db")//
            .build();
        }
         
        @Bean
        public JdbcTemplate jdbcTemplate() {
            return new JdbcTemplate(dataSource());
        }
    }
}
--------------------------------------------------------------------------------------------------------
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <configuration>
                <requiresUnpack>
                    <dependency>
                        <groupId>org.jruby</groupId>
                        <artifactId>jruby-complete</artifactId>
                    </dependency>
                </requiresUnpack>
            </configuration>
        </plugin>
    </plugins>
</build>
--------------------------------------------------------------------------------------------------------
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, classes = ToggleApplication.class)
@AutoConfigureMockMvc
--------------------------------------------------------------------------------------------------------
import java.net.InetAddress;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.DefaultValue;

@ConstructorBinding
@ConfigurationProperties("acme")
public class AcmeProperties {

    private final boolean enabled;

    private final InetAddress remoteAddress;

    private final Security security;

    public AcmeProperties(boolean enabled, InetAddress remoteAddress, Security security) {
        this.enabled = enabled;
        this.remoteAddress = remoteAddress;
        this.security = security;
    }

    public boolean isEnabled() { ... }

    public InetAddress getRemoteAddress() { ... }

    public Security getSecurity() { ... }

    public static class Security {

        private final String username;

        private final String password;

        private final List<String> roles;

        public Security(String username, String password,
                @DefaultValue("USER") List<String> roles) {
            this.username = username;
            this.password = password;
            this.roles = roles;
        }

        public String getUsername() { ... }

        public String getPassword() { ... }

        public List<String> getRoles() { ... }

    }
}
--------------------------------------------------------------------------------------------------------
@ConfigurationProperties("app.system")
public class AppSystemProperties {

    @DurationUnit(ChronoUnit.SECONDS)
    private Duration sessionTimeout = Duration.ofSeconds(30);

    private Duration readTimeout = Duration.ofMillis(1000);

    public Duration getSessionTimeout() {
        return this.sessionTimeout;
    }

    public void setSessionTimeout(Duration sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    public Duration getReadTimeout() {
        return this.readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }
}
--------------------------------------------------------------------------------------------------------
@ConfigurationProperties("app.io")
public class AppIoProperties {

    @DataSizeUnit(DataUnit.MEGABYTES)
    private DataSize bufferSize = DataSize.ofMegabytes(2);

    private DataSize sizeThreshold = DataSize.ofBytes(512);

    public DataSize getBufferSize() {
        return this.bufferSize;
    }

    public void setBufferSize(DataSize bufferSize) {
        this.bufferSize = bufferSize;
    }

    public DataSize getSizeThreshold() {
        return this.sizeThreshold;
    }

    public void setSizeThreshold(DataSize sizeThreshold) {
        this.sizeThreshold = sizeThreshold;
    }
}
--------------------------------------------------------------------------------------------------------
#spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.web.ErrorMvcAutoConfiguration
#spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration
--------------------------------------------------------------------------------------------------------
kill $(cat ./bin/shutdown.pid)

--------------------------------------------------------------------------------------------------------
type Post {
    id: ID!
    title: String!
    text: String!
    category: String
    author: Author
}

type Author {
    id: ID!
    name: String!
    thumbnail: String
    posts: [Post]!
}

# The Root Query for the application
type Query {
    recentPosts(count: Int, offset: Int): [Post]!
}

# The Root Mutation for the application
type Mutation {
    writePost(title: String!, text: String!, category: String, author: String!) : Post!
}
--------------------------------------------------------------------------------------------------------import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.ExecutableType;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;

import com.google.auto.service.AutoService;

@SupportedAnnotationTypes("com.baeldung.annotation.processor.BuilderProperty")
@SupportedSourceVersion(SourceVersion.RELEASE_8)
@AutoService(Processor.class)
public class BuilderProcessor extends AbstractProcessor {

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (TypeElement annotation : annotations) {

            Set<? extends Element> annotatedElements = roundEnv.getElementsAnnotatedWith(annotation);

            Map<Boolean, List<Element>> annotatedMethods = annotatedElements.stream().collect(Collectors.partitioningBy(element -> ((ExecutableType) element.asType()).getParameterTypes().size() == 1 && element.getSimpleName().toString().startsWith("set")));

            List<Element> setters = annotatedMethods.get(true);
            List<Element> otherMethods = annotatedMethods.get(false);

            otherMethods.forEach(element -> processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, "@BuilderProperty must be applied to a setXxx method with a single argument", element));

            if (setters.isEmpty()) {
                continue;
            }

            String className = ((TypeElement) setters.get(0).getEnclosingElement()).getQualifiedName().toString();

            Map<String, String> setterMap = setters.stream().collect(Collectors.toMap(setter -> setter.getSimpleName().toString(), setter -> ((ExecutableType) setter.asType()).getParameterTypes().get(0).toString()));

            try {
                writeBuilderFile(className, setterMap);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        return true;
    }

    private void writeBuilderFile(String className, Map<String, String> setterMap) throws IOException {

        String packageName = null;
        int lastDot = className.lastIndexOf('.');
        if (lastDot > 0) {
            packageName = className.substring(0, lastDot);
        }

        String simpleClassName = className.substring(lastDot + 1);
        String builderClassName = className + "Builder";
        String builderSimpleClassName = builderClassName.substring(lastDot + 1);

        JavaFileObject builderFile = processingEnv.getFiler().createSourceFile(builderClassName);
        try (PrintWriter out = new PrintWriter(builderFile.openWriter())) {

            if (packageName != null) {
                out.print("package ");
                out.print(packageName);
                out.println(";");
                out.println();
            }

            out.print("public class ");
            out.print(builderSimpleClassName);
            out.println(" {");
            out.println();

            out.print("    private ");
            out.print(simpleClassName);
            out.print(" object = new ");
            out.print(simpleClassName);
            out.println("();");
            out.println();

            out.print("    public ");
            out.print(simpleClassName);
            out.println(" build() {");
            out.println("        return object;");
            out.println("    }");
            out.println();

            setterMap.entrySet().forEach(setter -> {
                String methodName = setter.getKey();
                String argumentType = setter.getValue();

                out.print("    public ");
                out.print(builderSimpleClassName);
                out.print(" ");
                out.print(methodName);

                out.print("(");

                out.print(argumentType);
                out.println(" value) {");
                out.print("        object.");
                out.print(methodName);
                out.println("(value);");
                out.println("        return this;");
                out.println("    }");
                out.println();
            });

            out.println("}");

        }
    }

}
--------------------------------------------------------------------------------------------------------

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

public class FibonacciSequence {

    private static LoadingCache<Integer, BigInteger> memo = CacheBuilder.newBuilder()
            .maximumSize(100)
            .build(CacheLoader.from(FibonacciSequence::getFibonacciNumber));

    public static BigInteger getFibonacciNumber(int n) {
        if (n == 0) {
            return BigInteger.ZERO;
        } else if (n == 1) {
            return BigInteger.ONE;
        } else {
            return memo.getUnchecked(n - 1).add(memo.getUnchecked(n - 2));
        }
    }

}

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.math.BigInteger;

public class Factorial {

    private static LoadingCache<Integer, BigInteger> memo = CacheBuilder.newBuilder()
            .build(CacheLoader.from(Factorial::getFactorial));

    public static BigInteger getFactorial(int n) {
        if (n == 0) {
            return BigInteger.ONE;
        } else {
            return BigInteger.valueOf(n).multiply(memo.getUnchecked(n - 1));
        }
    }

}

--------------------------------------------------------------------------------------------------------
import org.immutables.value.Value;

@Value.Immutable(prehash = true)
public abstract class Person {
    abstract String getName();
    abstract Integer getAge();
}

--------------------------------------------------------------------------------------------------------
@JsonTypeName("itemIdRemovedFromUser")
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS, include = JsonTypeInfo.As.PROPERTY, property = "eventType")
@JsonTypeName("itemIdAddedToUser")
@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd@HH:mm:ss.SSSZ", locale = "en_GB")
--------------------------------------------------------------------------------------------------------
import com.baeldung.jackson.serialization.DistanceSerializer;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * Use  @JsonFormat to handle representation of Enum as JSON (available since Jackson 2.1.2)
 * Use @JsonSerialize to configure a custom Jackson serializer
 */
// @JsonFormat(shape = JsonFormat.Shape.OBJECT)
@JsonSerialize(using = DistanceSerializer.class)
public enum Distance {
    KILOMETER("km", 1000), MILE("miles", 1609.34), METER("meters", 1), INCH("inches", 0.0254), CENTIMETER("cm", 0.01), MILLIMETER("mm", 0.001);

    private String unit;
    private final double meters;

    private Distance(String unit, double meters) {
        this.unit = unit;
        this.meters = meters;
    }

    /**
     * Use @JsonValue to control marshalling output for an enum
     */
    // @JsonValue
    public double getMeters() {
        return meters;
    }

    public String getUnit() {
        return unit;
    }

    public void setUnit(String unit) {
        this.unit = unit;
    }

    /**
     * Usage example: Distance.MILE.convertFromMeters(1205.5);
     */
    public double convertFromMeters(double distanceInMeters) {
        return distanceInMeters / meters;

    }

    /**
     * Usage example: Distance.MILE.convertToMeters(0.5);
     */
    public double convertToMeters(double distanceInMeters) {
        return distanceInMeters * meters;
    }

}
--------------------------------------------------------------------------------------------------------
   @JacksonInject
    private UUID id;
	@JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
--------------------------------------------------------------------------------------------------------
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonDeserialize(builder = Person.Builder.class)
public class Person {

    private final String name;
    private final Integer age;

    private Person(String name, Integer age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public Integer getAge() {
        return age;
    }

    @JsonPOJOBuilder
    static class Builder {
        String name;
        Integer age;

        Builder withName(String name) {
            this.name = name;
            return this;
        }

        Builder withAge(Integer age) {
            this.age = age;
            return this;
        }

        Person build() {
            return new Person(name, age);
        }
    }
}
--------------------------------------------------------------------------------------------------------

import java.time.DayOfWeek;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.time.temporal.Temporal;
import java.time.temporal.TemporalAdjuster;

public class CustomTemporalAdjuster implements TemporalAdjuster {

    @Override
    public Temporal adjustInto(Temporal temporal) {
        switch (DayOfWeek.of(temporal.get(ChronoField.DAY_OF_WEEK))) {
        case FRIDAY:
            return temporal.plus(3, ChronoUnit.DAYS);
        case SATURDAY:
            return temporal.plus(2, ChronoUnit.DAYS);
        default:
            return temporal.plus(1, ChronoUnit.DAYS);
        }
    }
}
--------------------------------------------------------------------------------------------------------
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class TimeApi {

    public static List<Date> getDatesBetweenUsingJava7(Date startDate, Date endDate) {
        List<Date> datesInRange = new ArrayList<Date>();
        Calendar calendar = new GregorianCalendar();
        calendar.setTime(startDate);

        Calendar endCalendar = new GregorianCalendar();
        endCalendar.setTime(endDate);

        while (calendar.before(endCalendar)) {
            Date result = calendar.getTime();
            datesInRange.add(result);
            calendar.add(Calendar.DATE, 1);
        }
        return datesInRange;
    }

    public static List<LocalDate> getDatesBetweenUsingJava8(LocalDate startDate, LocalDate endDate) {
        long numOfDaysBetween = ChronoUnit.DAYS.between(startDate, endDate);
        return IntStream.iterate(0, i -> i + 1)
                 .limit(numOfDaysBetween)
                 .mapToObj(i -> startDate.plusDays(i))
                 .collect(Collectors.toList());
    }

    public static List<LocalDate> getDatesBetweenUsingJava9(LocalDate startDate, LocalDate endDate) {
        return startDate.datesUntil(endDate).collect(Collectors.toList());
    }

}
--------------------------------------------------------------------------------------------------------
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.runner.RunnerException;

public class Benchmarking {
    public static void main(String[] args) throws RunnerException, IOException {
        org.openjdk.jmh.Main.main(args);
    }

    @State(Scope.Thread)
    public static class ExecutionPlan {
        public int number = Integer.MAX_VALUE;
        public int length = 0;
        public NumberOfDigits numberOfDigits= new NumberOfDigits();
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void stringBasedSolution(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.stringBasedSolution(plan.number);
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void logarithmicApproach(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.logarithmicApproach(plan.number);
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void repeatedMultiplication(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.repeatedMultiplication(plan.number);
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void shiftOperators(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.shiftOperators(plan.number);
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void dividingWithPowersOf2(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.dividingWithPowersOf2(plan.number);
    }
    
    @Benchmark 
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void divideAndConquer(ExecutionPlan plan) {
        plan.length = plan.numberOfDigits.divideAndConquer(plan.number);
    }
}
--------------------------------------------------------------------------------------------------------
    public int dividingWithPowersOf2(int number) {
        int length = 1;
        if (number >= 100000000) {
            length += 8;
            number /= 100000000;
        }
        if (number >= 10000) {
            length += 4;
            number /= 10000;
        }
        if (number >= 100) {
            length += 2;
            number /= 100;
        }
        if (number >= 10) {
            length += 1;
        }
        return length;
    }
--------------------------------------------------------------------------------------------------------
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PrimeGenerator {
    public static List<Integer> sieveOfEratosthenes(int n) {
        final boolean prime[] = new boolean[n + 1];
        Arrays.fill(prime, true);

        for (int p = 2; p * p <= n; p++) {
            if (prime[p]) {
                for (int i = p * 2; i <= n; i += p)
                    prime[i] = false;
            }
        }

        final List<Integer> primes = new LinkedList<>();
        for (int i = 2; i <= n; i++) {
            if (prime[i])
                primes.add(i);
        }
        return primes;
    }

    public static List<Integer> primeNumbersBruteForce(int max) {
        final List<Integer> primeNumbers = new LinkedList<Integer>();
        for (int i = 2; i <= max; i++) {
            if (isPrimeBruteForce(i)) {
                primeNumbers.add(i);
            }
        }
        return primeNumbers;
    }

    private static boolean isPrimeBruteForce(int x) {
        for (int i = 2; i < x; i++) {
            if (x % i == 0) {
                return false;
            }
        }
        return true;
    }

    public static List<Integer> primeNumbersTill(int max) {
        return IntStream.rangeClosed(2, max)
            .filter(x -> isPrime(x))
            .boxed()
            .collect(Collectors.toList());
    }

    private static boolean isPrime(int x) {
        return IntStream.rangeClosed(2, (int) (Math.sqrt(x)))
            .allMatch(n -> x % n != 0);
    }
}
--------------------------------------------------------------------------------------------------------
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PrimeFactorizationAlgorithm {

    public static Map<Integer, Integer> getPrimeFactors(int number) {
        int absNumber = Math.abs(number);
        Map<Integer, Integer> primeFactorsMap = new HashMap<Integer, Integer>();
        for (int factor = 2; factor <= absNumber; factor++) {
            while (absNumber % factor == 0) {
                Integer power = primeFactorsMap.get(factor);
                if (power == null) {
                    power = 0;
                }
                primeFactorsMap.put(factor, power + 1);
                absNumber /= factor;
            }
        }
        return primeFactorsMap;
    }

    public static int lcm(int number1, int number2) {
        if (number1 == 0 || number2 == 0) {
            return 0;
        }
        Map<Integer, Integer> primeFactorsForNum1 = getPrimeFactors(number1);
        Map<Integer, Integer> primeFactorsForNum2 = getPrimeFactors(number2);
        Set<Integer> primeFactorsUnionSet = new HashSet<Integer>(primeFactorsForNum1.keySet());
        primeFactorsUnionSet.addAll(primeFactorsForNum2.keySet());
        int lcm = 1;
        for (Integer primeFactor : primeFactorsUnionSet) {
            lcm *= Math.pow(primeFactor, Math.max(primeFactorsForNum1.getOrDefault(primeFactor, 0),
                    primeFactorsForNum2.getOrDefault(primeFactor, 0)));
        }
        return lcm;
    }

}
--------------------------------------------------------------------------------------------------------

import java.util.Arrays;

public class EuclideanAlgorithm {

    public static int gcd(int number1, int number2) {
        if (number1 == 0 || number2 == 0) {
            return number1 + number2;
        } else {
            int absNumber1 = Math.abs(number1);
            int absNumber2 = Math.abs(number2);
            int biggerValue = Math.max(absNumber1, absNumber2);
            int smallerValue = Math.min(absNumber1, absNumber2);
            return gcd(biggerValue % smallerValue, smallerValue);
        }
    }

    public static int lcm(int number1, int number2) {
        if (number1 == 0 || number2 == 0)
            return 0;
        else {
            int gcd = gcd(number1, number2);
            return Math.abs(number1 * number2) / gcd;
        }
    }

    public static int lcmForArray(int[] numbers) {
        int lcm = numbers[0];
        for (int i = 1; i <= numbers.length - 1; i++) {
            lcm = lcm(lcm, numbers[i]);
        }
        return lcm;
    }

    public static int lcmByLambda(int... numbers) {
        return Arrays.stream(numbers).reduce(1, (lcmSoFar, currentNumber) -> Math.abs(lcmSoFar * currentNumber) / gcd(lcmSoFar, currentNumber));
    }

}
--------------------------------------------------------------------------------------------------------

public class BinaryNumbers {

    /**
     * This method takes a decimal number and convert it into a binary number.
     * example:- input:10, output:1010
     *
     * @param decimalNumber
     * @return binary number
     */
    public Integer convertDecimalToBinary(Integer decimalNumber) {

        if (decimalNumber == 0) {
            return decimalNumber;
        }

        StringBuilder binaryNumber = new StringBuilder();
        Integer quotient = decimalNumber;

        while (quotient > 0) {

            int remainder = quotient % 2;
            binaryNumber.append(remainder);
            quotient /= 2;
        }

        binaryNumber = binaryNumber.reverse();
        return Integer.valueOf(binaryNumber.toString());
    }

    /**
     * This method takes a binary number and convert it into a decimal number.
     * example:- input:101, output:5
     *
     * @param binary number
     * @return decimal Number
     */
    public Integer convertBinaryToDecimal(Integer binaryNumber) {

        Integer decimalNumber = 0;
        Integer base = 1;

        while (binaryNumber > 0) {

            int lastDigit = binaryNumber % 10;
            binaryNumber = binaryNumber / 10;

            decimalNumber += lastDigit * base;
            base = base * 2;
        }
        return decimalNumber;
    }

    /**
     * This method accepts two binary numbers and returns sum of input numbers.
     * Example:- firstNum: 101, secondNum: 100, output: 1001
     *
     * @param firstNum
     * @param secondNum
     * @return addition of input numbers
     */
    public Integer addBinaryNumber(Integer firstNum, Integer secondNum) {

        StringBuilder output = new StringBuilder();

        int carry = 0;
        int temp;

        while (firstNum != 0 || secondNum != 0) {

            temp = (firstNum % 10 + secondNum % 10 + carry) % 2;
            output.append(temp);

            carry = (firstNum % 10 + secondNum % 10 + carry) / 2;

            firstNum = firstNum / 10;
            secondNum = secondNum / 10;
        }

        if (carry != 0) {
            output.append(carry);
        }

        return Integer.valueOf(output.reverse()
            .toString());
    }

    /**
    * This method takes two binary number as input and subtract second number from the first number.
    * example:- firstNum: 1000, secondNum: 11, output: 101
    * @param firstNum
    * @param secondNum
    * @return Result of subtraction of secondNum from first
    */
    public Integer substractBinaryNumber(Integer firstNum, Integer secondNum) {

        int onesComplement = Integer.valueOf(getOnesComplement(secondNum));
        StringBuilder output = new StringBuilder();
        int carry = 0;
        int temp;

        while (firstNum != 0 || onesComplement != 0) {

            temp = (firstNum % 10 + onesComplement % 10 + carry) % 2;
            output.append(temp);

            carry = (firstNum % 10 + onesComplement % 10 + carry) / 2;

            firstNum = firstNum / 10;
            onesComplement = onesComplement / 10;
        }

        String additionOfFirstNumAndOnesComplement = output.reverse()
            .toString();

        if (carry == 1) {
            return addBinaryNumber(Integer.valueOf(additionOfFirstNumAndOnesComplement), carry);
        } else {
            return getOnesComplement(Integer.valueOf(additionOfFirstNumAndOnesComplement));
        }
    }

    public Integer getOnesComplement(Integer num) {

        StringBuilder onesComplement = new StringBuilder();
        while (num > 0) {
            int lastDigit = num % 10;
            if (lastDigit == 0) {
                onesComplement.append(1);
            } else {
                onesComplement.append(0);
            }
            num = num / 10;
        }
        return Integer.valueOf(onesComplement.reverse()
            .toString());
    }

}
--------------------------------------------------------------------------------------------------------
import java.util.Spliterator;
import java.util.function.BiConsumer;
import java.util.stream.Stream;

public class CustomForEach {

    public static class Breaker {
        private boolean shouldBreak = false;

        public void stop() {
            shouldBreak = true;
        }

        boolean get() {
            return shouldBreak;
        }
    }

    public static <T> void forEach(Stream<T> stream, BiConsumer<T, Breaker> consumer) {
        Spliterator<T> spliterator = stream.spliterator();
        boolean hadNext = true;
        Breaker breaker = new Breaker();

        while (hadNext && !breaker.get()) {
            hadNext = spliterator.tryAdvance(elem -> {
                consumer.accept(elem, breaker);
            });
        }
    }
}
--------------------------------------------------------------------------------------------------------
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Based on https://github.com/tedyoung/indexof-contains-benchmark
 */
@Fork(5)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class SubstringSearchPerformanceComparison {

    private String message;

    private Pattern pattern;

    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.Main.main(args);
    }

    @Setup
    public void setup() {
        message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum";
        pattern = Pattern.compile("(?<!\\S)" + "eiusmod" + "(?!\\S)");
    }

    @Benchmark
    public int indexOf() {
        return message.indexOf("eiusmod");
    }

    @Benchmark
    public boolean contains() {
        return message.contains("eiusmod");
    }

    @Benchmark
    public boolean containsStringUtilsIgnoreCase() {
        return StringUtils.containsIgnoreCase(message, "eiusmod");
    }

    @Benchmark
    public boolean searchWithPattern() {
        return pattern.matcher(message).find();
    }
}
--------------------------------------------------------------------------------------------------------
import java.util.StringTokenizer;

public class WordCounter {
    static final int WORD = 0;
    static final int SEPARATOR = 1;

    public static int countWordsUsingRegex(String arg) {
        if (arg == null) {
            return 0;
        }
        final String[] words = arg.split("[\\pP\\s&&[^']]+");
        return words.length;
    }

    public static int countWordsUsingTokenizer(String arg) {
        if (arg == null) {
            return 0;
        }
        final StringTokenizer stringTokenizer = new StringTokenizer(arg);
        return stringTokenizer.countTokens();
    }

    public static int countWordsManually(String arg) {
        if (arg == null) {
            return 0;
        }
        int flag = SEPARATOR;
        int count = 0;
        int stringLength = arg.length();
        int characterCounter = 0;

        while (characterCounter < stringLength) {
            if (isAllowedInWord(arg.charAt(characterCounter)) && flag == SEPARATOR) {
                flag = WORD;
                count++;
            } else if (!isAllowedInWord(arg.charAt(characterCounter))) {
                flag = SEPARATOR;
            }
            characterCounter++;
        }
        return count;
    }

    private static boolean isAllowedInWord(char charAt) {
        return charAt == '\'' || Character.isLetter(charAt);
    }
}
--------------------------------------------------------------------------------------------------------
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Measurement(batchSize = 100000, iterations = 10)
@Warmup(batchSize = 100000, iterations = 10)
@State(Scope.Thread)
public class StringPerformance {}
--------------------------------------------------------------------------------------------------------

import java.util.ArrayList;
import java.util.List;

public class WordIndexer {

    public List<Integer> findWord(String textString, String word) {
        int index = 0;
        List<Integer> indexes = new ArrayList<Integer>();
        String lowerCaseTextString = textString.toLowerCase();
        String lowerCaseWord = word.toLowerCase();

        while(index != -1) {
            index = lowerCaseTextString.indexOf(lowerCaseWord, index);
            if (index == -1) {
                break;
            }

            indexes.add(index);
            index++;
        }
        return indexes;
    }



    public List<Integer> findWordUpgrade(String textString, String word) {
        int index = 0;
        List<Integer> indexes = new ArrayList<Integer>();
        StringBuilder output = new StringBuilder();
        String lowerCaseTextString = textString.toLowerCase();
        String lowerCaseWord = word.toLowerCase();
        int wordLength = 0;

        while(index != -1){
            index = lowerCaseTextString.indexOf(lowerCaseWord, index + wordLength);  // Slight improvement
            if (index != -1) {
                indexes.add(index);
            }
            wordLength = word.length();
        }
        return indexes;
    }
}
--------------------------------------------------------------------------------------------------------
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.lang.Assert;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

@Service
public class SecretService {

    private Map<String, String> secrets = new HashMap<>();

    private SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
        @Override
        public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
            return TextCodec.BASE64.decode(secrets.get(header.getAlgorithm()));
        }
    };

    @PostConstruct
    public void setup() {
        refreshSecrets();
    }

    public SigningKeyResolver getSigningKeyResolver() {
        return signingKeyResolver;
    }

    public Map<String, String> getSecrets() {
        return secrets;
    }

    public void setSecrets(Map<String, String> secrets) {
        Assert.notNull(secrets);
        Assert.hasText(secrets.get(SignatureAlgorithm.HS256.getValue()));
        Assert.hasText(secrets.get(SignatureAlgorithm.HS384.getValue()));
        Assert.hasText(secrets.get(SignatureAlgorithm.HS512.getValue()));

        this.secrets = secrets;
    }

    public byte[] getHS256SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS256.getValue()));
    }

    public byte[] getHS384SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS384.getValue()));
    }

    public byte[] getHS512SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS512.getValue()));
    }

    public Map<String, String> refreshSecrets() {
        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256);
        secrets.put(SignatureAlgorithm.HS256.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        key = MacProvider.generateKey(SignatureAlgorithm.HS384);
        secrets.put(SignatureAlgorithm.HS384.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        key = MacProvider.generateKey(SignatureAlgorithm.HS512);
        secrets.put(SignatureAlgorithm.HS512.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        return secrets;
    }
}
--------------------------------------------------------------------------------------------------------
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jjwtfun.model.JwtResponse;
import io.jsonwebtoken.jjwtfun.service.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Date;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
public class StaticJWTController extends BaseController {

    @Autowired
    SecretService secretService;

    @RequestMapping(value = "/static-builder", method = GET)
    public JwtResponse fixedBuilder() throws UnsupportedEncodingException {
        String jws = Jwts.builder()
            .setIssuer("Stormpath")
            .setSubject("msilverman")
            .claim("name", "Micah Silverman")
            .claim("scope", "admins")
            .setIssuedAt(Date.from(Instant.ofEpochSecond(1466796822L))) // Fri Jun 24 2016 15:33:42 GMT-0400 (EDT)
            .setExpiration(Date.from(Instant.ofEpochSecond(4622470422L))) // Sat Jun 24 2116 15:33:42 GMT-0400 (EDT)
            .signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes())
            .compact();

        return new JwtResponse(jws);
    }

    @RequestMapping(value = "/parser", method = GET)
    public JwtResponse parser(@RequestParam String jwt) throws UnsupportedEncodingException {

        Jws<Claims> jws = Jwts.parser()
            .setSigningKeyResolver(secretService.getSigningKeyResolver())
            .parseClaimsJws(jwt);

        return new JwtResponse(jws);
    }

    @RequestMapping(value = "/parser-enforce", method = GET)
    public JwtResponse parserEnforce(@RequestParam String jwt) throws UnsupportedEncodingException {
        Jws<Claims> jws = Jwts.parser()
            .requireIssuer("Stormpath")
            .require("hasMotorcycle", true)
            .setSigningKeyResolver(secretService.getSigningKeyResolver())
            .parseClaimsJws(jwt);

        return new JwtResponse(jws);
    }
}
--------------------------------------------------------------------------------------------------------

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.UUID;

public class JWTCsrfTokenRepository implements CsrfTokenRepository {

    private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = CSRFConfig.class.getName()
        .concat(".CSRF_TOKEN");

    private static final Logger log = LoggerFactory.getLogger(JWTCsrfTokenRepository.class);
    private byte[] secret;

    public JWTCsrfTokenRepository(byte[] secret) {
        this.secret = secret;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String id = UUID.randomUUID()
            .toString()
            .replace("-", "");

        Date now = new Date();
        Date exp = new Date(System.currentTimeMillis() + (1000 * 30)); // 30 seconds

        String token = Jwts.builder()
            .setId(id)
            .setIssuedAt(now)
            .setNotBefore(now)
            .setExpiration(exp)
            .signWith(SignatureAlgorithm.HS256, secret)
            .compact();

        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", token);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(DEFAULT_CSRF_TOKEN_ATTR_NAME);
            }
        } else {
            HttpSession session = request.getSession();
            session.setAttribute(DEFAULT_CSRF_TOKEN_ATTR_NAME, token);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || "GET".equals(request.getMethod())) {
            return null;
        }
        return (CsrfToken) session.getAttribute(DEFAULT_CSRF_TOKEN_ATTR_NAME);
    }
}
--------------------------------------------------------------------------------------------------------
   private int id;
    @JsonbProperty("person-name")
    private String name;
    @JsonbProperty(nillable = true)
    private String email;
    @JsonbTransient
    private int age;
    @JsonbDateFormat("dd-MM-yyyy")
    private LocalDate registeredDate;
    private BigDecimal salary;
--------------------------------------------------------------------------------------------------------
    @RequestMapping(value = "/dynamic-builder-general", method = POST)
    public JwtResponse dynamicBuilderGeneric(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        String jws = Jwts.builder()
            .setClaims(claims)
            .signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes())
            .compact();
        return new JwtResponse(jws);
    }

    @RequestMapping(value = "/dynamic-builder-compress", method = POST)
    public JwtResponse dynamicBuildercompress(@RequestBody Map<String, Object> claims) throws UnsupportedEncodingException {
        String jws = Jwts.builder()
            .setClaims(claims)
            .compressWith(CompressionCodecs.DEFLATE)
            .signWith(SignatureAlgorithm.HS256, secretService.getHS256SecretBytes())
            .compact();
        return new JwtResponse(jws);
    }
--------------------------------------------------------------------------------------------------------

import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

public class Localization {

    public static String getLabel(Locale locale) {
        final ResourceBundle bundle = ResourceBundle.getBundle("messages", locale);
        return bundle.getString("label");
    }

    public static void run(List<Locale> locales) {
        locales.forEach(locale -> System.out.println(getLabel(locale)));
    }

}
--------------------------------------------------------------------------------------------------------

import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class CustomTakeWhile {

    public static <T> Stream<T> takeWhile(Stream<T> stream, Predicate<T> predicate) {
        CustomSpliterator<T> customSpliterator = new CustomSpliterator<>(stream.spliterator(), predicate);
        return StreamSupport.stream(customSpliterator, false);
    }

}
--------------------------------------------------------------------------------------------------------
import java.io.IOException;

import com.baeldung.jackson.enums.Distance;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class DistanceSerializer extends StdSerializer<Distance> {

    private static final long serialVersionUID = 1376504304439963619L;

    public DistanceSerializer() {
        super(Distance.class);
    }

    public DistanceSerializer(Class<Distance> t) {
        super(t);
    }

    public void serialize(Distance distance, JsonGenerator generator, SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();
        generator.writeFieldName("name");
        generator.writeString(distance.name());
        generator.writeFieldName("unit");
        generator.writeString(distance.getUnit());
        generator.writeFieldName("meters");
        generator.writeNumber(distance.getMeters());
        generator.writeEndObject();
    }
}
--------------------------------------------------------------------------------------------------------


spring.messages.basename=messages,config.i18n.messages
spring.messages.fallback-to-system-locale=false


--------------------------------------------------------------------------------------------------------


spring.resources.chain.strategy.content.enabled=true
spring.resources.chain.strategy.content.paths=/**
spring.resources.chain.strategy.fixed.enabled=true
spring.resources.chain.strategy.fixed.paths=/js/lib/
spring.resources.chain.strategy.fixed.version=v12



spring.mvc.contentnegotiation.favor-parameter=true

# We can change the parameter name, which is "format" by default:
# spring.mvc.contentnegotiation.parameter-name=myparam

# We can also register additional file extensions/media types with:
spring.mvc.contentnegotiation.media-types.markdown=text/markdown



spring.mvc.contentnegotiation.favor-parameter=true

# We can change the parameter name, which is "format" by default:
# spring.mvc.contentnegotiation.parameter-name=myparam

# We can also register additional file extensions/media types with:
spring.mvc.contentnegotiation.media-types.markdown=text/markdown



spring.mvc.contentnegotiation.favor-path-extension=true
spring.mvc.pathmatch.use-registered-suffix-pattern=true

# You can also register additional file extensions/media types with:
# spring.mvc.contentnegotiation.media-types.adoc=text/asciidoc


--------------------------------------------------------------------------------------------------------
src/
 +- main/
     +- java/
     |   + <source code>
     +- resources/
         +- public/
             +- error/
             |   +- 404.html
             +- <other public assets>
--------------------------------------------------------------------------------------------------------
src/
 +- main/
     +- java/
     |   + <source code>
     +- resources/
         +- templates/
             +- error/
             |   +- 5xx.ftlh
             +- <other templates>
--------------------------------------------------------------------------------------------------------


spring.webflux.static-path-pattern=/resources/**


--------------------------------------------------------------------------------------------------------
@Bean
public ErrorPageRegistrar errorPageRegistrar(){
    return new MyErrorPageRegistrar();
}

// ...

private static class MyErrorPageRegistrar implements ErrorPageRegistrar {

    @Override
    public void registerErrorPages(ErrorPageRegistry registry) {
        registry.addErrorPages(new ErrorPage(HttpStatus.BAD_REQUEST, "/400"));
    }
}

@Bean
public FilterRegistrationBean myFilter() {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(new MyFilter());
    ...
    registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
    return registration;
}
--------------------------------------------------------------------------------------------------------
public class CustomErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    // Define constructor here

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {

        return RouterFunctions
                .route(aPredicate, aHandler)
                .andRoute(anotherPredicate, anotherHandler);
    }

}
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.stereotype.Component;

@Component
public class CustomizationBean implements WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {

    @Override
    public void customize(ConfigurableServletWebServerFactory server) {
        server.setPort(9000);
    }

}
@Bean
public ConfigurableServletWebServerFactory webServerFactory() {
    TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
    factory.setPort(9000);
    factory.setSessionTimeout(10, TimeUnit.MINUTES);
    factory.addErrorPages(new ErrorPage(HttpStatus.NOT_FOUND, "/notfound.html"));
    return factory;
}
--------------------------------------------------------------------------------------------------------


spring.rsocket.server.mapping-path=/rsocket # a mapping path is defined
spring.rsocket.server.transport=websocket # websocket is chosen as a transport
#spring.rsocket.server.port= # no port is defined



spring.security.saml2.relyingparty.registration.my-relying-party1.signing.credentials[0].private-key-location=path-to-private-key
spring.security.saml2.relyingparty.registration.my-relying-party1.signing.credentials[0].certificate-location=path-to-certificate
spring.security.saml2.relyingparty.registration.my-relying-party1.identityprovider.verification.credentials[0].certificate-location=path-to-verification-cert
spring.security.saml2.relyingparty.registration.my-relying-party1.identityprovider.entity-id=remote-idp-entity-id1
spring.security.saml2.relyingparty.registration.my-relying-party1.identityprovider.sso-url=https://remoteidp1.sso.url

spring.security.saml2.relyingparty.registration.my-relying-party2.signing.credentials[0].private-key-location=path-to-private-key
spring.security.saml2.relyingparty.registration.my-relying-party2.signing.credentials[0].certificate-location=path-to-certificate
spring.security.saml2.relyingparty.registration.my-relying-party2.identityprovider.verification.credentials[0].certificate-location=path-to-other-verification-cert
spring.security.saml2.relyingparty.registration.my-relying-party2.identityprovider.entity-id=remote-idp-entity-id2
spring.security.saml2.relyingparty.registration.my-relying-party2.identityprovider.sso-url=https://remoteidp2.sso.url




# Number of ms to wait before throwing an exception if no connection is available.
spring.datasource.tomcat.max-wait=10000

# Maximum number of active connections that can be allocated from this pool at the same time.
spring.datasource.tomcat.max-active=50

# Validate the connection before borrowing it from the pool.
spring.datasource.tomcat.test-on-borrow=true



spring.data.mongodb.uri=mongodb://user:secret@mongo1.example.com:12345,mongo2.example.com:23456/test



spring.data.mongodb.host=mongoserver
spring.data.mongodb.port=27017



spring.data.neo4j.uri=bolt://my-server:7687
spring.data.neo4j.username=neo4j
spring.data.neo4j.password=secret



spring.data.neo4j.use-native-types=true



spring.data.neo4j.open-in-view=false

package com.example.myapp.domain;

import java.util.Optional;

import org.springframework.data.neo4j.repository.*;

public interface CityRepository extends Neo4jRepository<City, Long> {

    Optional<City> findOneByNameAndState(String name, String state);

}

spring.data.cassandra.keyspace-name=mykeyspace
spring.data.cassandra.contact-points=cassandrahost1,cassandrahost2



spring.couchbase.bootstrap-hosts=my-host-1,192.168.1.123
spring.couchbase.bucket.name=my-bucket
spring.couchbase.bucket.password=secret



spring.couchbase.env.timeouts.connect=3000
spring.couchbase.env.ssl.key-store=/location/of/keystore.jks
spring.couchbase.env.ssl.key-store-password=secret

@Configuration(proxyBeanMethods = false)
public class SomeConfiguration {

    @Bean(BeanNames.COUCHBASE_CUSTOM_CONVERSIONS)
    public CustomConversions myCustomConversions() {
        return new CustomConversions(...);
    }

    // ...

}
spring.ldap.embedded.base-dn:
  - dc=spring,dc=io
  - dc=pivotal,dc=io
--------------------------------------------------------------------------------------------------------


spring.influx.url=https://172.0.0.1:8086

https://cbor.io/
https://github.com/cbor/cbor.github.io/issues/new
https://rsocket.io/
https://github.com/rsocket
--------------------------------------------------------------------------------------------------------
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public enum WeatherStats {

    STATS_RAINY("Going to Rain, Take Umbrella"), STATS_HUMID("Going to be very humid, Take Water");

    private final String message;

    private static final List<WeatherStats> VALUES = Collections.unmodifiableList(Arrays.asList(values()));

    private static final int SIZE = VALUES.size();

    private static final Random RANDOM = new Random();

    WeatherStats(String msg) {
        this.message = msg;
    }

    public static WeatherStats forToday() {
        return VALUES.get(RANDOM.nextInt(SIZE));
    }

    public String getMessage() {
        return message;
    }

}

addSbtPlugin("com.lightbend.lagom" % "lagom-sbt-plugin" % "1.3.1")
addSbtPlugin("com.typesafe.sbteclipse" % "sbteclipse-plugin" % "3.0.0")
--------------------------------------------------------------------------------------------------------

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.monitor.FileAlterationListener;
import org.apache.commons.io.monitor.FileAlterationListenerAdaptor;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;

import java.io.File;

public class FileMonitor {

    public static void main(String[] args) throws Exception {
        File folder = FileUtils.getTempDirectory();
        startFileMonitor(folder);
    }

    /**
     * @param folder
     * @throws Exception
     */
    public static void startFileMonitor(File folder) throws Exception {
        FileAlterationObserver observer = new FileAlterationObserver(folder);
        FileAlterationMonitor monitor = new FileAlterationMonitor(5000);

        FileAlterationListener fal = new FileAlterationListenerAdaptor() {

            @Override
            public void onFileCreate(File file) {
                // on create action
            }

            @Override
            public void onFileDelete(File file) {
                // on delete action
            }
        };

        observer.addListener(fal);
        monitor.addObserver(observer);
        monitor.start();
    }
}
--------------------------------------------------------------------------------------------------------
#!/bin/bash

find . -maxdepth 1 -mindepth 1 -type d -printf '%f\n'

find . -maxdepth 1 -mindepth 1 -type d | while read dir; do
  echo "$dir"
done

find . -maxdepth 1 -type d -exec echo {} \;

#!/bin/bash

for dir in */; do
    echo "$dir"
done

for file in *; do
    if [ -d "$file" ]; then
        echo "$file"
    fi
done

#!/bin/bash

my_var="Hola Mundo"
echo ${my_var}

my_filename="interesting-text-file.txt"
echo ${my_filename:0:21}

echo ${my_filename%.*}

complicated_filename="hello-world.tar.gz"
echo ${complicated_filename%%.*}

echo ${my_filename/.*/}

echo 'interesting-text-file.txt' | sed 's/.txt*//'

echo 'interesting-text-file.txt' | cut -f1 -d"."
echo ${complicated_filename} | cut -f1 -d"."
--------------------------------------------------------------------------------------------------------
@Getter(lazy = true)


import lombok.Builder;

class ClientBuilder {

    @Builder(builderMethodName = "builder")
    public static ImmutableClient newClient(int id, String name) {
        return new ImmutableClient(id, name);
    }
}

@Builder(toBuilder = true)

import java.util.List;
import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

@Getter
@Builder
public class Sea {

    @Singular private final List<String> grasses;
    @Singular("oneFish") private final List<String> fish;
}
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
module com.baeldung.dip.services {
    requires com.baeldung.dip.entities;
    requires com.baeldung.dip.daos;
    uses com.baeldung.dip.daos.CustomerDao;
    exports com.baeldung.dip.services;
}
--------------------------------------------------------------------------------------------------------

    public static User getSingletonInstance(String name, String email, String country) {
        if (instance == null) {
            synchronized (User.class) {
                if (instance == null) {
                    instance = new User(name, email, country);
                }
            }
        }
        return instance;

    }
--------------------------------------------------------------------------------------------------------

public enum Operator {

    ADD {
        @Override
        public int apply(int a, int b) {
            return a + b;
        }
    },

    MULTIPLY {
        @Override
        public int apply(int a, int b) {
            return a * b;
        }
    },

    SUBTRACT {
        @Override
        public int apply(int a, int b) {
            return a - b;
        }
    },

    DIVIDE {
        @Override
        public int apply(int a, int b) {
            return a / b;
        }
    },

    MODULO {
        @Override
        public int apply(int a, int b) {
            return a % b;
        }
    };

    public abstract int apply(int a, int b);
}

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class RuleEngine {

    private static List<Rule> rules = new ArrayList<>();

    static {
        rules.add(new AddRule());
    }

    public Result process(Expression expression) {

        Rule rule = rules.stream()
            .filter(r -> r.evaluate(expression))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Expression does not matches any Rule"));
        return rule.getResult();
    }
}
--------------------------------------------------------------------------------------------------------
import io.github.resilience4j.retry.IntervalFunction;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.function.Function;

import static com.baeldung.backoff.jitter.BackoffWithJitterTest.RetryProperties.*;
import static io.github.resilience4j.retry.IntervalFunction.ofExponentialBackoff;
import static io.github.resilience4j.retry.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Collections.nCopies;
import static java.util.concurrent.Executors.newFixedThreadPool;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class BackoffWithJitterTest {

    static Logger log = LoggerFactory.getLogger(BackoffWithJitterTest.class);

    interface PingPongService {

        String call(String ping) throws PingPongServiceException;
    }

    class PingPongServiceException extends RuntimeException {

        public PingPongServiceException(String reason) {
            super(reason);
        }
    }

    private PingPongService service;
    private static final int NUM_CONCURRENT_CLIENTS = 8;

    @Before
    public void setUp() {
        service = mock(PingPongService.class);
    }

    @Test
    public void whenRetryExponentialBackoff_thenRetriedConfiguredNoOfTimes() {
        IntervalFunction intervalFn = ofExponentialBackoff(INITIAL_INTERVAL, MULTIPLIER);
        Function<String, String> pingPongFn = getRetryablePingPongFn(intervalFn);

        when(service.call(anyString())).thenThrow(PingPongServiceException.class);
        try {
            pingPongFn.apply("Hello");
        } catch (PingPongServiceException e) {
            verify(service, times(MAX_RETRIES)).call(anyString());
        }
    }

    @Test
    public void whenRetryExponentialBackoffWithoutJitter_thenThunderingHerdProblemOccurs() throws InterruptedException {
        IntervalFunction intervalFn = ofExponentialBackoff(INITIAL_INTERVAL, MULTIPLIER);
        test(intervalFn);
    }

    @Test
    public void whenRetryExponentialBackoffWithJitter_thenRetriesAreSpread() throws InterruptedException {
        IntervalFunction intervalFn = ofExponentialRandomBackoff(INITIAL_INTERVAL, MULTIPLIER, RANDOMIZATION_FACTOR);
        test(intervalFn);
    }

    private void test(IntervalFunction intervalFn) throws InterruptedException {
        Function<String, String> pingPongFn = getRetryablePingPongFn(intervalFn);
        ExecutorService executors = newFixedThreadPool(NUM_CONCURRENT_CLIENTS);
        List<Callable<String>> tasks = nCopies(NUM_CONCURRENT_CLIENTS, () -> pingPongFn.apply("Hello"));

        when(service.call(anyString())).thenThrow(PingPongServiceException.class);

        executors.invokeAll(tasks);
    }

    private Function<String, String> getRetryablePingPongFn(IntervalFunction intervalFn) {
        RetryConfig retryConfig = RetryConfig.custom()
                .maxAttempts(MAX_RETRIES)
                .intervalFunction(intervalFn)
                .retryExceptions(PingPongServiceException.class)
                .build();
        Retry retry = Retry.of("pingpong", retryConfig);
        return Retry.decorateFunction(retry, ping -> {
            log.info("Invoked at {}", LocalDateTime.now());
            return service.call(ping);
        });
    }

    static class RetryProperties {
        static final Long INITIAL_INTERVAL = 1000L;
        static final Double MULTIPLIER = 2.0D;
        static final Double RANDOMIZATION_FACTOR = 0.6D;
        static final Integer MAX_RETRIES = 4;
    }
}
--------------------------------------------------------------------------------------------------------
import com.baeldung.Constants;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;

@Controller
public class ResponseBodyEmitterController {
    private ExecutorService nonBlockingService = Executors.newCachedThreadPool();

    @GetMapping(Constants.API_RBE)
    public ResponseEntity<ResponseBodyEmitter> handleRbe() {
        ResponseBodyEmitter emitter = new ResponseBodyEmitter();

            nonBlockingService.execute(() -> {
                try {
                    emitter.send(Constants.API_RBE_MSG + " @ " + new Date(), MediaType.TEXT_PLAIN);
                    emitter.complete();
                } catch (Exception ex) {
                      System.out.println(Constants.GENERIC_EXCEPTION);
                      emitter.completeWithError(ex);
                }
            });

            return new ResponseEntity(emitter, HttpStatus.OK);
        }
}
--------------------------------------------------------------------------------------------------------
language: java
sudo: false
install: true

addons:
  sonarcloud:
    organization: "kakawait-github"
    branches:
      - master
      - develop
      - /^release\/.*$/
    token:
      secure: "yghqOuzw0Hov/i82t2CF7MlS8ifAQI1St3Bx3ZQ2yCer2sx5gBSZuJ12sWBJPsfnECxh2XLCHklud1maR1NOJPcogYSzF0Mm+/ymowGDXzwBmeO6ulEIXHWNyG9QSdZCvZtyvYEdXqErntsN4MnGWiGm0526n0qAv2sQE77MDBVTupbXGkqmwYe3vcDXuoRLUWVat4gop5A1tkdlu5LWXqn5tzylCJzDZ7VXD2eR+Cf7n0k/KMYA2MSFDUMBZWZzzj9O1lwhSkZystqlPo7ZL8UPUL/CpqsObdSWfeZVJG0VxfAbJxlSoHNi+KbffjyStPmIRGjgDIr8aWUANcwxmW2G2VDn898ZhvD+C7n1BiDqbKgbJRrhM8aG4klW3odE0gMcLEO3mOuqzT7p8h4IeeZCIFdr9wwsInXNnAfwDISCDiPTacUmM/DKwVDSBZTNxvi+tS1mwwoqphn1xc6ePnTx4RF/pvxNjLbGBEzToVmAAX7ViiU4MS/RDGPbxA/b0qVsgZWF0v9pD4uSb0O++fNtTAPObAnGOB9RUs5FEBtzIxBtw51oV0eyS7CffMLF+dkcxLzo0hj7UCnUpzotee/ydVMIc/K83NJZGlxy02NgdDEi5pxGJOyJyxV0s5F2DINCl4kuliqgxxjlyVvEgQAJ8gObGQkhQdA8Ax5qoqM="

jdk:
  - oraclejdk8

script:
  - mvn clean org.jacoco:jacoco-maven-plugin:prepare-agent package sonar:sonar

cache:
  directories:
    - '$HOME/.m2/repository'
    - '$HOME/.sonar/cache'
--------------------------------------------------------------------------------------------------------
@Command(name = "checksum", mixinStandardHelpOptions = true, version = "checksum 4.0",
         description = "Prints the checksum (MD5 by default) of a file to STDOUT.")
class CheckSum implements Callable<Integer> {

    @Parameters(index = "0", description = "The file whose checksum to calculate.")
    private File file;

    @Option(names = {"-a", "--algorithm"}, description = "MD5, SHA-1, SHA-256, ...")
    private String algorithm = "MD5";

    // this example implements Callable, so parsing, error handling and handling user
    // requests for usage help or version help can be done with one line of code.
    public static void main(String... args) {
        int exitCode = new CommandLine(new CheckSum()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception { // your business logic goes here...
        byte[] fileContents = Files.readAllBytes(file.toPath());
        byte[] digest = MessageDigest.getInstance(algorithm).digest(fileContents);
        System.out.printf("%0" + (digest.length*2) + "x%n", new BigInteger(1, digest));
        return 0;
    }
}
--------------------------------------------------------------------------------------------------------
class Login implements Callable<Integer> {
    @Option(names = {"-u", "--user"}, description = "User name")
    String user;

    @Option(names = {"-p", "--password"}, description = "Passphrase", interactive = true)
    char[] password;

    public Integer call() throws Exception {
        byte[] bytes = new byte[password.length];
        for (int i = 0; i < bytes.length; i++) { bytes[i] = (byte) password[i]; }

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes);

        System.out.printf("Hi %s, your password is hashed to %s.%n", user, base64(md.digest()));

        // null out the arrays when done
        Arrays.fill(bytes, (byte) 0);
        Arrays.fill(password, ' ');

        return 0;
    }

    private String base64(byte[] arr) { /* ... */ }
}
new CommandLine(new Login()).execute("-u", "user123", "-p");
--------------------------------------------------------------------------------------------------------
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
--------------------------------------------------------------------------------------------------------
    public static short[] ByteArrayToShortArray(byte[] input)
    {
        int short_index, byte_index;
        int iterations = input.length;

        short[] output = new short[input.length / 2];
        short_index = byte_index = 0;

        for(int i=0; i < input.length /2 ; i++)
        {
            output[i] = (short) (((short)input[i*2] & 0xFF) + (((short)input[i*2+1] & 0xFF) << 8));
        }
        return output;
    }
--------------------------------------------------------------------------------------------------------
org.springframework.boot.env.EnvironmentPostProcessor=org.springframework.boot.env.MockWebServerEnvironmentPostProcessor
--------------------------------------------------------------------------------------------------------
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * @author Rob Winch
 */
public class MockWebServerEnvironmentPostProcessor implements EnvironmentPostProcessor, DisposableBean {

    private final MockWebServerPropertySource propertySource = new MockWebServerPropertySource();

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        environment.getPropertySources().addFirst(this.propertySource);
    }

    @Override
    public void destroy() throws Exception {
        this.propertySource.destroy();
    }
}
--------------------------------------------------------------------------------------------------------
language: java
dist: trusty
git:
  depth: false
  quiet: true
  submodules: false
  lfs_skip_smudge: true
sudo: false
branches:
  only:
    - master
    - stable
jdk:
  - oraclejdk8
  - openjdk8
addons:
  sonarcloud:
    organization: "alexrogalskiy-github"
    token:
      secure:
      ##"EFloHmTj8WE5g+NJ0OPbXFYF5+YZ+az4K5seJgCjY+dxw8CbwyNCZPc0rxRbzxevf00hg/OywEfWQM1x9g6JuPvVeoR51kkqF1Ved7gTl4Xi5s7hLYltq2U/4e+iDPyRBJehelw1sclSSgQPQ66YDWlRq9zAT/9NJcz4Nbp89mTwZ9jrOPepy8U0iXwVg167OJhUWowGdv+g3Ffn0ZsuEXJ92XMgd3c7ypb39/c3W72rmL2iNNa/FdtIVRAmOS89371CFdh8vUx8qTGgUyofXfkJTnh1Ha8gf1taZTZsdnfgy9cL3S6wq/rpbbyxMnC6A8JpKRxPgXPCjVGPFgZWzQol8UpiNftnoR/7y4+q6cQJ1Nlo/NEdx+liXK6+WC96tzApf/8Wrsx7pYxSLEExSzeAb8gnSVY/qh9K5Ix8jcyPQPYWNrv8Lo59sbg5f0Lzg5qMAvk6FBJwvB/QCSD+ZUSCEvjhLBhugv9xi+UVVEzcMJMm7yFVeskBoInngD1rjIeZvA8asppJALHw7a9sluJvLQlntd0QYZlYipSwj9ayJYYXdn1sxxeUA2Ldlq9JhUHYo1oAIfD+varTYEksf7XJsCkc3HnlBW1rPdnUG5NHvFcwn2Y0lPcH7AZsL8duIiriq3OGEa9m/4OybkLlxvbKo/RVfp11vUSpJJZpdqk="
  apt:
    update: true
    packages:
      - oracle-java8-installer
before_install: echo "MAVEN_OPTS='-Xmx2048m -XX:MaxPermSize=512m'" > ~/.mavenrc
install: true
before_script:
  - pip install --user codecov
  - curl http://www.jpm4j.org/install/script | sh
script:
  - mvn -U -B -V test --fail-at-end -Dsource.skip=true -Dmaven.javadoc.skip=true
  - mvn cobertura:cobertura
  - mvn sonar:sonar -Dsonar.projectKey=AlexRogalskiy_AnsiFancy -Dsonar.organization=alexrogalskiy-github -Dsonar.host.url=https://sonarcloud.io -Dsonar.login=$SONAR_TOKEN
after_success:
  - mvn clean test jacoco:report
  - codecov --build "$TRAVIS_JOB_NUMBER-jdk8"
  - bash <(curl -s https://codecov.io/bash) -t $CODECOV_TOKEN
notifications:
  email:
    on_success: change
    on_failure: always
env:
  global:
    - secure: "YNE9GjEV52M9LawKTHLTgNcc8n7LG6884Xq2VGNstdz4xtqphunCZKWpVAPIDKrMdJDjZvji7PT1uZz7aleypSI3sXLjYjvXaGQ3bZ2G9zqCfMfHFTbAb1oW0zhy27gFsQ0+8/EvEd5xNrEuniBbo5ZRMz1WuHLSQvNiiR6QntCziTn0lgvrbnpsX1tFlWIONxvnaMcDFYyV7gDEODDn45ese05wAcqEl2tQBUfMu5BJZ1cw40qvuhfEK+M4Kui6/bcZZbCIRe0We0m4RlFx04G6xZ1GstQJCVDFIi7lZXY55EqAm+7d/XMQoCmmElEWV81GajyH1LOWZL9gq4ZED1TKSZUQcuWVIfANHpNxCzTNZ9fqD4g/MTa0rG2xfBJYcPd58eXuo2xWzZ/Wbkx5kFWr0xegG+6ctiySV7f4uy85n5V1loLTVOFLegJu00uGl4j6o0hHfE8Qc9+DupDB3WgPkKOW9ZMJGgT6v47uYr1qGnze9FhBMboFUPlbDEbbYdCrch4op9v/w1fzegX6QMWcDVa1nqTJ8uG7pbATkIk2AvAbDbofBtDcWq3neXr8zp2hdb/RIa6jeReGhIHiQ8eckhRoOW+eC3omOlqkX2+6rxoH3JtU4eSBovzXkOiq50xsm/vmzhCcLFlLEhyTV1GUQN8SzLzizanTtcAw6y0="
cache:
  directories:
    - "$HOME/.m2/repository"
    - "$HOME/.sonar/cache"
--------------------------------------------------------------------------------------------------------
import de.pearl.pem.common.validation.model.OffsetPageRequest;
import de.pearl.pem.common.validation.validator.OffsetPageRequestValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
public class OffsetPageHandler {

    public Mono<ServerResponse> handleRequest(final ServerRequest request) {
        final Validator validator = new OffsetPageRequestValidator();
        final Mono<String> responseBody = request.bodyToMono(OffsetPageRequest.class)
            .map(body -> {
                final Errors errors = new BeanPropertyBindingResult(body, OffsetPageRequest.class.getName());
                validator.validate(body, errors);

                if (Objects.isNull(errors) || errors.getAllErrors().isEmpty()) {
                    return String.format("{%s}: offset: [%s], page number: [%s], page size: [%s], sort: [%s]", getClass().getCanonicalName(), body.getOffset(), body.getPageNumber(), body.getPageSize(), body.getSort());
                }
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, errors.getAllErrors().toString());
            });
        return ServerResponse
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(responseBody, String.class);
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.context.annotation.Configuration;
import org.springframework.hateoas.config.EnableHypermediaSupport;
import org.springframework.hateoas.config.EnableHypermediaSupport.HypermediaType;

/**
 * Separate configuration class to enable Spring Hateoas functionality if the {@code hateoas} profile is activated.
 */
@Configuration
//@Profile("hateoas")
@EnableHypermediaSupport(type = HypermediaType.HAL)
public class MediaConfiguration {
}
--------------------------------------------------------------------------------------------------------

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.util.Locale;

/**
 * Application configuration
 */
@Configuration
public class AppConfig {

//    @Bean
//    public ModelMapper modelMapper() {
//        return new ModelMapper();
//    }

    @Bean
    public ObjectMapper jsonObjectMapper() {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setDefaultMergeable(Boolean.TRUE);
        objectMapper.setLocale(Locale.getDefault());
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

        objectMapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
        objectMapper.enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
        objectMapper.enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);
        objectMapper.enable(JsonGenerator.Feature.ESCAPE_NON_ASCII);

        objectMapper.disable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.disable(DeserializationFeature.UNWRAP_ROOT_VALUE);
        objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        objectMapper.enable(SerializationFeature.WRITE_ENUMS_USING_TO_STRING);
        objectMapper.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);
        //objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return objectMapper;
    }

    @Bean
    public ObjectMapper jacksonObjectMapper() {
        final Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.indentOutput(true);
        builder.autoDetectFields(true);
        return builder.build();
    }

    //    @Bean
//    public ServletListenerRegistrationBean<HttpSessionListener> httpSessionCreatedListener() {
//        ServletListenerRegistrationBean<HttpSessionListener> listenerRegistrationBean = new ServletListenerRegistrationBean<>();
//        listenerRegistrationBean.setListener(new HttpSessionCreatedListener());
//        return listenerRegistrationBean;
//    }
//    @Bean
//    public FilterRegistrationBean noHttpSessionFilter() {
//        FilterRegistrationBean registration = new FilterRegistrationBean();
//        registration.setFilter(new NoHttpSessionFilter());
//        registration.addUrlPatterns("/*");
//        return registration;
//    }
//    @Bean
//    @Autowired
//    public CookieSecurityContextRepository securityContextRepository(final String sessionEncryptionKeyBase64) {
//        return new CookieSecurityContextRepository(new JwtEncryption(""));
//    }
//
//    @Bean
//    public CookieRequestCache cookieRequestCache() {
//        return new CookieRequestCache();
//    }
//
//    @Bean
//    public FilterRegistrationBean httpsOnlyFilter() {
//        FilterRegistrationBean registration = new FilterRegistrationBean();
//        registration.setFilter(new HttpsOnlyFilter());
//        registration.addUrlPatterns("/*");
//        return registration;
//    }
}
--------------------------------------------------------------------------------------------------------
@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DEFAULT_DATE_FORMAT_PATTERN_EXT, locale = DEFAULT_DATE_FORMAT_LOCALE)
--------------------------------------------------------------------------------------------------------
import java.sql.SQLException;

import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;

public interface MyService {

    @Retryable
    void retryService();

    @Retryable(value = { SQLException.class }, maxAttempts = 2, backoff = @Backoff(delay = 5000))
    void retryServiceWithRecovery(String sql) throws SQLException;

    @Recover
    void recover(SQLException e, String sql);

    void templateRetryService();
}
--------------------------------------------------------------------------------------------------------
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@EqualsAndHashCode
@ToString
public class SessionCountListener implements HttpSessionListener {

    private final AtomicInteger sessionCount = new AtomicInteger();

    @Override
    public void sessionCreated(final HttpSessionEvent se) {
        this.sessionCount.incrementAndGet();
        setActiveSessionCount(se);
    }

    @Override
    public void sessionDestroyed(final HttpSessionEvent se) {
        this.sessionCount.decrementAndGet();
        setActiveSessionCount(se);
    }

    private void setActiveSessionCount(final HttpSessionEvent se) {
        se.getSession().getServletContext().setAttribute("activeSessions", this.sessionCount.get());
        System.out.println("Total Active Session: " + this.sessionCount.get());
    }
}
--------------------------------------------------------------------------------------------------------
package jcg.zheng.demo.web.service;
 
import java.util.List;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
 
import jcg.zheng.demo.web.api.UserResource;
import jcg.zheng.demo.web.data.User;
 
@Component
public class UserResourceImpl implements UserResource {
 
    @Autowired
    private UserService userSrv;
 
    @Override
    // @RequiresPermissions(type = "role", value = "10")
    public User createUser(User user) {
        return userSrv.saveUser(user);
    }
 
    @Override
//  @RequiresPermissions(type = "role", value = "1")
    public List<User> getUsers() {
        return userSrv.getUsers();
    }
}
--------------------------------------------------------------------------------------------------------
package jcg.zheng.demo.customannotation;
 
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
 
//Retained at runtime (so we can use them with Reflection).
//Applied to a method
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD )
public @interface RequiresPermissions {
 String type() default "";
 
 String value() default "";
}


package jcg.zheng.demo.web.security;
 
import java.io.IOException;
import java.util.List;
 
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.CollectionUtils;
 
import jcg.zheng.demo.customannotation.RequiresPermissions;
import jcg.zheng.demo.web.data.User;
import jcg.zheng.demo.web.service.UserService;
 
public class RequiresPermissionsFilter implements ContainerRequestFilter {
 
    private static final String SUPER_USER = "MZheng";
 
    @Context
    private ApplicationContext applicationContext;
 
    @Context
    private ResourceInfo resourceInfo;
 
    @Autowired
    private UserService userSrv;
 
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        RequiresPermissions annotation = AnnotationUtils.findAnnotation(resourceInfo.getResourceMethod(),
                RequiresPermissions.class);
        if (annotation != null) {
            MultivaluedMap<String, String> headers = requestContext.getHeaders();
            processPermission(headers, annotation);
        }
 
    }
 
    private void processPermission(MultivaluedMap<String, String> headers, RequiresPermissions permission) {
        String permissionValue = permission.value();
        String permissionType = permission.type();
        if ("role".equalsIgnoreCase(permissionType)) {
            // need to check the header user id's role match to the permission role
            List<String> requestUserId = headers.get("requestUserId");
            if (CollectionUtils.isEmpty(requestUserId)) {
                throw new NotAuthorizedException("Missing security header");
            }
 
            if (!requestUserId.get(0).equalsIgnoreCase(SUPER_USER)) {
                Integer requestUserNum = Integer.valueOf(requestUserId.get(0));
                User requestUser = userSrv.getUser(requestUserNum);
                if (requestUser == null) {
                    throw new NotAuthorizedException("Invalid requestUserId");
                }
                Integer userRoleInt = Integer.valueOf(requestUser.getRole());
                Integer permissionRoleInt = Integer.valueOf(permissionValue);
                if (userRoleInt < permissionRoleInt) {
                    throw new NotAuthorizedException(
                            "Not Authorized for the method, request user must have a role=" + permissionValue);
                }
            }
        }
    }
}
--------------------------------------------------------------------------------------------------------
/* parse each line */CSVParserparser=CSVParser.parse(line,CSVFormat.RFC4180);for(CSVRecordcr:parser){intid=cr.get(1);// columns start at 1 not 0 !!!intyear=cr.get(2);Stringcity=cr.get(3);}

JSONParserparser=newJSONParser();try{JSONObjectjObj=(JSONObject)parser.parse(newFileReader("data.json"));// TODO do something with jObj}catch(IOException|ParseExceptione){System.err.println(e.getMessage());}

JSONParserparser=newJSONParser();try{JSONArrayjArr=(JSONArray)parser.parse(newFileReader("data.json"));// TODO do something with jObj}catch(IOException|ParseExceptione){System.err.println(e.getMessage());}
--------------------------------------------------------------------------------------------------------
/**
 * uses hashing trick to store terms in large hashmap to avoid collisions
 * @author Michael Brzustowicz
 */
public class HashingDictionary implements Dictionary {
    private int numTerms; // 2^n is optimal

    public HashingDictionary() {
        // 2^20 = 1048576
        this(new Double(Math.pow(2,20)).intValue());
    }

    public HashingDictionary(int numTerms) {
        this.numTerms = numTerms;
    }
    
    @Override
    public Integer getTermIndex(String term) {
        return Math.floorMod(term.hashCode(), numTerms);
    }

    @Override
    public int getNumTerms() {
        return numTerms;
    }
}
--------------------------------------------------------------------------------------------------------
java --module-path com.jdojo.policy\build\classes;com.jdojo.claim\build\classes --module com.jdojo.claim/com.jdojo.claim.Main

FOR /F "tokens=1 delims=" %%A in ('dir com.jdojo.policy\src\*.java /S /B') do javac -d com.jdojo.policy\build\classes %%A

FOR /F "tokens=1 delims=" %%A in ('dir com.jdojo.intro\src\*.java /S /B') do javac --module-path com.jdojo.intro\build\classes -d com.jdojo.intro\build\classes %%A

FOR /F "tokens=1 delims=" %%A in ('dir com.jdojo.claim\src\*.java /S /B') do javac --module-path com.jdojo.policy\build\classes -d com.jdojo.claim\build\classes %%A

FOR /F "tokens=1 delims=" %%A in ('dir src\*.java /S /B') do javac -d build\classes %%A
--------------------------------------------------------------------------------------------------------
import jdk.incubator.http.HttpHeaders;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;

/**
 * Implementation of HttpHeaders.
 */
public class HttpHeadersImpl implements HttpHeaders {

    private final TreeMap<String,List<String>> headers;

    public HttpHeadersImpl() {
        headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    @Override
    public Optional<String> firstValue(String name) {
        List<String> l = headers.get(name);
        return Optional.ofNullable(l == null ? null : l.get(0));
    }

    @Override
    public List<String> allValues(String name) {
        return headers.get(name);
    }

    @Override
    public Map<String, List<String>> map() {
        return Collections.unmodifiableMap(headers);
    }

    public Map<String, List<String>> directMap() {
        return headers;
    }

    // package private mutators

    public HttpHeadersImpl deepCopy() {
        HttpHeadersImpl h1 = new HttpHeadersImpl();
        TreeMap<String,List<String>> headers1 = h1.headers;
        Set<String> keys = headers.keySet();
        for (String key : keys) {
            List<String> vals = headers.get(key);
            List<String> vals1 = new ArrayList<>(vals);
            headers1.put(key, vals1);
        }
        return h1;
    }

    public void addHeader(String name, String value) {
        headers.computeIfAbsent(name, k -> new ArrayList<>(1))
               .add(value);
    }

    public void setHeader(String name, String value) {
        List<String> values = new ArrayList<>(1); // most headers has one value
        values.add(value);
        headers.put(name, values);
    }

    @Override
    public OptionalLong firstValueAsLong(String name) {
        List<String> l = headers.get(name);
        if (l == null) {
            return OptionalLong.empty();
        } else {
            String v = l.get(0);
            return OptionalLong.of(Long.parseLong(v));
        }
    }

    public void clear() {
        headers.clear();
    }
}
--------------------------------------------------------------------------------------------------------
public static void startProcess(ProcessBuilder.Redirect outputDest) {                try {            ProcessBuilder pb = new ProcessBuilder()                    .command("java", "-version")                                        .redirectOutput(outputDest)                    .redirectError(outputDest);            Process process = pb.start();            process.waitFor();        } catch (IOException | InterruptedException e) {            e.printStackTrace();        }    }

-Xlint:unchecked
java -Xlog:gc*=debug,exit*=off --module-path com.jdojo.intro\dist--module com.jdojo.intro/com.jdojo.intro.Welcome
java -Xlog:gc=trace:stdout:level,time,tags--module-path com.jdojo.intro\dist--module com.jdojo.intro/com.jdojo.intro.Welcome

public static void testFlatMapping(){        Map<String,Set<List<String>>> langByDept = Employee.employees()                .stream()                .collect(groupingBy(Employee::getDepartment,                                mapping(Employee::getSpokenLanguages, toSet())));                        System.out.println("Languages spoken by department using mapping():");        System.out.println(langByDept);        Map<String,Set<String>> langByDept2 = Employee.employees()                .stream()                .collect(groupingBy(Employee::getDepartment,                                flatMapping(e -> e.getSpokenLanguages().stream(), toSet())));          System.out.println("\nLanguages spoken by department using flapMapping():");        System.out.println(langByDept2) ;           }
et<String> nonNullvalues = map.entrySet()           .stream()                      .flatMap(e ->  e.getValue() == null ? Stream.empty() : Stream.of(e.getValue()))           .collect(toSet());

javac -Xlint:deprecation -d ..\build\classes com\jdojo\deprecation\ImportDeprecationWarning.java
jdeprscan --list --release 8

public static void main(String[] args) {        // Create an array of snippets to evaluate/execute        // them sequentially        String[] snippets = { "int x = 100;",                              "double x = 190.89;",                              "long multiply(int value) {return value * multiplier;}",                              "int multiplier = 2;",                              "multiply(200)",                              "mul(99)"                            };        try (JShell shell = JShell.create()) {            // Register a snippet event handler            shell.onSnippetEvent(JShellApiTest::snippetEventHandler);            // Evaluate all snippets            for(String snippet : snippets) {                shell.eval(snippet);                System.out.println("------------------------");            }        }    }

try (JShell shell = JShell.create()) {    // Create a snippet    String snippet = "int x = 100;";    shell.eval(snippet)         .forEach((SnippetEvent se) -> {              Snippet s = se.snippet();              System.out.printf("Snippet: %s%n", s.source());              System.out.printf("Kind: %s%n", s.kind());              System.out.printf("Sub-Kind: %s%n", s.subKind());              System.out.printf("Previous Status: %s%n", se.previousStatus());              System.out.printf("Current Status: %s%n", se.status());              System.out.printf("Value: %s%n", se.value());        });}
--------------------------------------------------------------------------------------------------------
jshell> /set mode silent|  /set mode silent -quiet|  /set prompt silent "-> " ">> "|  /set format silent display ""|  /set format silent err "%6$s"|  /set format silent errorline "    {err}%n

|  /set format silent errorpost "%n"|  /set format silent errorpre "|  "|  /set format silent errors "%5$s"|  /set format silent name "%1$s"|  /set format silent post "%n"|  /set format silent pre "|  "|  /set format silent type "%2$s"|  /set format silent unresolved "%4$s"|  /set format silent value "%3$s"|  /set truncation silent 80|  /set truncation silent 1000 expression,varvalue

• /set start [-retain] <file>• /set start [-retain] -default• /set start [-retain] -none
--------------------------------------------------------------------------------------------------------
public enum TradingSignal {
	LONG, SHORT, NONE;

	public TradingSignal flip() {
		switch (this) {
		case LONG:
			return SHORT;
		case SHORT:
			return LONG;
		default:
			return this;
		}
	}
}

import org.joda.time.DateTime;

import com.precioustech.fxtrading.instrument.TradeableInstrument;

public class Price<T> {
	private final TradeableInstrument<T> instrument;
	private final double bidPrice, askPrice;
	private final DateTime pricePoint;

	public TradeableInstrument<T> getInstrument() {
		return instrument;
	}

	public double getBidPrice() {
		return bidPrice;
	}

	public double getAskPrice() {
		return askPrice;
	}

	public DateTime getPricePoint() {
		return pricePoint;
	}

	public Price(TradeableInstrument<T> instrument, double bidPrice, double askPrice, DateTime pricePoint) {
		this.instrument = instrument;
		this.bidPrice = bidPrice;
		this.askPrice = askPrice;
		this.pricePoint = pricePoint;
	}
}

import org.joda.time.DateTime;

import com.google.common.eventbus.EventBus;
import com.precioustech.fxtrading.instrument.TradeableInstrument;

/**
 * A callback handler for a market data event. The separate streaming event
 * handler upstream, is responsible for handling and parsing the incoming event
 * from the market data source and invoke the onMarketEvent of this handler,
 * which in turn can disseminate the event if required, further downstream.
 * Ideally, the implementer of this interface, would drop the event on a queue
 * for asynchronous processing or use an event bus for synchronous processing.
 * 
 * @author Shekhar Varshney
 *
 * @param <T>
 *            The type of instrumentId in class TradeableInstrument
 * @see TradeableInstrument
 * @see EventBus
 */
public interface MarketEventCallback<T> {
	/**
	 * A method, invoked by the upstream handler of streaming market data
	 * events. This invocation of this method is synchronous, therefore the
	 * method should return asap, to make sure that the upstream events do not
	 * queue up.
	 * 
	 * @param instrument
	 * @param bid
	 * @param ask
	 * @param eventDate
	 */
	void onMarketEvent(TradeableInstrument<T> instrument, double bid, double ask, DateTime eventDate);
}

import org.joda.time.DateTime;

import com.google.common.eventbus.EventBus;
import com.precioustech.fxtrading.instrument.TradeableInstrument;

public class MarketEventHandlerImpl<T> implements MarketEventCallback<T> {

	private final EventBus eventBus;

	public MarketEventHandlerImpl(EventBus eventBus) {
		this.eventBus = eventBus;
	}

	@Override
	public void onMarketEvent(TradeableInstrument<T> instrument, double bid, double ask, DateTime eventDate) {
		MarketDataPayLoad<T> payload = new MarketDataPayLoad<T>(instrument, bid, ask, eventDate);
		eventBus.post(payload);

	}
}


public enum CandleStickGranularity {

	S5(5, "5 seconds"), // 5s
	S10(10, "10 seconds"), // 10s
	S15(15, "15 seconds"), // 15s
	S30(30, "30 seconds"), // 30s
	M1(60 * 1, "1 minute"), // 1min
	M2(60 * 2, "2 minutes"), // 2mins
	M3(60 * 3, "3 minutes"), // 3mins
	M5(60 * 5, "5 minutes"), // 5mins
	M10(60 * 10, "10 minutes"), // 10mins
	M15(60 * 15, "15 minutes"), // 15mins
	M30(60 * 30, "30 minutes"), // 30mins
	H1(60 * 60, "1 hour"), // 1hr
	H2(60 * 60 * 2, "2 hours"), // 2hr
	H3(60 * 60 * 3, "3 hours"), // 3hr
	H4(60 * 60 * 4, "4 hours"), // 4hr
	H6(60 * 60 * 6, "6 hours"), // 6hr
	H8(60 * 60 * 8, "8 hours"), // 8hr
	H12(60 * 60 * 12, "12 hours"), // 12hr
	D(60 * 60 * 24, "1 day"), // 1day
	W(60 * 60 * 24 * 7, "1 week"), // 1wk
	M(60 * 60 * 24 * 30, "1 month");// 1mth

	private final long granularityInSeconds;
	private final String label;

	private CandleStickGranularity(long granularityInSeconds, String label) {
		this.granularityInSeconds = granularityInSeconds;
		this.label = label;
	}

	public long getGranularityInSeconds() {
		return granularityInSeconds;
	}

	public String getLabel() {
		return label;
	}

	public String getName() {
		return name();
	}
}
--------------------------------------------------------------------------------------------------------
public class ConcurrentObjectAccumulator implements        BiConsumer<List<Product>, Path> {    private String word;    public ConcurrentObjectAccumulator(String word) {        this.word = word;    }

@Override    public void accept(List<Product> list, Path path) {        Product product=ProductLoader.load(path);        if (product.getTitle().toLowerCase().contains           (word.toLowerCase())) {            list.add(product);        }    }}
--------------------------------------------------------------------------------------------------------
import org.junit.Test;
import org.openqa.selenium.By;

import static com.codeborne.selenide.Selenide.*;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;

public class SelenideTest {
    @Test
    public void wikipediaSearchFeature() throws InterruptedException {
        // Opening Wikipedia page
        open("http://en.wikipedia.org/wiki/Main_Page");

        // Searching TDD
        $(By.name("search")).setValue("Test-driven development");

        // Clicking search button
        $(By.name("go")).click();

        // Checks
        assertThat(title(), startsWith("Test-driven development"));
    }
}


import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxDriver;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;

public class SeleniumTest {
    @Test
    public void wikipediaSearchFeature() throws InterruptedException {
        // Declaring the web driver used for web browsing
        WebDriver driver = new FirefoxDriver();

        // Opening Wikipedia page
        driver.get("http://en.wikipedia.org/wiki/Main_Page");

        // Searching TDD
        WebElement query = driver.findElement(By.name("search"));
        query.sendKeys("Test-driven development");

        // Clicking search button
        WebElement goButton = driver.findElement(By.name("go"));
        goButton.click();

        // Checks
        assertThat(driver.getTitle(), startsWith("Test-driven development"));

        driver.quit();
    }
}


import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.openqa.selenium.By;

import static com.codeborne.selenide.Selenide.*;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

public class WebSteps {
    @Given("^I go to Wikipedia homepage$")
    @org.jbehave.core.annotations.Given("I go to Wikipedia homepage")
    public void goToWikiPage() {
        open("http://en.wikipedia.org/wiki/Main_Page");
    }

    @When("^I enter the value (.*) on a field named (.*)$")
    @org.jbehave.core.annotations.When("I enter the value $value on a field named $fieldName")
    public void enterValueOnFieldByName(String value, String fieldName){
        $(By.name(fieldName)).setValue(value);
    }

    @When("^I click the button (.*)$")
    @org.jbehave.core.annotations.When("I click the button $buttonName")
    public void clickButonByName(String buttonName){
        $(By.name(buttonName)).click();
    }

    @Then("^the page title contains (.*)$")
    @org.jbehave.core.annotations.Then("the page title contains $title")
    public void pageTitleIs(String title) {
        assertThat(title(), containsString(title));
    }

}
--------------------------------------------------------------------------------------------------------
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.togglz.console.TogglzConsoleServlet;
import org.togglz.core.Feature;
import org.togglz.core.activation.ActivationStrategyProvider;
import org.togglz.core.activation.DefaultActivationStrategyProvider;
import org.togglz.core.manager.CompositeFeatureProvider;
import org.togglz.core.manager.EnumBasedFeatureProvider;
import org.togglz.core.manager.FeatureManager;
import org.togglz.core.manager.FeatureManagerBuilder;
import org.togglz.core.manager.PropertyFeatureProvider;
import org.togglz.core.repository.StateRepository;
import org.togglz.core.repository.cache.CachingStateRepository;
import org.togglz.core.repository.composite.CompositeStateRepository;
import org.togglz.core.repository.file.FileBasedStateRepository;
import org.togglz.core.repository.mem.InMemoryStateRepository;
import org.togglz.core.spi.ActivationStrategy;
import org.togglz.core.spi.FeatureProvider;
import org.togglz.core.user.NoOpUserProvider;
import org.togglz.core.user.UserProvider;
import org.togglz.spring.boot.autoconfigure.TogglzProperties.FeatureSpec;
import org.togglz.spring.listener.TogglzApplicationContextBinderApplicationListener;
import org.togglz.spring.listener.TogglzApplicationContextBinderApplicationListener.ContextRefreshedEventFilter;
import org.togglz.spring.security.SpringSecurityUserProvider;
import org.togglz.spring.web.FeatureInterceptor;

import com.github.heneke.thymeleaf.togglz.TogglzDialect;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for Togglz.
 *
 * @author Marcel Overdijk
 */
@Configuration
@ConditionalOnProperty(prefix = "togglz", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(TogglzProperties.class)
public class TogglzAutoConfiguration {

    @Bean
    public TogglzApplicationContextBinderApplicationListener togglzApplicationContextBinderApplicationListener(
        ObjectProvider<ContextRefreshedEventFilter> contextRefreshedEventFilter) {
        return new TogglzApplicationContextBinderApplicationListener(contextRefreshedEventFilter.getIfAvailable());
    }

    @Configuration
    @ConditionalOnMissingBean(FeatureProvider.class)
    protected static class FeatureProviderConfiguration {

        @Autowired
        private TogglzProperties properties;

        @Bean
        public FeatureProvider featureProvider() {
            PropertyFeatureProvider provider = new PropertyFeatureProvider(properties.getFeatureProperties());
            Class<? extends Feature>[] featureEnums = properties.getFeatureEnums();
            if (featureEnums != null && featureEnums.length > 0) {
                return new CompositeFeatureProvider(new EnumBasedFeatureProvider(featureEnums), provider);
            } else {
                return provider;
            }
        }
    }

    @Configuration
    @ConditionalOnMissingBean(FeatureManager.class)
    protected static class FeatureManagerConfiguration {

        @Autowired
        private TogglzProperties properties;

        @Bean
        public FeatureManager featureManager(FeatureProvider featureProvider, List<StateRepository> stateRepositories,
                UserProvider userProvider, ActivationStrategyProvider activationStrategyProvider) {
            StateRepository stateRepository = null;
            if (stateRepositories.size() == 1) {
                stateRepository = stateRepositories.get(0);
            } else if (stateRepositories.size() > 1) {
                stateRepository = new CompositeStateRepository(
                        stateRepositories.toArray(new StateRepository[stateRepositories.size()]));
            }
            // If caching is enabled wrap state repository in caching state
            // repository.
            // Note that we explicitly check if the state repository is not
            // already a caching state repository,
            // as the auto configuration of the state repository already creates
            // a caching state repository if needed.
            // The below wrapping only occurs if the user provided the state
            // repository manually and caching is enabled.
            if (properties.getCache().isEnabled() && !(stateRepository instanceof CachingStateRepository)) {
                stateRepository = new CachingStateRepository(stateRepository, properties.getCache().getTimeToLive(),
                        properties.getCache().getTimeUnit());
            }
            FeatureManagerBuilder featureManagerBuilder = new FeatureManagerBuilder();
            String name = properties.getFeatureManagerName();
            if (name != null && name.length() > 0) {
                featureManagerBuilder.name(name);
            }
            featureManagerBuilder.featureProvider(featureProvider).stateRepository(stateRepository)
                    .userProvider(userProvider).activationStrategyProvider(activationStrategyProvider).build();
            FeatureManager manager = featureManagerBuilder.build();
            return manager;
        }
    }

    @Configuration
    @ConditionalOnMissingBean(ActivationStrategyProvider.class)
    protected static class ActivationStrategyProviderConfiguration {

        @Autowired(required = false)
        private List<ActivationStrategy> activationStrategies;

        @Bean
        public ActivationStrategyProvider activationStrategyProvider() {
            DefaultActivationStrategyProvider provider = new DefaultActivationStrategyProvider();
            if (activationStrategies != null && activationStrategies.size() > 0) {
                provider.addActivationStrategies(activationStrategies);
            }
            return provider;
        }
    }

    @Configuration
    @ConditionalOnMissingBean(StateRepository.class)
    protected static class StateRepositoryConfiguration {

        @Autowired
        private ResourceLoader resourceLoader = new DefaultResourceLoader();

        @Autowired
        private TogglzProperties properties;

        @Bean
        public StateRepository stateRepository() throws IOException {
            StateRepository stateRepository;
            String featuresFile = properties.getFeaturesFile();
            if (featuresFile != null) {
                Resource resource = this.resourceLoader.getResource(featuresFile);
                Integer minCheckInterval = properties.getFeaturesFileMinCheckInterval();
                if (minCheckInterval != null) {
                    stateRepository = new FileBasedStateRepository(resource.getFile(), minCheckInterval);
                } else {
                    stateRepository = new FileBasedStateRepository(resource.getFile());
                }
            } else {
                Map<String, FeatureSpec> features = properties.getFeatures();
                stateRepository = new InMemoryStateRepository();
                for (String name : features.keySet()) {
                    stateRepository.setFeatureState(features.get(name).state(name));
                }
            }
            // If caching is enabled wrap state repository in caching state
            // repository.
            if (properties.getCache().isEnabled()) {
                stateRepository = new CachingStateRepository(stateRepository, properties.getCache().getTimeToLive(),
                        properties.getCache().getTimeUnit());
            }
            return stateRepository;
        }
    }

    @Configuration
    @ConditionalOnMissingClass("org.springframework.security.config.annotation.web.configuration.EnableWebSecurity")
    @ConditionalOnMissingBean(UserProvider.class)
    protected static class UserProviderConfiguration {
        @Bean
        public UserProvider userProvider() {
            return new NoOpUserProvider();
        }
    }

    @Configuration
    @ConditionalOnClass({ EnableWebSecurity.class, AuthenticationEntryPoint.class, SpringSecurityUserProvider.class })
    @ConditionalOnMissingBean(UserProvider.class)
    protected static class SpringSecurityUserProviderConfiguration {

        @Autowired
        private TogglzProperties properties;

        @Bean
        public UserProvider userProvider() {
            return new SpringSecurityUserProvider(properties.getConsole().getFeatureAdminAuthority());
        }
    }

    @Configuration
    @ConditionalOnWebApplication
    @ConditionalOnClass(TogglzConsoleServlet.class)
    @Conditional(TogglzConsoleBaseConfiguration.OnConsoleAndNotUseManagementPort.class)
    protected static class TogglzConsoleConfiguration extends TogglzConsoleBaseConfiguration {

        public TogglzConsoleConfiguration(TogglzProperties properties) {
            super(properties);
        }
    }

    @Configuration
    @ConditionalOnWebApplication
    @ConditionalOnClass(HandlerInterceptorAdapter.class)
    @ConditionalOnProperty(prefix = "togglz.web", name = "register-feature-interceptor", havingValue = "true")
    protected static class TogglzFeatureInterceptorConfiguration extends WebMvcConfigurerAdapter {
        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(new FeatureInterceptor());
        }
    }

    @Configuration
    @ConditionalOnClass(TogglzDialect.class)
    protected static class ThymeleafTogglzDialectConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public TogglzDialect togglzDialect() {
            return new TogglzDialect();
        }
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.togglz.console.TogglzConsoleServlet;

/**
 * Base {@link EnableAutoConfiguration Auto-configuration} class for Togglz Console.
 *
 * <p>Provides a common ground implementation for console on management port or on the
 * application port, as well as for Spring Boot 1.5 and Spring Boot 2.
 *
 * @author Marcel Overdijk
 * @author Rui Figueira
 */
public abstract class TogglzConsoleBaseConfiguration {

    private final TogglzProperties properties;

    protected TogglzConsoleBaseConfiguration(TogglzProperties properties) {
        this.properties = properties;
    }

    @Bean
    public ServletRegistrationBean togglzConsole() {
        String path = getContextPath() + properties.getConsole().getPath();
        String urlMapping = (path.endsWith("/") ? path + "*" : path + "/*");
        TogglzConsoleServlet servlet = new TogglzConsoleServlet();
        servlet.setSecured(properties.getConsole().isSecured());
        return new ServletRegistrationBean(servlet, urlMapping);
    }

    protected String getContextPath() {
        return "";
    }

    public static class OnConsoleAndUseManagementPort extends AllNestedConditions {

        OnConsoleAndUseManagementPort() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "togglz.console", name = "enabled", matchIfMissing = true)
        static class OnConsole {
        }
        
        @ConditionalOnProperty(prefix = "togglz.console", name = "use-management-port", havingValue = "true", matchIfMissing = true)
        static class OnUseManagementPort {
        }

    }

    public static class OnConsoleAndNotUseManagementPort extends AllNestedConditions {

        OnConsoleAndNotUseManagementPort() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "togglz.console", name = "enabled", matchIfMissing = true)
        static class OnConsole {
        }

        @ConditionalOnProperty(prefix = "togglz.console", name = "use-management-port", havingValue = "false")
        static class OnNotUseManagementPort {
        }

    }
}
--------------------------------------------------------------------------------------------------------
 * public boolean isActive() {
 *     return FeatureContext.getFeatureManager().isActive(this);
 * }
--------------------------------------------------------------------------------------------------------
@Bean
public FeatureProvider featureProvider() {
    return new EnumBasedFeatureProvider(MyFeatures.class);
}
--------------------------------------------------------------------------------------------------------
<servers>
  <server>
    <id>sonatype-nexus-snapshots</id>
    <username>sonatypeuser</username>
    <password>sonatypepassword</password>
  </server>
  <server>
    <id>sonatype-nexus-staging</id>
    <username>sonatypeuser</username>
    <password>sonatypepassword</password>
  </server>
</servers>

mvn dependency:resolve -Dclassifier=sources
mvn versions:display-dependency-updates versions:display-plugin-updates -Pall
mvn validate license:format -Pall
mvn clean org.jacoco:jacoco-maven-plugin:prepare-agent test sonar:sonar

mvn versions:set -DnewVersion=X.Z-SNAPSHOT -Pall
mvn versions:commit -Pall
--------------------------------------------------------------------------------------------------------
https://gitlab.paragon-software.com/pba/DevOps/ansible/
--------------------------------------------------------------------------------------------------------
@EnableRuleMigrationSupport
public class JUnit4TemporaryFolderTest {
   @Rule
   public TemporaryFolder temporaryFolder = new TemporaryFolder();
   @Test
   public void test() throws IOException {
      temporaryFolder.newFile(“new_file”);
   }
}
--------------------------------------------------------------------------------------------------------
public class SMTPServerRule extends ExternalResource {

   private GreenMail smtpServer;
   private String hostname;
   private int port;

   public SMTPServerRule() {
       this(25);
   }

   public SMTPServerRule(int port) {
       this("localhost", port);
   }

   public SMTPServerRule(String hostname, int port) {
       this.hostname = hostname;
       this.port = port;
   }


   @Override
   protected void before() throws Throwable {
       super.before();

       smtpServer = new GreenMail(new ServerSetup(port, hostname, "smtp"));
       smtpServer.start();
   }

   public List<ExpectedMail> getMessages() {
       return Lists.newArrayList(smtpServer.getReceivedMessages()).stream()
           .parallel()
           .map(mimeMessage -> ExpectedMail.transformMimeMessage(mimeMessage)).collect(Collectors.toList());
   }

   @Override
   protected void after() {
       super.after();
       smtpServer.stop();
   }
}
--------------------------------------------------------------------------------------------------------
import static org.apiguardian.api.API.Status.STABLE;

import java.util.Locale;

import org.apiguardian.api.API;
import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;
import org.junit.platform.commons.util.StringUtils;

/**
 * Enumeration of common operating systems used for testing Java applications.
 *
 * <p>If the current operating system cannot be detected &mdash; for example,
 * if the {@code os.name} JVM system property is undefined &mdash; then none
 * of the constants defined in this enum will be considered to be the
 * {@linkplain #isCurrentOs current operating system}.
 *
 * @since 5.1
 * @see #AIX
 * @see #LINUX
 * @see #MAC
 * @see #SOLARIS
 * @see #WINDOWS
 * @see #OTHER
 * @see EnabledOnOs
 * @see DisabledOnOs
 */
@API(status = STABLE, since = "5.1")
public enum OS {

	/**
	 * IBM AIX operating system.
	 *
	 * @since 5.3
	 */
	@API(status = STABLE, since = "5.3")
	AIX,

	/**
	 * Linux-based operating system.
	 */
	LINUX,

	/**
	 * Apple Macintosh operating system (e.g., macOS).
	 */
	MAC,

	/**
	 * Oracle Solaris operating system.
	 */
	SOLARIS,

	/**
	 * Microsoft Windows operating system.
	 */
	WINDOWS,

	/**
	 * An operating system other than {@link #AIX}, {@link #LINUX}, {@link #MAC},
	 * {@link #SOLARIS}, or {@link #WINDOWS}.
	 */
	OTHER;

	private static final Logger logger = LoggerFactory.getLogger(OS.class);

	private static final OS CURRENT_OS = determineCurrentOs();

	private static OS determineCurrentOs() {
		String osName = System.getProperty("os.name");

		if (StringUtils.isBlank(osName)) {
			logger.debug(
				() -> "JVM system property 'os.name' is undefined. It is therefore not possible to detect the current OS.");

			// null signals that the current OS is "unknown"
			return null;
		}

		osName = osName.toLowerCase(Locale.ENGLISH);

		if (osName.contains("aix")) {
			return AIX;
		}
		if (osName.contains("linux")) {
			return LINUX;
		}
		if (osName.contains("mac")) {
			return MAC;
		}
		if (osName.contains("sunos") || osName.contains("solaris")) {
			return SOLARIS;
		}
		if (osName.contains("win")) {
			return WINDOWS;
		}
		return OTHER;
	}

	/**
	 * @return {@code true} if <em>this</em> {@code OS} is known to be the
	 * operating system on which the current JVM is executing
	 */
	public boolean isCurrentOs() {
		return this == CURRENT_OS;
	}

}

import static org.apiguardian.api.API.Status.STABLE;

import java.lang.reflect.Method;

import org.apiguardian.api.API;
import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;
import org.junit.platform.commons.util.ReflectionUtils;
import org.junit.platform.commons.util.StringUtils;

/**
 * Enumeration of Java Runtime Environment (JRE) versions.
 *
 * <p>If the current JRE version cannot be detected &mdash; for example, if the
 * {@code java.version} JVM system property is undefined &mdash; then none of
 * the constants defined in this enum will be considered to be the
 * {@linkplain #isCurrentVersion current JRE version}.
 *
 * @since 5.1
 * @see #JAVA_8
 * @see #JAVA_9
 * @see #JAVA_10
 * @see #JAVA_11
 * @see #JAVA_12
 * @see #JAVA_13
 * @see #JAVA_14
 * @see #OTHER
 * @see EnabledOnJre
 * @see DisabledOnJre
 */
@API(status = STABLE, since = "5.1")
public enum JRE {

	/**
	 * Java 8.
	 */
	JAVA_8,

	/**
	 * Java 9.
	 */
	JAVA_9,

	/**
	 * Java 10.
	 */
	JAVA_10,

	/**
	 * Java 11.
	 */
	JAVA_11,

	/**
	 * Java 12.
	 *
	 * @since 5.4
	 */
	@API(status = STABLE, since = "5.4")
	JAVA_12,

	/**
	 * Java 13.
	 *
	 * @since 5.4
	 */
	@API(status = STABLE, since = "5.4")
	JAVA_13,

	/**
	 * Java 14.
	 *
	 * @since 5.5
	 */
	@API(status = STABLE, since = "5.5")
	JAVA_14,

	/**
	 * A JRE version other than {@link #JAVA_8}, {@link #JAVA_9},
	 * {@link #JAVA_10}, {@link #JAVA_11}, {@link #JAVA_12},
	 * {@link #JAVA_13}, or {@link #JAVA_14}.
	 */
	OTHER;

	private static final Logger logger = LoggerFactory.getLogger(JRE.class);

	private static final JRE CURRENT_VERSION = determineCurrentVersion();

	private static JRE determineCurrentVersion() {
		String javaVersion = System.getProperty("java.version");
		boolean javaVersionIsBlank = StringUtils.isBlank(javaVersion);

		if (javaVersionIsBlank) {
			logger.debug(
				() -> "JVM system property 'java.version' is undefined. It is therefore not possible to detect Java 8.");
		}

		if (!javaVersionIsBlank && javaVersion.startsWith("1.8")) {
			return JAVA_8;
		}

		try {
			// java.lang.Runtime.version() is a static method available on Java 9+
			// that returns an instance of java.lang.Runtime.Version which has the
			// following method: public int major()
			Method versionMethod = Runtime.class.getMethod("version");
			Object version = ReflectionUtils.invokeMethod(versionMethod, null);
			Method majorMethod = version.getClass().getMethod("major");
			int major = (int) ReflectionUtils.invokeMethod(majorMethod, version);
			switch (major) {
				case 9:
					return JAVA_9;
				case 10:
					return JAVA_10;
				case 11:
					return JAVA_11;
				case 12:
					return JAVA_12;
				case 13:
					return JAVA_13;
				case 14:
					return JAVA_14;
				default:
					return OTHER;
			}
		}
		catch (Exception ex) {
			logger.debug(ex, () -> "Failed to determine the current JRE version via java.lang.Runtime.Version.");
		}

		// null signals that the current JRE version is "unknown"
		return null;
	}

	/**
	 * @return {@code true} if <em>this</em> {@code JRE} is known to be the
	 * Java Runtime Environment version for the currently executing JVM
	 */
	public boolean isCurrentVersion() {
		return this == CURRENT_VERSION;
	}
}
--------------------------------------------------------------------------------------------------------
@RunWith(JUnitPlatform.class)
@SelectPackages({net.mednikov.teststutorial.groupA, net.mednikov.teststutorial.groupB, net.mednikov.teststutorial.groupC})
public class TestSuite(){}
--------------------------------------------------------------------------------------------------------
import net.andreinc.jbvext.annotations.digits.MinDigits;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class MinDigitsDoubleValidator implements ConstraintValidator<MinDigits, Double> {

    private MinDigits annotation;

    @Override
    public void initialize(MinDigits constraintAnnotation) {
        this.annotation = constraintAnnotation;
    }

    @Override
    public boolean isValid(Double value, ConstraintValidatorContext context) {

        if (value == null) {
            return false;
        }

        Double minDigitsValue = Double.valueOf(this.annotation.value());

        int result = Double.compare(value, minDigitsValue);

        if (0 == result){
            // Value is equal to min
            return true;
        } else if (result < 0){
            // Value is less than min
            return false;
        } else if (result > 0){
            // Value is greater than min
            return true;
        } else {
            throw new IllegalArgumentException("How this could be possible");
        }

    }
}

DeliveryAcceptedStatus
topic: Delivery
clientId: delivery-status-id
groupId: free-coupons-delivery-status
mapping: 
--------------------------------------------------------------------------------------------------------
- src: 'git@gitlab.paragon-software.com:pba/DevOps/paragon.ansible.k8s.roles/pim.git'
  scm: 'git'
  name: 'pim'

- src: 'git@gitlab.paragon-software.com:pba/DevOps/paragon.ansible.k8s.roles/usercontour.git'
  scm: 'git'
  name: 'usercontour'
  version: GD-199-usercontour-mailer-documentsgenerator

--------------------------------------------------------------------------------------------------------
public LocalDate convertToLocalDate(Date dateToConvert) {
    return LocalDate.ofInstant(
      dateToConvert.toInstant(), ZoneId.systemDefault());
}
 
public LocalDateTime convertToLocalDateTime(Date dateToConvert) {
    return LocalDateTime.ofInstant(
      dateToConvert.toInstant(), ZoneId.systemDefault());
}
--------------------------------------------------------------------------------------------------------
junit-platform.properties

mvn -Dtest=org.example.MyTest test
mvn -Dtest=com.paragon.microservices.freecoupons.exception.ExceptionTest test

JUnit Platform Provider supports the test JVM system property supported by the Maven Surefire Plugin. For example, to run only test methods in the org.example.MyTest test class you can execute 
--------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<testsuite xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://maven.apache.org/surefire/maven-surefire-plugin/xsd/surefire-test-report-3.0.xsd" version="3.0" name="com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest" time="2.703" tests="3" errors="2" skipped="0" failures="0">
  <properties>
    <property name="sun.desktop" value="windows"/>
    <property name="awt.toolkit" value="sun.awt.windows.WToolkit"/>
    <property name="file.encoding.pkg" value="sun.io"/>
    <property name="java.specification.version" value="1.8"/>
    <property name="sun.cpu.isalist" value="amd64"/>
    <property name="sun.jnu.encoding" value="Cp1251"/>
    <property name="java.class.path" value="C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.service\test-classes;C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.service\classes;C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.common\classes;C:\Users\rogalski\.m2\repository\org\projectlombok\lombok\1.18.8\lombok-1.18.8.jar;C:\Users\rogalski\.m2\repository\com\paragon\mailingcontour\paragon.mailingcontour.commons\0.3.0-alpha-0352-ef7813f\paragon.mailingcontour.commons-0.3.0-alpha-0352-ef7813f.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-aop\2.1.8.RELEASE\spring-boot-starter-aop-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\aspectj\aspectjweaver\1.9.4\aspectjweaver-1.9.4.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-logging\2.1.8.RELEASE\spring-boot-starter-logging-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\logging\log4j\log4j-to-slf4j\2.11.2\log4j-to-slf4j-2.11.2.jar;C:\Users\rogalski\.m2\repository\org\apache\logging\log4j\log4j-api\2.11.2\log4j-api-2.11.2.jar;C:\Users\rogalski\.m2\repository\org\slf4j\jul-to-slf4j\1.7.28\jul-to-slf4j-1.7.28.jar;C:\Users\rogalski\.m2\repository\org\springframework\retry\spring-retry\1.2.4.RELEASE\spring-retry-1.2.4.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-redis\2.1.10.RELEASE\spring-data-redis-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-keyvalue\2.1.10.RELEASE\spring-data-keyvalue-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-commons\2.1.10.RELEASE\spring-data-commons-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-oxm\5.1.9.RELEASE\spring-oxm-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-context-support\5.1.9.RELEASE\spring-context-support-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\commons\commons-lang3\3.8.1\commons-lang3-3.8.1.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-spi\2.9.2\springfox-spi-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-core\2.9.2\springfox-core-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-spring-web\2.9.2\springfox-spring-web-2.9.2.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-web\2.1.8.RELEASE\spring-boot-starter-web-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter\2.1.8.RELEASE\spring-boot-starter-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\javax\annotation\javax.annotation-api\1.3.2\javax.annotation-api-1.3.2.jar;C:\Users\rogalski\.m2\repository\org\yaml\snakeyaml\1.23\snakeyaml-1.23.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-json\2.1.8.RELEASE\spring-boot-starter-json-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\datatype\jackson-datatype-jdk8\2.9.9\jackson-datatype-jdk8-2.9.9.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\datatype\jackson-datatype-jsr310\2.9.9\jackson-datatype-jsr310-2.9.9.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\module\jackson-module-parameter-names\2.9.9\jackson-module-parameter-names-2.9.9.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-tomcat\2.1.8.RELEASE\spring-boot-starter-tomcat-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-core\9.0.24\tomcat-embed-core-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-websocket\9.0.24\tomcat-embed-websocket-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\hibernate\validator\hibernate-validator\6.0.17.Final\hibernate-validator-6.0.17.Final.jar;C:\Users\rogalski\.m2\repository\org\jboss\logging\jboss-logging\3.3.3.Final\jboss-logging-3.3.3.Final.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-web\5.1.9.RELEASE\spring-web-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-beans\5.1.9.RELEASE\spring-beans-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-webmvc\5.1.9.RELEASE\spring-webmvc-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-expression\5.1.9.RELEASE\spring-expression-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-data-redis\2.1.8.RELEASE\spring-boot-starter-data-redis-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\lettuce\lettuce-core\5.1.8.RELEASE\lettuce-core-5.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-common\4.1.39.Final\netty-common-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-handler\4.1.39.Final\netty-handler-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-buffer\4.1.39.Final\netty-buffer-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-codec\4.1.39.Final\netty-codec-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-transport\4.1.39.Final\netty-transport-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-resolver\4.1.39.Final\netty-resolver-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\projectreactor\reactor-core\3.2.12.RELEASE\reactor-core-3.2.12.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\reactivestreams\reactive-streams\1.0.3\reactive-streams-1.0.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-security\2.1.8.RELEASE\spring-boot-starter-security-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-aop\5.1.9.RELEASE\spring-aop-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-config\5.1.6.RELEASE\spring-security-config-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-web\5.1.6.RELEASE\spring-security-web-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-validation\2.1.8.RELEASE\spring-boot-starter-validation-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-el\9.0.24\tomcat-embed-el-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-actuator\2.1.8.RELEASE\spring-boot-starter-actuator-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-actuator-autoconfigure\2.1.8.RELEASE\spring-boot-actuator-autoconfigure-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-actuator\2.1.8.RELEASE\spring-boot-actuator-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\micrometer\micrometer-core\1.1.6\micrometer-core-1.1.6.jar;C:\Users\rogalski\.m2\repository\org\hdrhistogram\HdrHistogram\2.1.9\HdrHistogram-2.1.9.jar;C:\Users\rogalski\.m2\repository\org\latencyutils\LatencyUtils\2.0.3\LatencyUtils-2.0.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-devtools\2.1.8.RELEASE\spring-boot-devtools-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot\2.1.8.RELEASE\spring-boot-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-autoconfigure\2.1.8.RELEASE\spring-boot-autoconfigure-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\kafka\spring-kafka\2.2.8.RELEASE\spring-kafka-2.2.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-context\5.1.9.RELEASE\spring-context-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-messaging\5.1.9.RELEASE\spring-messaging-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-tx\5.1.9.RELEASE\spring-tx-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka-clients\2.0.1\kafka-clients-2.0.1.jar;C:\Users\rogalski\.m2\repository\org\lz4\lz4-java\1.4.1\lz4-java-1.4.1.jar;C:\Users\rogalski\.m2\repository\org\xerial\snappy\snappy-java\1.1.7.1\snappy-java-1.1.7.1.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-jwt\1.0.10.RELEASE\spring-security-jwt-1.0.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\bouncycastle\bcpkix-jdk15on\1.60\bcpkix-jdk15on-1.60.jar;C:\Users\rogalski\.m2\repository\org\bouncycastle\bcprov-jdk15on\1.60\bcprov-jdk15on-1.60.jar;C:\Users\rogalski\.m2\repository\com\google\guava\guava\28.0-jre\guava-28.0-jre.jar;C:\Users\rogalski\.m2\repository\com\google\guava\failureaccess\1.0.1\failureaccess-1.0.1.jar;C:\Users\rogalski\.m2\repository\com\google\guava\listenablefuture\9999.0-empty-to-avoid-conflict-with-guava\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar;C:\Users\rogalski\.m2\repository\com\google\code\findbugs\jsr305\3.0.2\jsr305-3.0.2.jar;C:\Users\rogalski\.m2\repository\org\checkerframework\checker-qual\2.8.1\checker-qual-2.8.1.jar;C:\Users\rogalski\.m2\repository\com\google\errorprone\error_prone_annotations\2.3.2\error_prone_annotations-2.3.2.jar;C:\Users\rogalski\.m2\repository\com\google\j2objc\j2objc-annotations\1.3\j2objc-annotations-1.3.jar;C:\Users\rogalski\.m2\repository\org\codehaus\mojo\animal-sniffer-annotations\1.17\animal-sniffer-annotations-1.17.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger2\2.9.2\springfox-swagger2-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\swagger\swagger-annotations\1.5.20\swagger-annotations-1.5.20.jar;C:\Users\rogalski\.m2\repository\io\swagger\swagger-models\1.5.20\swagger-models-1.5.20.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.9.0\jackson-annotations-2.9.0.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-schema\2.9.2\springfox-schema-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger-common\2.9.2\springfox-swagger-common-2.9.2.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\classmate\1.4.0\classmate-1.4.0.jar;C:\Users\rogalski\.m2\repository\org\slf4j\slf4j-api\1.7.28\slf4j-api-1.7.28.jar;C:\Users\rogalski\.m2\repository\org\springframework\plugin\spring-plugin-core\1.2.0.RELEASE\spring-plugin-core-1.2.0.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\plugin\spring-plugin-metadata\1.2.0.RELEASE\spring-plugin-metadata-1.2.0.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\mapstruct\mapstruct\1.2.0.Final\mapstruct-1.2.0.Final.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger-ui\2.9.2\springfox-swagger-ui-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-bean-validators\2.9.2\springfox-bean-validators-2.9.2.jar;C:\Users\rogalski\.m2\repository\javax\validation\validation-api\2.0.1.Final\validation-api-2.0.1.Final.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-json-classic\0.1.5\logback-json-classic-0.1.5.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\logback-classic\1.2.3\logback-classic-1.2.3.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\logback-core\1.2.3\logback-core-1.2.3.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-json-core\0.1.5\logback-json-core-0.1.5.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-jackson\0.1.5\logback-jackson-0.1.5.jar;C:\Users\rogalski\.m2\repository\net\logstash\logback\logstash-logback-encoder\6.1\logstash-logback-encoder-6.1.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.9.9.3\jackson-databind-2.9.9.3.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.9.9\jackson-core-2.9.9.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-api\5.5.2\junit-jupiter-api-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\apiguardian\apiguardian-api\1.1.0\apiguardian-api-1.1.0.jar;C:\Users\rogalski\.m2\repository\org\opentest4j\opentest4j\1.2.0\opentest4j-1.2.0.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-params\5.5.2\junit-jupiter-params-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-engine\5.5.2\junit-jupiter-engine-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-migrationsupport\5.5.2\junit-jupiter-migrationsupport-5.5.2.jar;C:\Users\rogalski\.m2\repository\junit\junit\4.12\junit-4.12.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-launcher\1.4.1\junit-platform-launcher-1.4.1.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-runner\1.5.2\junit-platform-runner-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-suite-api\1.3.2\junit-platform-suite-api-1.3.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-commons\1.5.2\junit-platform-commons-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-engine\1.5.2\junit-platform-engine-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\mockito\mockito-junit-jupiter\2.23.4\mockito-junit-jupiter-2.23.4.jar;C:\Users\rogalski\.m2\repository\org\mockito\mockito-core\2.23.4\mockito-core-2.23.4.jar;C:\Users\rogalski\.m2\repository\net\bytebuddy\byte-buddy\1.9.16\byte-buddy-1.9.16.jar;C:\Users\rogalski\.m2\repository\net\bytebuddy\byte-buddy-agent\1.9.16\byte-buddy-agent-1.9.16.jar;C:\Users\rogalski\.m2\repository\org\objenesis\objenesis\2.6\objenesis-2.6.jar;C:\Users\rogalski\.m2\repository\org\springframework\kafka\spring-kafka-test\2.2.8.RELEASE\spring-kafka-test-2.2.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-test\5.1.9.RELEASE\spring-test-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka-clients\2.0.1\kafka-clients-2.0.1-test.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka_2.11\2.0.1\kafka_2.11-2.0.1.jar;C:\Users\rogalski\.m2\repository\net\sf\jopt-simple\jopt-simple\5.0.4\jopt-simple-5.0.4.jar;C:\Users\rogalski\.m2\repository\com\yammer\metrics\metrics-core\2.2.0\metrics-core-2.2.0.jar;C:\Users\rogalski\.m2\repository\org\scala-lang\scala-library\2.11.12\scala-library-2.11.12.jar;C:\Users\rogalski\.m2\repository\org\scala-lang\scala-reflect\2.11.12\scala-reflect-2.11.12.jar;C:\Users\rogalski\.m2\repository\com\typesafe\scala-logging\scala-logging_2.11\3.9.0\scala-logging_2.11-3.9.0.jar;C:\Users\rogalski\.m2\repository\com\101tec\zkclient\0.10\zkclient-0.10.jar;C:\Users\rogalski\.m2\repository\org\apache\zookeeper\zookeeper\3.4.13\zookeeper-3.4.13.jar;C:\Users\rogalski\.m2\repository\org\apache\yetus\audience-annotations\0.5.0\audience-annotations-0.5.0.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka_2.11\2.0.1\kafka_2.11-2.0.1-test.jar;C:\Users\rogalski\.m2\repository\com\github\kstyrc\embedded-redis\0.6\embedded-redis-0.6.jar;C:\Users\rogalski\.m2\repository\commons-io\commons-io\2.4\commons-io-2.4.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-test\2.1.8.RELEASE\spring-boot-starter-test-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-test\2.1.8.RELEASE\spring-boot-test-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\com\jayway\jsonpath\json-path\2.4.0\json-path-2.4.0.jar;C:\Users\rogalski\.m2\repository\net\minidev\json-smart\2.3\json-smart-2.3.jar;C:\Users\rogalski\.m2\repository\net\minidev\accessors-smart\1.2\accessors-smart-1.2.jar;C:\Users\rogalski\.m2\repository\org\ow2\asm\asm\5.0.4\asm-5.0.4.jar;C:\Users\rogalski\.m2\repository\org\assertj\assertj-core\3.11.1\assertj-core-3.11.1.jar;C:\Users\rogalski\.m2\repository\org\hamcrest\hamcrest-core\1.3\hamcrest-core-1.3.jar;C:\Users\rogalski\.m2\repository\org\hamcrest\hamcrest-library\1.3\hamcrest-library-1.3.jar;C:\Users\rogalski\.m2\repository\org\skyscreamer\jsonassert\1.5.0\jsonassert-1.5.0.jar;C:\Users\rogalski\.m2\repository\com\vaadin\external\google\android-json\0.0.20131108.vaadin1\android-json-0.0.20131108.vaadin1.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-core\5.1.9.RELEASE\spring-core-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-jcl\5.1.9.RELEASE\spring-jcl-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\xmlunit\xmlunit-core\2.6.3\xmlunit-core-2.6.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-test\5.1.6.RELEASE\spring-security-test-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-core\5.1.6.RELEASE\spring-security-core-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-test-autoconfigure\2.1.8.RELEASE\spring-boot-test-autoconfigure-2.1.8.RELEASE.jar;"/>
    <property name="java.vm.vendor" value="Oracle Corporation"/>
    <property name="sun.arch.data.model" value="64"/>
    <property name="user.variant" value=""/>
    <property name="java.vendor.url" value="http://java.oracle.com/"/>
    <property name="user.timezone" value="Europe/Moscow"/>
    <property name="user.country.format" value="RU"/>
    <property name="java.vm.specification.version" value="1.8"/>
    <property name="os.name" value="Windows 10"/>
    <property name="user.country" value="US"/>
    <property name="sun.java.launcher" value="SUN_STANDARD"/>
    <property name="sun.boot.library.path" value="C:\Program Files\Java\jdk1.8.0_191\jre\bin"/>
    <property name="sun.java.command" value="C:\Users\rogalski\AppData\Local\Temp\surefire5096680877611110727\surefirebooter410434119339594636.jar C:\Users\rogalski\AppData\Local\Temp\surefire5096680877611110727 2019-10-31T20-35-15_628-jvmRun1 surefire6326151768280446625tmp surefire_08843624168109330963tmp"/>
    <property name="surefire.test.class.path" value="C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.service\test-classes;C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.service\classes;C:\git-project\paragon.microservices.freecoupons\.build\bin\paragon.microservices.freecoupons.common\classes;C:\Users\rogalski\.m2\repository\org\projectlombok\lombok\1.18.8\lombok-1.18.8.jar;C:\Users\rogalski\.m2\repository\com\paragon\mailingcontour\paragon.mailingcontour.commons\0.3.0-alpha-0352-ef7813f\paragon.mailingcontour.commons-0.3.0-alpha-0352-ef7813f.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-aop\2.1.8.RELEASE\spring-boot-starter-aop-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\aspectj\aspectjweaver\1.9.4\aspectjweaver-1.9.4.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-logging\2.1.8.RELEASE\spring-boot-starter-logging-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\logging\log4j\log4j-to-slf4j\2.11.2\log4j-to-slf4j-2.11.2.jar;C:\Users\rogalski\.m2\repository\org\apache\logging\log4j\log4j-api\2.11.2\log4j-api-2.11.2.jar;C:\Users\rogalski\.m2\repository\org\slf4j\jul-to-slf4j\1.7.28\jul-to-slf4j-1.7.28.jar;C:\Users\rogalski\.m2\repository\org\springframework\retry\spring-retry\1.2.4.RELEASE\spring-retry-1.2.4.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-redis\2.1.10.RELEASE\spring-data-redis-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-keyvalue\2.1.10.RELEASE\spring-data-keyvalue-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\data\spring-data-commons\2.1.10.RELEASE\spring-data-commons-2.1.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-oxm\5.1.9.RELEASE\spring-oxm-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-context-support\5.1.9.RELEASE\spring-context-support-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\commons\commons-lang3\3.8.1\commons-lang3-3.8.1.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-spi\2.9.2\springfox-spi-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-core\2.9.2\springfox-core-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-spring-web\2.9.2\springfox-spring-web-2.9.2.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-web\2.1.8.RELEASE\spring-boot-starter-web-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter\2.1.8.RELEASE\spring-boot-starter-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\javax\annotation\javax.annotation-api\1.3.2\javax.annotation-api-1.3.2.jar;C:\Users\rogalski\.m2\repository\org\yaml\snakeyaml\1.23\snakeyaml-1.23.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-json\2.1.8.RELEASE\spring-boot-starter-json-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\datatype\jackson-datatype-jdk8\2.9.9\jackson-datatype-jdk8-2.9.9.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\datatype\jackson-datatype-jsr310\2.9.9\jackson-datatype-jsr310-2.9.9.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\module\jackson-module-parameter-names\2.9.9\jackson-module-parameter-names-2.9.9.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-tomcat\2.1.8.RELEASE\spring-boot-starter-tomcat-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-core\9.0.24\tomcat-embed-core-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-websocket\9.0.24\tomcat-embed-websocket-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\hibernate\validator\hibernate-validator\6.0.17.Final\hibernate-validator-6.0.17.Final.jar;C:\Users\rogalski\.m2\repository\org\jboss\logging\jboss-logging\3.3.3.Final\jboss-logging-3.3.3.Final.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-web\5.1.9.RELEASE\spring-web-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-beans\5.1.9.RELEASE\spring-beans-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-webmvc\5.1.9.RELEASE\spring-webmvc-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-expression\5.1.9.RELEASE\spring-expression-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-data-redis\2.1.8.RELEASE\spring-boot-starter-data-redis-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\lettuce\lettuce-core\5.1.8.RELEASE\lettuce-core-5.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-common\4.1.39.Final\netty-common-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-handler\4.1.39.Final\netty-handler-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-buffer\4.1.39.Final\netty-buffer-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-codec\4.1.39.Final\netty-codec-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-transport\4.1.39.Final\netty-transport-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\netty\netty-resolver\4.1.39.Final\netty-resolver-4.1.39.Final.jar;C:\Users\rogalski\.m2\repository\io\projectreactor\reactor-core\3.2.12.RELEASE\reactor-core-3.2.12.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\reactivestreams\reactive-streams\1.0.3\reactive-streams-1.0.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-security\2.1.8.RELEASE\spring-boot-starter-security-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-aop\5.1.9.RELEASE\spring-aop-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-config\5.1.6.RELEASE\spring-security-config-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-web\5.1.6.RELEASE\spring-security-web-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-validation\2.1.8.RELEASE\spring-boot-starter-validation-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\tomcat\embed\tomcat-embed-el\9.0.24\tomcat-embed-el-9.0.24.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-actuator\2.1.8.RELEASE\spring-boot-starter-actuator-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-actuator-autoconfigure\2.1.8.RELEASE\spring-boot-actuator-autoconfigure-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-actuator\2.1.8.RELEASE\spring-boot-actuator-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\io\micrometer\micrometer-core\1.1.6\micrometer-core-1.1.6.jar;C:\Users\rogalski\.m2\repository\org\hdrhistogram\HdrHistogram\2.1.9\HdrHistogram-2.1.9.jar;C:\Users\rogalski\.m2\repository\org\latencyutils\LatencyUtils\2.0.3\LatencyUtils-2.0.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-devtools\2.1.8.RELEASE\spring-boot-devtools-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot\2.1.8.RELEASE\spring-boot-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-autoconfigure\2.1.8.RELEASE\spring-boot-autoconfigure-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\kafka\spring-kafka\2.2.8.RELEASE\spring-kafka-2.2.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-context\5.1.9.RELEASE\spring-context-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-messaging\5.1.9.RELEASE\spring-messaging-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-tx\5.1.9.RELEASE\spring-tx-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka-clients\2.0.1\kafka-clients-2.0.1.jar;C:\Users\rogalski\.m2\repository\org\lz4\lz4-java\1.4.1\lz4-java-1.4.1.jar;C:\Users\rogalski\.m2\repository\org\xerial\snappy\snappy-java\1.1.7.1\snappy-java-1.1.7.1.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-jwt\1.0.10.RELEASE\spring-security-jwt-1.0.10.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\bouncycastle\bcpkix-jdk15on\1.60\bcpkix-jdk15on-1.60.jar;C:\Users\rogalski\.m2\repository\org\bouncycastle\bcprov-jdk15on\1.60\bcprov-jdk15on-1.60.jar;C:\Users\rogalski\.m2\repository\com\google\guava\guava\28.0-jre\guava-28.0-jre.jar;C:\Users\rogalski\.m2\repository\com\google\guava\failureaccess\1.0.1\failureaccess-1.0.1.jar;C:\Users\rogalski\.m2\repository\com\google\guava\listenablefuture\9999.0-empty-to-avoid-conflict-with-guava\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar;C:\Users\rogalski\.m2\repository\com\google\code\findbugs\jsr305\3.0.2\jsr305-3.0.2.jar;C:\Users\rogalski\.m2\repository\org\checkerframework\checker-qual\2.8.1\checker-qual-2.8.1.jar;C:\Users\rogalski\.m2\repository\com\google\errorprone\error_prone_annotations\2.3.2\error_prone_annotations-2.3.2.jar;C:\Users\rogalski\.m2\repository\com\google\j2objc\j2objc-annotations\1.3\j2objc-annotations-1.3.jar;C:\Users\rogalski\.m2\repository\org\codehaus\mojo\animal-sniffer-annotations\1.17\animal-sniffer-annotations-1.17.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger2\2.9.2\springfox-swagger2-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\swagger\swagger-annotations\1.5.20\swagger-annotations-1.5.20.jar;C:\Users\rogalski\.m2\repository\io\swagger\swagger-models\1.5.20\swagger-models-1.5.20.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.9.0\jackson-annotations-2.9.0.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-schema\2.9.2\springfox-schema-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger-common\2.9.2\springfox-swagger-common-2.9.2.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\classmate\1.4.0\classmate-1.4.0.jar;C:\Users\rogalski\.m2\repository\org\slf4j\slf4j-api\1.7.28\slf4j-api-1.7.28.jar;C:\Users\rogalski\.m2\repository\org\springframework\plugin\spring-plugin-core\1.2.0.RELEASE\spring-plugin-core-1.2.0.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\plugin\spring-plugin-metadata\1.2.0.RELEASE\spring-plugin-metadata-1.2.0.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\mapstruct\mapstruct\1.2.0.Final\mapstruct-1.2.0.Final.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-swagger-ui\2.9.2\springfox-swagger-ui-2.9.2.jar;C:\Users\rogalski\.m2\repository\io\springfox\springfox-bean-validators\2.9.2\springfox-bean-validators-2.9.2.jar;C:\Users\rogalski\.m2\repository\javax\validation\validation-api\2.0.1.Final\validation-api-2.0.1.Final.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-json-classic\0.1.5\logback-json-classic-0.1.5.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\logback-classic\1.2.3\logback-classic-1.2.3.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\logback-core\1.2.3\logback-core-1.2.3.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-json-core\0.1.5\logback-json-core-0.1.5.jar;C:\Users\rogalski\.m2\repository\ch\qos\logback\contrib\logback-jackson\0.1.5\logback-jackson-0.1.5.jar;C:\Users\rogalski\.m2\repository\net\logstash\logback\logstash-logback-encoder\6.1\logstash-logback-encoder-6.1.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.9.9.3\jackson-databind-2.9.9.3.jar;C:\Users\rogalski\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.9.9\jackson-core-2.9.9.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-api\5.5.2\junit-jupiter-api-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\apiguardian\apiguardian-api\1.1.0\apiguardian-api-1.1.0.jar;C:\Users\rogalski\.m2\repository\org\opentest4j\opentest4j\1.2.0\opentest4j-1.2.0.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-params\5.5.2\junit-jupiter-params-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-engine\5.5.2\junit-jupiter-engine-5.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\jupiter\junit-jupiter-migrationsupport\5.5.2\junit-jupiter-migrationsupport-5.5.2.jar;C:\Users\rogalski\.m2\repository\junit\junit\4.12\junit-4.12.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-launcher\1.4.1\junit-platform-launcher-1.4.1.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-runner\1.5.2\junit-platform-runner-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-suite-api\1.3.2\junit-platform-suite-api-1.3.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-commons\1.5.2\junit-platform-commons-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\junit\platform\junit-platform-engine\1.5.2\junit-platform-engine-1.5.2.jar;C:\Users\rogalski\.m2\repository\org\mockito\mockito-junit-jupiter\2.23.4\mockito-junit-jupiter-2.23.4.jar;C:\Users\rogalski\.m2\repository\org\mockito\mockito-core\2.23.4\mockito-core-2.23.4.jar;C:\Users\rogalski\.m2\repository\net\bytebuddy\byte-buddy\1.9.16\byte-buddy-1.9.16.jar;C:\Users\rogalski\.m2\repository\net\bytebuddy\byte-buddy-agent\1.9.16\byte-buddy-agent-1.9.16.jar;C:\Users\rogalski\.m2\repository\org\objenesis\objenesis\2.6\objenesis-2.6.jar;C:\Users\rogalski\.m2\repository\org\springframework\kafka\spring-kafka-test\2.2.8.RELEASE\spring-kafka-test-2.2.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-test\5.1.9.RELEASE\spring-test-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka-clients\2.0.1\kafka-clients-2.0.1-test.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka_2.11\2.0.1\kafka_2.11-2.0.1.jar;C:\Users\rogalski\.m2\repository\net\sf\jopt-simple\jopt-simple\5.0.4\jopt-simple-5.0.4.jar;C:\Users\rogalski\.m2\repository\com\yammer\metrics\metrics-core\2.2.0\metrics-core-2.2.0.jar;C:\Users\rogalski\.m2\repository\org\scala-lang\scala-library\2.11.12\scala-library-2.11.12.jar;C:\Users\rogalski\.m2\repository\org\scala-lang\scala-reflect\2.11.12\scala-reflect-2.11.12.jar;C:\Users\rogalski\.m2\repository\com\typesafe\scala-logging\scala-logging_2.11\3.9.0\scala-logging_2.11-3.9.0.jar;C:\Users\rogalski\.m2\repository\com\101tec\zkclient\0.10\zkclient-0.10.jar;C:\Users\rogalski\.m2\repository\org\apache\zookeeper\zookeeper\3.4.13\zookeeper-3.4.13.jar;C:\Users\rogalski\.m2\repository\org\apache\yetus\audience-annotations\0.5.0\audience-annotations-0.5.0.jar;C:\Users\rogalski\.m2\repository\org\apache\kafka\kafka_2.11\2.0.1\kafka_2.11-2.0.1-test.jar;C:\Users\rogalski\.m2\repository\com\github\kstyrc\embedded-redis\0.6\embedded-redis-0.6.jar;C:\Users\rogalski\.m2\repository\commons-io\commons-io\2.4\commons-io-2.4.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-starter-test\2.1.8.RELEASE\spring-boot-starter-test-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-test\2.1.8.RELEASE\spring-boot-test-2.1.8.RELEASE.jar;C:\Users\rogalski\.m2\repository\com\jayway\jsonpath\json-path\2.4.0\json-path-2.4.0.jar;C:\Users\rogalski\.m2\repository\net\minidev\json-smart\2.3\json-smart-2.3.jar;C:\Users\rogalski\.m2\repository\net\minidev\accessors-smart\1.2\accessors-smart-1.2.jar;C:\Users\rogalski\.m2\repository\org\ow2\asm\asm\5.0.4\asm-5.0.4.jar;C:\Users\rogalski\.m2\repository\org\assertj\assertj-core\3.11.1\assertj-core-3.11.1.jar;C:\Users\rogalski\.m2\repository\org\hamcrest\hamcrest-core\1.3\hamcrest-core-1.3.jar;C:\Users\rogalski\.m2\repository\org\hamcrest\hamcrest-library\1.3\hamcrest-library-1.3.jar;C:\Users\rogalski\.m2\repository\org\skyscreamer\jsonassert\1.5.0\jsonassert-1.5.0.jar;C:\Users\rogalski\.m2\repository\com\vaadin\external\google\android-json\0.0.20131108.vaadin1\android-json-0.0.20131108.vaadin1.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-core\5.1.9.RELEASE\spring-core-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\spring-jcl\5.1.9.RELEASE\spring-jcl-5.1.9.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\xmlunit\xmlunit-core\2.6.3\xmlunit-core-2.6.3.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-test\5.1.6.RELEASE\spring-security-test-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\security\spring-security-core\5.1.6.RELEASE\spring-security-core-5.1.6.RELEASE.jar;C:\Users\rogalski\.m2\repository\org\springframework\boot\spring-boot-test-autoconfigure\2.1.8.RELEASE\spring-boot-test-autoconfigure-2.1.8.RELEASE.jar;"/>
    <property name="sun.cpu.endian" value="little"/>
    <property name="user.home" value="C:\Users\rogalski"/>
    <property name="user.language" value="en"/>
    <property name="java.specification.vendor" value="Oracle Corporation"/>
    <property name="java.home" value="C:\Program Files\Java\jdk1.8.0_191\jre"/>
    <property name="basedir" value="C:\git-project\paragon.microservices.freecoupons\service"/>
    <property name="file.separator" value="\"/>
    <property name="line.separator" value="&#10;"/>
    <property name="java.vm.specification.vendor" value="Oracle Corporation"/>
    <property name="java.specification.name" value="Java Platform API Specification"/>
    <property name="java.awt.graphicsenv" value="sun.awt.Win32GraphicsEnvironment"/>
    <property name="surefire.real.class.path" value="C:\Users\rogalski\AppData\Local\Temp\surefire5096680877611110727\surefirebooter410434119339594636.jar"/>
    <property name="sun.boot.class.path" value="C:\Program Files\Java\jdk1.8.0_191\jre\lib\resources.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\rt.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\sunrsasign.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\jsse.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\jce.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\charsets.jar;C:\Program Files\Java\jdk1.8.0_191\jre\lib\jfr.jar;C:\Program Files\Java\jdk1.8.0_191\jre\classes"/>
    <property name="user.script" value=""/>
    <property name="sun.management.compiler" value="HotSpot 64-Bit Tiered Compilers"/>
    <property name="java.runtime.version" value="1.8.0_191-b12"/>
    <property name="user.name" value="rogalskiy"/>
    <property name="path.separator" value=";"/>
    <property name="os.version" value="10.0"/>
    <property name="java.endorsed.dirs" value="C:\Program Files\Java\jdk1.8.0_191\jre\lib\endorsed"/>
    <property name="java.runtime.name" value="Java(TM) SE Runtime Environment"/>
    <property name="file.encoding" value="Cp1251"/>
    <property name="java.vm.name" value="Java HotSpot(TM) 64-Bit Server VM"/>
    <property name="localRepository" value="C:\Users\rogalski\.m2\repository"/>
    <property name="java.vendor.url.bug" value="http://bugreport.sun.com/bugreport/"/>
    <property name="java.io.tmpdir" value="C:\Users\rogalski\AppData\Local\Temp\"/>
    <property name="java.version" value="1.8.0_191"/>
    <property name="user.dir" value="C:\git-project\paragon.microservices.freecoupons\service"/>
    <property name="os.arch" value="amd64"/>
    <property name="java.vm.specification.name" value="Java Virtual Machine Specification"/>
    <property name="java.awt.printerjob" value="sun.awt.windows.WPrinterJob"/>
    <property name="user.language.format" value="ru"/>
    <property name="sun.os.patch.level" value=""/>
    <property name="java.library.path" value="C:\Program Files\Java\jdk1.8.0_191\jre\bin;C:\WINDOWS\Sun\Java\bin;C:\WINDOWS\system32;C:\WINDOWS;C:\Users\rogalski\AppData\Local\Programs\Python\Python37-32;C:\Users\rogalski\AppData\Local\Programs\Python\Python37-32\Scripts;C:\ProgramData\DockerDesktop\version-bin;C:\Program Files\Docker\Docker\Resources\bin;C:\Users\rogalski\Downloads\WINDOWS.X64_180000_db_home\bin;C:\gradle-5.0\bin;C:\apache-maven-3.6.0\bin;C:\Program Files\Microsoft MPI\Bin\;C:\Program Files\Java\jdk-11.0.2\bin;C:\Program Files\Java\jdk1.8.0_191\bin;C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\Program Files\Sysinternals;C:\Program Files\PuTTY\;C:\WINDOWS\System32\OpenSSH\;C:\Program Files (x86)\Bitvise SSH Client;C:\HashiCorp\Vagrant\bin;C:\Program Files\TortoiseHg\;C:\Program Files\nodejs\;C:\ProgramData\chocolatey\bin;C:\Program Files\dotnet\;C:\PostgreSQL\pg11\bin;C:\Program Files\Microsoft SQL Server\130\Tools\Binn\;C:\Program Files (x86)\sbt\bin;C:\Program Files (x86)\Brackets\command;C:\Go\bin;C:\Program Files (x86)\Common Files\MicroStrategy;C:\Program Files (x86)\MicroStrategy\Intelligence Server;C:\Program Files (x86)\Common Files\MicroStrategy\JRE\170_51\Win32\bin\client;C:\Users\rogalski\Documents\pandoc;C:\Program Files (x86)\Yarn\bin\;C:\apache-ant-1.10.5\bin;C:\Program Files\Git LFS;C:\Program Files\Git\cmd;C:\exec;C:\Users\rogalski\scoop\shims;C:\Users\rogalski\AppData\Roaming\local\bin;C:\Users\rogalski\.cargo\bin;C:\Ruby25-x64\bin;C:\Users\rogalski\AppData\Local\Microsoft\WindowsApps;C:\Users\rogalski\AppData\Local\atom\bin;C:\Users\rogalski\AppData\Roaming\npm;C:\Users\rogalski\go\bin;C:\Users\rogalski\AppData\Local\Yarn\bin;C:\Program Files (x86)\Nmap;%IntelliJ IDEA%;C:\Users\rogalski\AppData\Local\hyper\app-2.1.2\resources\bin;."/>
    <property name="java.vm.info" value="mixed mode"/>
    <property name="java.vendor" value="Oracle Corporation"/>
    <property name="java.vm.version" value="25.191-b12"/>
    <property name="java.ext.dirs" value="C:\Program Files\Java\jdk1.8.0_191\jre\lib\ext;C:\WINDOWS\Sun\Java\lib\ext"/>
    <property name="sun.io.unicode.encoding" value="UnicodeLittle"/>
    <property name="java.class.version" value="52.0"/>
  </properties>
  <testcase name="getLicense_OK_whenLicensePresent" classname="com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest" time="2.533"/>
  <testcase name="getLicense_shouldReturnEmpty_whenLicenseServiceReturn404" classname="com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest" time="0.094">
    <error type="java.lang.NullPointerException">java.lang.NullPointerException
	at com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest.getLicense_shouldReturnEmpty_whenLicenseServiceReturn404(LicenseClientImplTest.java:120)
</error>
  </testcase>
  <testcase name="getLicense_shouldReturnEmpty_whenLicenseAbsence" classname="com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest" time="0.009">
    <error type="java.lang.NullPointerException">java.lang.NullPointerException
	at com.paragon.microservices.freecoupons.client.impl.LicenseClientImplTest.getLicense_shouldReturnEmpty_whenLicenseAbsence(LicenseClientImplTest.java:100)
</error>
  </testcase>
</testsuite>
--------------------------------------------------------------------------------------------------------
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>2.22.1</version>

    <dependency>
        <groupId>org.apache.maven.surefire</groupId>
        <artifactId>surefire-junit-platform</artifactId>
        <version>2.22.1</version>
    </dependency>
</plugin>

http://stackoverflow.com/questions/36970384/surefire-is-not-picking-up-junit-5-tests 
--------------------------------------------------------------------------------------------------------
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CalculatorTests {

	@Test
	@DisplayName("1 + 1 = 2")
	void addsTwoNumbers() {
		Calculator calculator = new Calculator();
		assertEquals(2, calculator.add(1, 1), "1 + 1 should equal 2");
	}

	@ParameterizedTest(name = "{0} + {1} = {2}")
	@CsvSource({
			"0,    1,   1",
			"1,    2,   3",
			"49,  51, 100",
			"1,  100, 101"
	})
	void add(int first, int second, int expectedResult) {
		Calculator calculator = new Calculator();
		assertEquals(expectedResult, calculator.add(first, second),
				() -> first + " + " + second + " should equal " + expectedResult);
	}
}
--------------------------------------------------------------------------------------------------------
<build>
    <plugins>
        ...
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.0.0-M3</version>
            <configuration>
                <excludes>
                    <exclude>some test to exclude here</exclude>
                </excludes>
            </configuration>
        </plugin>
    </plugins>
</build>

<build>
    <plugins>
        ...
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.0.0-M3</version>
            <configuration>
                <groups>acceptance | !feature-a</groups>
                <excludedGroups>integration, regression</excludedGroups>
            </configuration>
        </plugin>
    </plugins>
</build>
--------------------------------------------------------------------------------------------------------
@TestMethodOrder(OrderAnnotation.class)
class OrderedTestsDemo {

    @Test
    @Order(1)
    void nullValues() {
        // perform assertions against null values
    }

    @Test
    @Order(2)
    void emptyValues() {
        // perform assertions against empty values
    }

    @Test
    @Order(3)
    void validValues() {
        // perform assertions against valid values
    }

}

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.Alphanumeric.class)
public class TestClass{
   //..
}
--------------------------------------------------------------------------------------------------------
python -m pip install --upgrade pip

<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-test</artifactId>
   <exclusions>
     <exclusion>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
     </exclusion>
   </exclusions>
</dependency>
<dependency>
   <groupId>org.dbunit</groupId>
   <artifactId>dbunit</artifactId>
   <version>${dbunit.version}</version>
   <exclusions>
     <exclusion>
       <groupId>junit</groupId>
       <artifactId>junit</artifactId>
     </exclusion>
   </exclusions>
</dependency>
--------------------------------------------------------------------------------------------------------
@ExtendWith(SpringExtension.class)
@ExtendWith(MockitoExtension.class)

        <!--<dependency>-->
        <!--<groupId>org.junit.jupiter</groupId>-->
        <!--<artifactId>junit-jupiter-migrationsupport</artifactId>-->
        <!--<version>${junit-jupiter.version}</version>-->
        <!--<scope>test</scope>-->
        <!--</dependency>-->
--------------------------------------------------------------------------------------------------------
language: java
jdk:
  - oraclejdk8
branches:
  only:
    - master
script: mvn -f chapter-8/build/pom.xml verify
before_script:
  - "export DISPLAY=:99.0"
  - "sh -e /etc/init.d/xvfb start"
  - sleep 3 # give xvfb some time to start
after_success:
  - mvn -f chapter-8/build/pom.xml test jacoco:report coveralls:report
--------------------------------------------------------------------------------------------------------
after_success:  - mvn -f sample.application/build/pom.xml test \    jacoco:report coveralls:report
sudo service network-manager restar
sudo ufw disable
sudo ufw app list
sudo ufw allow 'Apache Full'

sudo ufw status
sudo service apache2 force-reload

sudo systemctl disable apache2
sudo systemctl enable apache2

vim: syntax=apache ts=4 sw=4 sts=4 sr noet

sudo a2ensite example1.conf
sudo service apache2 force-reload

Listen 8080Listen 8181# 1st vhost<VirtualHost *:8080>ServerAdmin webmaster@localhostDocumentRoot /var/www/htmlDirectoryIndex index3.htmlErrorLog ${APACHE_LOG_DIR}/error.logCustomLog ${APACHE_LOG_DIR}/access.log combined</VirtualHost># 2nd vhost<VirtualHost *:8181>ServerAdmin webmaster@localhostDocumentRoot /var/www/htmlDirectoryIndex index4.htmlErrorLog ${APACHE_LOG_DIR}/error.logCustomLog ${APACHE_LOG_DIR}/access.log combined</VirtualHost>

sudo apachectl -S

export APACHE_LOG_DIR=/var/log/apache2$SUFFI
grep APACHE_LOG_DIR /etc/apache2/envvars
tail –fn 1 access.log
















--------------------------------------------------------------------------------------------------------

import static book.twju.timeline.util.Exceptions.guard;
import static java.lang.String.format;
import static org.eclipse.jgit.api.Git.open;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.Callable;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.errors.RepositoryNotFoundException;

class GitOperator {
  
  static final String DIRECTORY_CONTAINS_NO_GIT_REPOSITORY = "Directory <%s> contains no git repository.";
  
  private final File repositoryLocation;
  
  @FunctionalInterface
  interface GitOperation<T> {
    T execute( Git git ) throws Exception;
  }

  GitOperator( File repositoryLocation ) {
    this.repositoryLocation = repositoryLocation;
    openRepository().close();
  }
  
  <T> T execute( GitOperation<T> gitOperation ) {
     Git git = openRepository();
     try {
       return guarded( () -> gitOperation.execute( git ) );
     } finally {
       git.close();
     }
  }

  static <T> T guarded( Callable<T> callable ) {
    return guard( callable ).with( IllegalStateException.class );
  }

  private Git openRepository() {
    return guarded( () -> openRepository( repositoryLocation ) );
  }

  private static Git openRepository( File repositoryDir ) throws IOException {
    try {
      return open( repositoryDir ); 
    } catch ( RepositoryNotFoundException rnfe ) {
      throw new IllegalArgumentException( format( DIRECTORY_CONTAINS_NO_GIT_REPOSITORY, repositoryDir ), rnfe );
    }
  }
}
--------------------------------------------------------------------------------------------------------
// в группе все ассерты исполняются независимо,
// успех - когда прошли успешно все ассерты
assertAll("habr",
    () -> assertThat("https://habrahabr.ru", startsWith("https")),
    () -> assertThat("https://habrahabr.ru", endsWith(".ru"))
);

assertIterableEquals(asList(1, 2, 3), asList(1, 2, 3));

Assertions.assertLinesMatch(
    asList("можно сравнивать строки", "а можно по regex: \\d{2}\\.\\d{2}\\.\\d{4}"),
    asList("можно сравнивать строки", "а можно по regex: 12.09.2017")
);

// JUnit 4
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface Test {
    Class<? extends Throwable> expected() default Test.None.class;

    long timeout() default 0L;

    public static class None extends Throwable {
        private static final long serialVersionUID = 1L;

        private None() {
        }
    }
}
--------------------------------------------------------------------------------------------------------
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class StandardTests {

    // вместо @BeforeClass
    @BeforeAll
    static void initAll() {
    }

    // вместо @Before
    @BeforeEach
    void init() {
    }

    @Test
    void succeedingTest() {
    }

    @Test
    void failingTest() {
        fail("a failing test");
    }

    // Вместо @Ignore
    @Test
    @Disabled("for demonstration purposes")
    void skippedTest() {
        // not executed
    }

    // Новая аннотация для улучшения читаемости при выводе результатов тестов.
    @DisplayName("╯°□°）╯")
    void testWithDisplayNameContainingSpecialCharacters() {}

    // вместо @After
    @AfterEach
    void tearDown() {
    }

    // вместо @AfterClass
    @AfterAll
    static void tearDownAll() {
    }

}
--------------------------------------------------------------------------------------------------------
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.EmptyStackException;
import java.util.Stack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("A stack")
class TestingAStackDemo {

    Stack<Object> stack;

    @Test
    @DisplayName("is instantiated with new Stack()")
    void isInstantiatedWithNew() {
        new Stack<>();
    }

    @Nested
    @DisplayName("when new")
    class WhenNew {

        @BeforeEach
        void createNewStack() {
            stack = new Stack<>();
        }

        @Test
        @DisplayName("is empty")
        void isEmpty() {
            assertTrue(stack.isEmpty());
        }

        @Test
        @DisplayName("throws EmptyStackException when popped")
        void throwsExceptionWhenPopped() {
            assertThrows(EmptyStackException.class, () -> stack.pop());
        }

        @Test
        @DisplayName("throws EmptyStackException when peeked")
        void throwsExceptionWhenPeeked() {
            assertThrows(EmptyStackException.class, () -> stack.peek());
        }

        @Nested
        @DisplayName("after pushing an element")
        class AfterPushing {

            String anElement = "an element";

            @BeforeEach
            void pushAnElement() {
                stack.push(anElement);
            }

            @Test
            @DisplayName("it is no longer empty")
            void isNotEmpty() {
                assertFalse(stack.isEmpty());
            }

            @Test
            @DisplayName("returns the element when popped and is empty")
            void returnElementWhenPopped() {
                assertEquals(anElement, stack.pop());
                assertTrue(stack.isEmpty());
            }

            @Test
            @DisplayName("returns the element when peeked but remains not empty")
            void returnElementWhenPeeked() {
                assertEquals(anElement, stack.peek());
                assertFalse(stack.isEmpty());
            }
        }
    }
}

@RepeatedTest(5)
void repeatedTest() {
    System.out.println("Этот тест будет запущен пять раз. ");
}

@ParameterizedTest
@EnumSource(value = TimeUnit.class, names = { "DAYS", "HOURS" })
void testWithEnumSourceInclude(TimeUnit timeUnit) {
    assertTrue(EnumSet.of(TimeUnit.DAYS, TimeUnit.HOURS).contains(timeUnit));
}


https://habr.com/ru/post/337700/

@ParameterizedTest
@ArgumentsSource(MyArgumentsProvider.class)
void testWithArgumentsSource(String argument) {
    assertNotNull(argument);
}

static class MyArgumentsProvider implements ArgumentsProvider {
    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        return Stream.of("foo", "bar").map(Arguments::of);
    }
}

Если вы укажите над классом @TestInstance(Lifecycle.PER_CLASS) то вы можете не делать @BeforeAll/@AfterAll статическими. Это же работает и для Котлина.
--------------------------------------------------------------------------------------------------------
cobertura-report -–format html --datafile cobertura.ser     --destination reports src
--------------------------------------------------------------------------------------------------------
buildscript {    ext {springBootVersion = '2.1.0.RELEASE'    }    repositories {mavenCentral()    }    dependencies {classpath("org.springframework.boot:spring-boot-gradle-plugin:${springBootVersion}")    }}apply plugin: 'java'apply plugin: 'org.springframework.boot'apply plugin: 'io.spring.dependency-management'dependencies {    compile 'org.springframework.boot:spring-boot-starter'}repositories {    mavenCentral()}
--------------------------------------------------------------------------------------------------------
mvn install:install-file -Dfile=junit-4.6/junit-4.6.jar -DgroupId=junit -DartifactId=junit -Dversion=4.6 -Dpackaging=jar 

--------------------------------------------------------------------------------------------------------
import java.util.Map;public class CustomizedErrorAttributes extends DefaultErrorAttributes {@Overridepublic Map<String, Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace) {Map<String, Object> errorAttributes =super.getErrorAttributes(webRequest, includeStackTrace);errorAttributes.put("parameters", webRequest.getParameterMap());return errorAttributes;}}
--------------------------------------------------------------------------------------------------------
@Beanpublic LocaleResolver localeResolver () {return new AcceptHeaderLocaleResolver();}

@Beanpublic LocaleResolver localeResolver () {    SessionLocaleResolver localeResolver = new SessionLocaleResolver();    localeResolver.setDefaultLocale(new Locale("en"));return localeResolver;}

@Beanpublic LocaleResolver localeResolver() {    CookieLocaleResolver cookieLocaleResolver = new CookieLocaleResolver();    cookieLocaleResolver.setCookieName("language");    cookieLocaleResolver.setCookieMaxAge(3600);    cookieLocaleResolver.setDefaultLocale(new Locale("en"));return cookieLocaleResolver;}

@Beanpublic LocaleResolver localeResolver() {    FixedLocaleResolver cookieLocaleResolver = new FixedLocaleResolver();    cookieLocaleResolver.setDefaultLocale(new Locale("en"));return cookieLocaleResolver;}
--------------------------------------------------------------------------------------------------------
keytool -genkey -keyalg RSA -alias sb2-recipes -keystore sb2-recipes.pfx -storepass password -validity 3600 -keysize 4096 -storetype pkcs1

server.ssl.key-store=classpath:sb2-recipes.pfxserver.ssl.key-store-type=pkcs12server.ssl.key-store-password=passwordserver.ssl.key-password=passwordserver.ssl.key-alias=sb2-recipes

@Beanpublic TomcatServletWebServerFactory tomcatServletWebServerFactory() {  var factory = new TomcatServletWebServerFactory();  factory.addAdditionalTomcatConnectors(httpConnector());return factory;}

private Connector httpConnector() {   var connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);  connector.setScheme("http");  connector.setPort(8080);  connector.setSecure(false);return connector;}

@Beanpublic TomcatServletWebServerFactory tomcatServletWebServerFactory() {  var factory = new TomcatServletWebServerFactory();  factory.addAdditionalTomcatConnectors(httpConnector());  factory.addContextCustomizers(securityCustomizer());return factory;}private Connector httpConnector() {   var connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);  connector.setScheme("http");  connector.setPort(8080);  connector.setSecure(false);  connector.setRedirectPort(8443);return connector;}private TomcatContextCustomizer securityCustomizer() {return context -> {    var securityConstraint = new SecurityConstraint();    securityConstraint.setUserConstraint("CONFIDENTIAL");    var collection = new SecurityCollection();    collection.addPattern("/*");    securityConstraint.addCollection(collection);    context.addConstraint(securityConstraint);  };}

@Beanpublic BeanPostProcessor addHttpConnectorProcessor() {return new BeanPostProcessor() {    @Overridepublic Object postProcessBeforeInitialization(Object bean, String beanName)throws BeansException {if (bean instanceof TomcatServletWebServerFactory) {var factory = (TomcatServletWebServerFactory) bean;factory.addAdditionalTomcatConnectors(httpConnector());}return bean;    }  };}

package com.apress.springbootrecipes.library;import org.springframework.web.bind.annotation.GetMapping;import org.springframework.web.bind.annotation.RestController;import java.util.concurrent.Callable;import java.util.concurrent.ThreadLocalRandom;@RestControllerpublic class HelloWorldController {@GetMappingpublic Callable<String> hello() {return () -> {Thread.sleep(ThreadLocalRandom.current().nextInt(5000));return "Hello World, from Spring Boot 2!";};}}

@RestControllerpublic class HelloWorldController {private final TaskExecutor taskExecutor;public HelloWorldController(TaskExecutor taskExecutor) {this.taskExecutor = taskExecutor;  }  @GetMappingpublic CompletableFuture<String> hello() {return CompletableFuture.supplyAsync(() -> {randomDelay();return "Hello World, from Spring Boot 2!";    }, taskExecutor);  }private void randomDelay() {try {Thread.sleep(ThreadLocalRandom.current().nextInt(5000));    } catch (InterruptedException e) {Thread.currentThread().interrupt();    }  }}

double amount = ThreadLocalRandom.current().nextDouble(1000.00d)

@GetMapping("/orders")public SseEmitter orders() {SseEmitter emitter = new SseEmitter();ExecutorService executor = Executors.newSingleThreadExecutor();executor.execute(() -> {var orders = orderService.findAll();try {for (var order : orders) {randomDelay();emitter.send(order);}emitter.complete();} catch (IOException e) {emitter.completeWithError(e);}});executor.shutdown();return emitter;}

User user = Reflection.constructor().in(User.class).newInstance();


--------------------------------------------------------------------------------------------------------
database.driverClassName=org.hsqldb.jdbcDriver               database.url=jdbc:hsqldb:mem:my-project-test;shutdown=true  database.dialect=hsqldb                                     database.schemaNames=PUBLIC                                 unitils.modules=database,jpa,dbunit 
--------------------------------------------------------------------------------------------------------
import org.junit.Test;import org.unitils.UnitilsJUnit4;import org.unitils.database.annotations.TestDataSource;import org.unitils.dbunit.annotation.DataSet;import org.unitils.dbunit.annotation.ExpectedDataSet;import com.manning.junitbook.ch19.model.User;publicclass UserDaoJpaImplTest extends UnitilsJUnit4 {  @JpaEntityManagerFactory(persistenceUnit="chapter-19")          @PersistenceContext                                         EntityManager em;private final UserDaoJpaImpl dao = new UserDaoJpaImpl();  @Beforepublic void prepareDao() {                        dao.setEntityManager(em);  }  @Test  @DataSet("user.xml")public void testGetUserById() throws Exception {       long id = 1;    User user = dao.getUserById(id);    assertUser(user);  }[...]}

@TestDataSourcevoid setDataSource(DataSource ds) throws SQLException {         Connection connection = ds.getConnection();    dao.setConnection(connection);    dao.createTables();  }

@Test  @DataSets(setUpDataSet="/user-with-telephone.xml")public void testGetUserByIdWithTelephone() throws Exception {    beginTransaction();long id = ELFunctionMapperImpl.getId(User.class);    User user = dao.getUserById(id);    commitTransaction();    assertUserWithTelephone(user);  }  @Test  @DataSets(assertDataSet="/user-with-telephone.xml")public void testAddUserWithTelephone() throws Exception {    beginTransaction();    User user = newUserWithTelephone();    dao.addUser(user);    commitTransaction();long id = user.getId();    assertTrue(id>0);  }

import org.hibernate.event.PostInsertEvent;import org.hibernate.event.PostInsertEventListener;public class ELPostInsertEventListener implements PostInsertEventListener {public void onPostInsert(PostInsertEvent event) {    String className = event.getEntity().getClass().getSimpleName();        Long id = (Long) event.getId();    ELFunctionMapperImpl.setId(className, id);   }}

hibernate.ejb.event.post-insert=  ➥org.hibernate.ejb.event.EJB3PostInsertEventListener,➥com.manning.jia.chapter18.hibernate.ELPostInsertEventListener

@Retention(RetentionPolicy.RUNTIME)@Target(ElementType.METHOD)public @interface DataSets {  String setUpDataSet() default "/empty.xml";        String assertDataSet() default "";                      }

public class UserDaoJdbcImplAnnotationTest extends  AbstractDbUnitTemplateTestCase {  @Test  @DataSets(setUpDataSet="/user-token.xml")public void testGetUserById() throws Exception {    User user = dao.getUserById(id);    assertUser(user);  }    @Test  @DataSets(assertDataSet="/user-token.xml")public void testAddUser() throws Exception {    User user = newUser();    id = dao.addUser(user);    assertTrue(id>0);  }}
--------------------------------------------------------------------------------------------------------
access("hasAuthority('ADMIN') " +"or @accessChecker.hasLocalAccess(authentication)"

Stream.of(names).filter(name -> name.toLowerCase().contains("jms")).sorted(Comparator.naturalOrder()).forEach(name -> {Object bean = ctx.getBean(name);System.out.printf(MSG, name, bean.getClass().getSimpleName());})

http://localhost:8090/actuator/metrics/system.cpu.usage

management.metrics.enable.system=falsemanagement.metrics.enable.tomcat=fals
--------------------------------------------------------------------------------------------------------
<plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId><configuration><executable>true</executable></configuration></plugin>

your-application.conf

JAVA_OPTS=-Xmx1024mDEBUG=true

<plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId><dependencies><dependency><groupId>org.springframework.boot.experimental</groupId><artifactId>spring-boot-thin-layout</artifactId><version>1.0.15.RELEASE</version></dependency></dependencies></plugin>

META-INF/thin.properties

thin.repo

FROM openjdk:11-jre-slimVOLUME /tmpARG JAR_FILECOPY ${JAR_FILE} app.jarENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"

<plugin><groupId>com.spotify</groupId><artifactId>dockerfile-maven-plugin</artifactId><version>1.4.4</version><configuration><repository>spring-boot-recipes/${project.name}</repository><tag>${project.version}</tag><buildArgs><JAR_FILE>target/${project.build.finalName}.jar</JAR_FILE></buildArgs></configuration><dependencies><dependency><groupId>javax.activation</groupId><artifactId>javax.activation-api</artifactId><version>1.2.0</version></dependency><dependency><groupId>org.codehaus.plexus</groupId><artifactId>plexus-archiver</artifactId><version>3.6.0</version></dependency></dependencies></plugin>

ocker run -d -e AUDIENCE='Docker' spring-boot-recipes/dockerize:2.0.0-SNAPSHOT

go get github.com/marpaia/graphite-golang

$ java -jar myapp.jar --thin.dryrun --thin.root=target/thin/root
$ java -jar myapp.jar --thin.library=org.springframework.boot.experimental:spring-boot-thin-tools-converter:1.0.21.RELEASE
$ java -jar myapp-exec.jar

$ CP1=`java -jar myapp.jar --thin.classpath=path`
$ CP2=`java -jar otherapp.jar --thin.classpath=path --thin.parent=myapp.jar`

$ java -XX:+UnlockCommercialFeatures -XX:+UseAppCDS -Xshare:off \
  -XX:DumpLoadedClassList=app.classlist \
  -noverify -cp $CP1:myapp.jar demo.MyApplication
$ java -XX:+UnlockCommercialFeatures -XX:+UseAppCDS -Xshare:dump \
  -XX:SharedArchiveFile=app.jsa -XX:SharedClassListFile=app.classlist \
  -noverify -cp $CP1

$ java -XX:+UnlockCommercialFeatures -XX:+UseAppCDS -Xshare:on \
  -XX:SharedArchiveFile=app.jsa -noverify -cp $CP1:myapp.jar demo.MyApplication 
$ java -XX:+UnlockCommercialFeatures -XX:+UseAppCDS -Xshare:on \
  -XX:SharedArchiveFile=app.jsa -noverify -cp $CP1:otherapp.jar demo.OtherApplication
  
./mvnw spring-boot-thin:resolve -Dthin.repo=http://localhost:8081/repository/maven-central
./gradlew thinResolve -P thin.repo=http://localhost:8081/repository/maven-central
--------------------------------------------------------------------------------------------------------
	static class ServiceStream extends ByteArrayOutputStream {

		public ServiceStream() {
			super(1024);
		}

		public void append(String content) throws IOException {
			if (count > 0 && buf[count - 1] != '\n' && buf[count - 1] != '\r') {
				write('\n');
			}

			byte[] contentBytes = content.getBytes("UTF-8");
			this.write(contentBytes);
		}

		public InputStream toInputStream() {
			return new ByteArrayInputStream(buf, 0, count);
		}

	}
--------------------------------------------------------------------------------------------------------
mvn install -s settings.xml

mvn release:prepare -Preporting,distribution
mvn release:perform -Preporting,distribution
--------------------------------------------------------------------------------------------------------
@DisabledIfSystemProperty(named = "file.separator", matches = "[/]")
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.*;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public class ConditionalAnnotationsUnitTest {
    @Test
    @EnabledOnOs({OS.WINDOWS, OS.MAC})
    public void shouldRunBothWindowsAndMac() {
        System.out.println("runs on Windows and Mac");
    }

    @Test
    @DisabledOnOs(OS.LINUX)
    public void shouldNotRunAtLinux() {
        System.out.println("will not run on Linux");
    }

    @Test
    @EnabledOnJre({JRE.JAVA_10, JRE.JAVA_11})
    public void shouldOnlyRunOnJava10And11() {
        System.out.println("runs with java 10 and 11");
    }

    @Test
    @DisabledOnJre(JRE.OTHER)
    public void thisTestOnlyRunsWithUpToDateJREs() {
        System.out.println("this test will only run on java8, 9, 10 and 11.");
    }

    @Test
    @EnabledIfSystemProperty(named = "java.vm.vendor", matches = "Oracle.*")
    public void onlyIfVendorNameStartsWithOracle() {
        System.out.println("runs only if vendor name starts with Oracle");
    }

    @Test
    @DisabledIfSystemProperty(named = "file.separator", matches = "[/]")
    public void disabledIfFileSeperatorIsSlash() {
        System.out.println("Will not run if file.sepeartor property is /");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "GDMSESSION", matches = "ubuntu")
    public void onlyRunOnUbuntuServer() {
        System.out.println("only runs if GDMSESSION is ubuntu");
    }

    @Test
    @DisabledIfEnvironmentVariable(named = "LC_TIME", matches = ".*UTF-8.")
    public void shouldNotRunWhenTimeIsNotUTF8() {
        System.out.println("will not run if environment variable LC_TIME is UTF-8");
    }

    @Test
    @EnabledIf("'FR' == systemProperty.get('user.country')")
    public void onlyFrenchPeopleWillRunThisMethod() {
        System.out.println("will run only if user.country is FR");
    }

    @Test
    @DisabledIf("java.lang.System.getProperty('os.name').toLowerCase().contains('mac')")
    public void shouldNotRunOnMacOS() {
        System.out.println("will not run if our os.name is mac");
    }

    @Test
    @EnabledIf(value = {
            "load('nashorn:mozilla_compat.js')",
            "importPackage(java.time)",
            "",
            "var thisMonth = LocalDate.now().getMonth().name()",
            "var february = Month.FEBRUARY.name()",
            "thisMonth.equals(february)"
    },
            engine = "nashorn",
            reason = "Self-fulfilling: {result}")
    public void onlyRunsInFebruary() {
        System.out.println("this test only runs in February");
    }

    @Test
    @DisabledIf("systemEnvironment.get('XPC_SERVICE_NAME') != null " +
            "&& systemEnvironment.get('XPC_SERVICE_NAME').contains('intellij')")
    public void notValidForIntelliJ() {
        System.out.println("this test will run if our ide is INTELLIJ");
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Test
    @DisabledOnOs({OS.WINDOWS, OS.SOLARIS, OS.OTHER})
    @EnabledOnJre({JRE.JAVA_9, JRE.JAVA_10, JRE.JAVA_11})
    @interface ThisTestWillOnlyRunAtLinuxAndMacWithJava9Or10Or11 {
    }

    @ThisTestWillOnlyRunAtLinuxAndMacWithJava9Or10Or11
    public void someSuperTestMethodHere() {
        System.out.println("this method will run with java9, 10, 11 and Linux or macOS.");
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @DisabledIf("Math.random() >= 0.5")
    @interface CoinToss {
    }

    @RepeatedTest(2)
    @CoinToss
    public void gamble() {
        System.out.println("This tests run status is a gamble with %50 rate");
    }
}
--------------------------------------------------------------------------------------------------------
npm install express
npm install -D @types/express
--------------------------------------------------------------------------------------------------------
import java.io.Serializable;
import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.solr.analysis.LowerCaseFilterFactory;
import org.apache.solr.analysis.SnowballPorterFilterFactory;
import org.apache.solr.analysis.StandardTokenizerFactory;
import org.apache.solr.analysis.SynonymFilterFactory;
import org.hibernate.search.annotations.Analyzer;
import org.hibernate.search.annotations.AnalyzerDef;
import org.hibernate.search.annotations.Boost;
import org.hibernate.search.annotations.DateBridge;
import org.hibernate.search.annotations.Field;
import org.hibernate.search.annotations.Index;
import org.hibernate.search.annotations.Indexed;
import org.hibernate.search.annotations.Latitude;
import org.hibernate.search.annotations.Longitude;
import org.hibernate.search.annotations.Parameter;
import org.hibernate.search.annotations.Resolution;
import org.hibernate.search.annotations.Spatial;
import org.hibernate.search.annotations.SpatialMode;
import org.hibernate.search.annotations.Store;
import org.hibernate.search.annotations.TokenFilterDef;
import org.hibernate.search.annotations.TokenizerDef;

/**
*
* @author sam
*/
@Entity
@Table(name = "myisam_product_article", catalog = "hibernatedb", schema = "")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "MyisamProductArticle.findAll", query = "SELECT m FROM MyisamProductArticle m"),
    @NamedQuery(name = "MyisamProductArticle.findByArticleId", query = "SELECT m FROM MyisamProductArticle m WHERE m.articleId = :articleId"),
    @NamedQuery(name = "MyisamProductArticle.findByLat", query = "SELECT m FROM MyisamProductArticle m WHERE m.lat = :lat"),
    @NamedQuery(name = "MyisamProductArticle.findByLon", query = "SELECT m FROM MyisamProductArticle m WHERE m.lon = :lon"),
    @NamedQuery(name = "MyisamProductArticle.findByCreationDate", query = "SELECT m FROM MyisamProductArticle m WHERE m.creationDate = :creationDate")})

@Spatial(spatialMode = SpatialMode.GRID)
//This annotation tells hibernate search that this class has to be indexed
@Indexed(index = "MyisamProductArticle")
@Analyzer(impl = org.apache.lucene.analysis.standard.StandardAnalyzer.class)
@AnalyzerDef(name = "customanalyzer", tokenizer = @TokenizerDef(factory = StandardTokenizerFactory.class),
        filters = {@TokenFilterDef(factory = LowerCaseFilterFactory.class),
                    @TokenFilterDef(factory = SnowballPorterFilterFactory.class, params = {
                        @Parameter(name = "language", value = "English"),
                    }),
                    @TokenFilterDef(factory = SynonymFilterFactory.class, params = {
                        @Parameter(name = "ignoreCase", value = "true"),
                        @Parameter(name = "expand", value = "true"),
                        @Parameter(name = "synonyms", value="syntest.txt")})
                    })
public class MyisamProductArticle implements Serializable, Comparable<MyisamProductArticle> {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "article_id")
    private Integer articleId;
    @Lob
    @Size(max = 65535)
    @Column(name = "a_desc")
    @Analyzer(definition = "customanalyzer")
    @Field(index = Index.YES, store = Store.YES)
    private String aDesc;
    // @Max(value=?)  @Min(value=?)//if you know range of your decimal fields consider using these annotations to enforce field validation
    @Column(name = "lat")
    @Latitude(of="location")
    private Double lat;
    @Column(name = "lon")
    @Longitude(of="location")
    private Double lon;
    @Column(name = "creation_date")
    @Temporal(TemporalType.DATE)
    private Date creationDate;

    public MyisamProductArticle() {
    }

    public MyisamProductArticle(Integer articleId) {
        this.articleId = articleId;
    }

    public Integer getArticleId() {
        return articleId;
    }

    public void setArticleId(Integer articleId) {
        this.articleId = articleId;
    }

    public String getADesc() {
        return aDesc;
    }

    public void setADesc(String aDesc) {
        this.aDesc = aDesc;
    }

    public Double getLat() {
        return lat;
    }

    public void setLat(Double lat) {
        this.lat = lat;
    }

    public Double getLon() {
        return lon;
    }

    public void setLon(Double lon) {
        this.lon = lon;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (articleId != null ? articleId.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof MyisamProductArticle)) {
            return false;
        }
        MyisamProductArticle other = (MyisamProductArticle) object;
        if ((this.articleId == null && other.articleId != null) || (this.articleId != null && !this.articleId.equals(other.articleId))) {
            return false;
        }
        return true;
    }

    // default comparator on Date
    @Override
    public int compareTo(MyisamProductArticle compareArticle) {
        //ascending order
        return this.creationDate.compareTo(compareArticle.creationDate);

        //descending order
        //return compareAritcle.compareTo(this.creationDate.creationDate);

   }
    
    @Override
    public String toString() {
        return "HibernateSearch.entity.MyisamProductArticle[ articleId=" + articleId + " ]";
    }
    
}


Thank you for your time again.
Samuel


Top	 Profile   

samsam9988	
 Post subject: Re: DelegateNamedAnalyzer not found in Hibernate-search 4.2.0PostPosted: Mon Jan 28, 2013 5:18 am 
Regular
Regular

Joined: Fri Feb 04, 2011 8:34 pm
Posts: 66	
After added value="LUCENE_36" in the following persistence.xml file,

Code:
<?xml version="1.0" encoding="UTF-8"?>
<persistence version="1.0" xmlns="http://java.sun.com/xml/ns/persistence" 
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
xsi:schemaLocation="http://java.sun.com/xml/ns/persistence http://java.sun.com/xml/ns/persistence/persistence_1_0.xsd">
  <persistence-unit name="HibernateSeasrchTestPU" transaction-type="JTA">
    <provider>org.hibernate.ejb.HibernatePersistence</provider>
    <jta-data-source>java:jboss/datasources/HibernateSearchTest</jta-data-source>
    <exclude-unlisted-classes>false</exclude-unlisted-classes>
    <properties>
      <property name="hibernate.hbm2ddl.auto" value="update"/>
      <property name="hibernate.show_sql" value="true"/>
      <property name="hibernate.format_sql" value="true"/>
      <property name="hibernate.max_fetch_depth" value="4"/>
      <property name="hibernate.default_batch_fetch_size" value="365"/>
       
      <property name="hibernate.search.default.directory_provider" value="filesystem"/>
      <property name="hibernate.search.default.indexBase" value="./lucene/indexes"/>
      <property name="hibernate.search.default.batch.merge_factor" value="10"/>
      <property name="hibernate.search.default.batch.max_buffered_docs" value="10"/>
      <property name="hibernate.search.lucene_version" value="LUCENE_36" />

    </properties>
  </persistence-unit>
</persistence>
--------------------------------------------------------------------------------------------------------
@Component
public class TokenProcessingFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = this.getAsHttpRequest(request);
        String authToken = this.extractAuthTokenFromRequest(httpRequest);
        String userName = TokenUtils.getUserNameFromToken(authToken);
        if (userName != null) {/*
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);*/
            UserDetails userDetails = fakeUserDetails();
            if (TokenUtils.validateToken(authToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            }
        }
        chain.doFilter(request, response);
    }

    private HttpServletRequest getAsHttpRequest(ServletRequest request){
        if (!(request instanceof HttpServletRequest)) {
            throw new RuntimeException("Expecting an HTTP request");
        }
        return (HttpServletRequest) request;
    }


    private String extractAuthTokenFromRequest(HttpServletRequest httpRequest) {
        /* Get token from header */
        String authToken = httpRequest.getHeader("x-auth-token");
        /* If token not found get it from request parameter */
        if (authToken == null) {
            authToken = httpRequest.getParameter("token");
        }
        return authToken;
    }

    private UserDetails fakeUserDetails(){
        UsernamePasswordAuthenticationToken authenticationToken = new
                UsernamePasswordAuthenticationToken("user","password");

        List<SimpleGrantedAuthority> auth= new ArrayList<>();
        auth.add(new SimpleGrantedAuthority("USER"));
        return  new User("user","password",auth);
    }
}

@Bean
TokenProcessingFilter tokenProcessingFilter() {
  TokenProcessingFilter tokenProcessingFilter = new TokenProcessingFilter();
  tokenProcessingFilter.setAuthenticationManager(authenticationManager());
  return tokenProcessingFilter;
}

protected void configure(HttpSecurity http) throws Exception {
  ...
  .addFilter(tokenProcessingFilter())
--------------------------------------------------------------------------------------------------------
	@ElementCollection
	@JoinTable(name = "WEBSITE_COOKIES", joinColumns = @JoinColumn(name = "WEBSITE_ID"))
	@MapKeyColumn(name = "COOKIES_KEY")
	@Column(name = "COOKIES_VALUE")
	private Map<String, String> cookies;
--------------------------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import com.mifmif.networking.mspider.model.ParameterValue;

/**
 * It present the parameter model that has a website. values used to query the
 * website are presented by <code>ParameterValue</code>
 * 
 * @author y.mifrah
 *
 */
@Entity
@Table(name = "URL_PARAMETER")
public class URLParameter {

	@Id
	@SequenceGenerator(name = "URL_PARAMETER_SEQ_GEN", sequenceName = "URL_PARAMETER_SEQ_GEN")
	@GeneratedValue(generator = "URL_PARAMETER_SEQ_GEN", strategy = GenerationType.TABLE)
	@Column(name = "ID")
	private Long id;

	/**
	 * Name of the parameter that will be used when requesting the url
	 */
	private String name;
	/**
	 * Value could have a constant value or a pattern expression that will be
	 * used to generate parameter value to use when requesting the url
	 */
	private String expression;

	/**
	 * description of the parameter (not used when we request the url)
	 */
	private String description;
	/**
	 * Type of the parameter : CONSTANT or PATTERN_EXPRESSION
	 */
	@Enumerated(EnumType.STRING)
	private URLParameterType type = URLParameterType.PATTERN_EXPRESSION;
	@ManyToOne
	@JoinColumn(name = "URL_PATTERN_ID")
	private URLPattern pattern;
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "urlParameter")
	private List<ParameterValue> parameterValues;

	/**
	 * 
	 */
	public URLParameter() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param pattern
	 * @param name
	 * @param value
	 */
	public URLParameter(URLPattern pattern, String name, String expression) {
		super();
		this.pattern = pattern;
		this.name = name;
		this.expression = expression;
		parameterValues = new ArrayList<ParameterValue>();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public URLParameterType getType() {
		return type;
	}

	public void setType(URLParameterType type) {
		this.type = type;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public URLPattern getPattern() {
		return pattern;
	}

	public void setPattern(URLPattern pattern) {
		this.pattern = pattern;
	}

	public String getExpression() {
		return expression;
	}

	public void setExpression(String expression) {
		this.expression = expression;
	}

	public List<ParameterValue> getParameterValues() {
		return parameterValues;
	}

	public void setParameterValues(List<ParameterValue> parameterValues) {
		this.parameterValues = parameterValues;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
}
--------------------------------------------------------------------------------------------------------
import java.util.HashMap;
import java.util.Map;

import com.mifmif.gefmmat.core.Agent;
import com.mifmif.gefmmat.core.Result;
import com.mifmif.gefmmat.core.Task;

/**
 * @author y.mifrah
 *
 */
public class CamouflageDishonestStudent extends Student {

	public CamouflageDishonestStudent() {
		setTaskHandler(new CamouflageDishonestTaskHandler(this));
	}

	class CamouflageDishonestTaskHandler extends HonestTaskHandler {
		Map<String, Status> proposerIdStatus = new HashMap<String, Status>();

		public CamouflageDishonestTaskHandler(Agent ownerAgent) {
			super(ownerAgent);
		}

		@Override
		public Result performTask(Task task) {
			boolean performFairly = isTimeToPerformFairly(task);
			Result result = null;
			if (performFairly) {
				result = prepareFairResult(task);
			} else {
				result = prepareUnfairResult(task);

			}
			updateProposerStatus(task, performFairly);
			return result;

		}

		private void updateProposerStatus(Task task, boolean performFairly) {
			String proposerId = task.getProposerId();
			Status status = proposerIdStatus.get(proposerId);
			if (performFairly) {
				status.incrementFairlyCount();
			} else {
				status.incrementUnfairlyCount();
			}
		}

		/**
		 * This method inform whether if the camouflageAgent could perform the task unfairly or fairly
		 * 
		 * @param task
		 * @return
		 */
		private boolean isTimeToPerformFairly(Task task) {
			String proposerId = task.getProposerId();
			Status status = proposerIdStatus.get(proposerId);
			if (status == null) {
				status = new Status();
				proposerIdStatus.put(proposerId, status);
				return true;
			}
			if (status.getFairCount() > 10)
				return false;
			// analyze status e.g. how many time did we perform a valid
			// result
			// for this agent.
			return true;
		}

	}

	static class Status {
		private long fairCount, unfairCount;// TODO we have to think about
											// another

		// structure that handle the order and the
		// services of tasks processed
		// fairly/unfairly

		public void incrementFairlyCount() {
			fairCount++;
		}

		public void incrementUnfairlyCount() {
			unfairCount++;
		}

		public long getFairCount() {
			return fairCount;
		}

		public long getUnfairCount() {
			return unfairCount;
		}
	}
}
--------------------------------------------------------------------------------------------------------
import java.util.Map;

import com.mifmif.gefmmat.core.Result;
import com.mifmif.gefmmat.core.Service;
import com.mifmif.gefmmat.core.Task;
import com.mifmif.gefmmat.testbed.student.exception.InvalidInputParameterException;
import com.mifmif.gefmmat.testbed.student.exception.TaskProcessingException;
import com.mifmif.gefmmat.testbed.student.operation.task.SpeedTask;
import com.mifmif.gefmmat.testbed.student.operation.task.EnergyTask.EnergyResult;
import com.mifmif.gefmmat.testbed.student.operation.task.SpeedTask.SpeedResult;

/**
 * @author y.mifrah
 *
 */
public class CalculateSpeed extends Service {
	private double d, t, speedResult;

	public CalculateSpeed() {
		setName("calculateSpeed");
	}

	@Override
	protected void prepareInputs(Task task) throws InvalidInputParameterException {
		try {
			d = ((SpeedTask) task).getD();
			t = ((SpeedTask) task).getT();
		} catch (NumberFormatException exception) {
			throw new InvalidInputParameterException();
		}
		return;
	}

	@Override
	protected Result processTask(Task task) throws TaskProcessingException {
		SpeedResult result = new SpeedResult();
		speedResult = d / t;
		result.setSpeedResult(speedResult);
		return result;
	}

	@Override
	public boolean isResultTaskValid(Task task) {
		try {
			SpeedResult curResult = (SpeedResult) task.getResult();
			SpeedResult validResult = (SpeedResult) execute(task);
			return curResult.getSpeedResult().equals(validResult.getSpeedResult());
		} catch (Exception exception) {
			exception.printStackTrace();
		}

		return false;
	}
}
--------------------------------------------------------------------------------------------------------
import java.util.Map;

import com.mifmif.gefmmat.core.Result;
import com.mifmif.gefmmat.core.Service;
import com.mifmif.gefmmat.core.Task;
import com.mifmif.gefmmat.testbed.student.exception.InvalidInputParameterException;
import com.mifmif.gefmmat.testbed.student.exception.TaskProcessingException;
import com.mifmif.gefmmat.testbed.student.operation.task.AdditionTask;
import com.mifmif.gefmmat.testbed.student.operation.task.AdditionTask.AdditionResult;

/**
 * Addition service implementation
 * 
 * @author y.mifrah
 *
 */
public class Addition extends Service {
	double a, b, additionResult;

	public Addition() {
		setName("addition");
	}

	@Override
	protected void prepareInputs(Task task) throws InvalidInputParameterException {
		try {
			a = ((AdditionTask) task).getA();
			b = ((AdditionTask) task).getB();
		} catch (Exception exception) {
			throw new InvalidInputParameterException();
		}
	}

	@Override
	protected Result processTask(Task task) throws TaskProcessingException {
		AdditionResult result = new AdditionResult();
		additionResult = a + b;
		result.setAdditionResult(additionResult);
		return result;
	}

	@Override
	public boolean isResultTaskValid(Task task) {
		try {
			AdditionResult curResult = (AdditionResult) task.getResult();
			AdditionResult validResult = (AdditionResult) execute(task);
			return curResult.getAdditionResult().equals(validResult.getAdditionResult());
		} catch (Exception exception) {
			exception.printStackTrace();
		}

		return false;
	}
}
--------------------------------------------------------------------------------------------------------
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * @author y.mifrah
 *
 */
public class Feature implements Serializable {

	private String id;
	private String name;
	private String value;
	private float SLAValue;
	private float width;
	/**
	 * 
	 */
	private static Map<String, Feature> featureMap = new HashMap<String, Feature>();

	private Feature() {
	}

	synchronized public static Feature getInstance(String featureName) {
		Feature feature = featureMap.get(featureName);
		if (feature == null) {
			feature = new Feature();
			feature.setName(featureName);
			featureMap.put(featureName, feature);
		}
		return feature;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * @param value
	 *            the value to set
	 */
	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id
	 *            the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}

	public float getSLAValue() {
		return SLAValue;
	}

	public void setSLAValue(float sLAValue) {
		SLAValue = sLAValue;
	}

	public float getWidth() {
		return width;
	}

	public void setWidth(float width) {
		this.width = width;
	}
}

import java.util.Date;

/**
 * Immutable ResponseTime Event class. The process control system creates these events. The
 * ResponseTimeEventHandler picks these up and processes them.
 */
public class ResponseTimeEvent {

    /** Response Time in milliseconds. */
    private int responseTime;
    
    /** Time responseTime reading was taken. */
    private Date timeOfReading;
    
    /**
     * Single value constructor.
     * @param value ResponseTime in Milliseconds.
     */
    /**
     * ResponseTime constructor.
     * @param responseTime ResponseTime in Milliseconds
     * @param timeOfReading Time of Reading
     */
    public ResponseTimeEvent(int responseTime, Date timeOfReading) {
        this.responseTime = responseTime;
        this.timeOfReading = timeOfReading;
    }

    /**
     * Get the ResponseTime.
     * @return ResponseTime in Milliseconds
     */
    public int getResponseTime() {
        return responseTime;
    }
       
    /**
     * Get time ResponseTime reading was taken.
     * @return Time of Reading
     */
    public Date getTimeOfReading() {
        return timeOfReading;
    }

    @Override
    public String toString() {
        return "ResponseTimeEvent ["+timeOfReading + ": " +responseTime + " ms]";
    }

}
--------------------------------------------------------------------------------------------------------
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

public class HttpSessionCreatedListener implements HttpSessionListener {
    private final Log logger = LogFactory.getLog(this.getClass());

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        String stackTrace = StringUtils.arrayToDelimitedString(Thread.currentThread().getStackTrace(), " ");
        logger.warn("HttpSession was created: " + stackTrace);
        if (event.getSession() == null) {
            return;
        }
        try {
            logger.warn("Invalidating unexpected HttpSession");
            event.getSession().invalidate();
        } catch (IllegalStateException e) {
            logger.warn("Could not invalidate already invalidated HttpSession", e);
        }
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.util.Assert;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Cross-site request forgery (CSRF or CSRF) protection using double submit cookies:
 * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet#Double_Submit_Cookies
 * <p>
 * Issues to be aware of when using double submit cookies for CSRF protection: http://security.stackexchange.com/a/61039
 * <p>
 * Some code borrowed from cloudfoundry/uaa under the Apache 2.0 license:
 * https://github.com/cloudfoundry/uaa/blob/41dba9d81dbdf24ede4fb9719de28b1b88b3e1b4/common/src/main/java/org/cloudfoundry/identity/uaa/web/CookieBasedCsrfTokenRepository.java
 */
public class CookieCsrfTokenRepository implements CsrfTokenRepository {
    public static final String DEFAULT_CSRF_COOKIE_NAME = "csrf";

    private SecureRandom secureRandom = new SecureRandom();
    private String csrfHeaderName = "X-CSRF-TOKEN";
    private String csrfParameterName = "_csrf";
    private String csrfCookieName = DEFAULT_CSRF_COOKIE_NAME;
    private String csrfCookiePath = null;
    private int csrfCookieMaxAgeSeconds = -1;  // default to session cookie (non-persistent)

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String tokenValue = new BigInteger(130, secureRandom).toString(32); // http://stackoverflow.com/a/41156
        return new DefaultCsrfToken(csrfHeaderName, csrfParameterName, tokenValue);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        Cookie csrfCookie;
        if (token == null) {
            csrfCookie = new Cookie(csrfCookieName, "");
            csrfCookie.setMaxAge(0);
        } else {
            csrfCookie = new Cookie(csrfCookieName, token.getToken());
            csrfCookie.setMaxAge(csrfCookieMaxAgeSeconds);
        }
        csrfCookie.setHttpOnly(true);
        csrfCookie.setSecure(request.isSecure());
        csrfCookie.setPath(csrfCookiePath);
        response.addCookie(csrfCookie);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie != null && csrfCookieName.equals(cookie.getName())) {
                    return new DefaultCsrfToken(csrfHeaderName, csrfParameterName, cookie.getValue());
                }
            }
        }
        return null;
    }

    public void setSecureRandom(SecureRandom secureRandom) {
        Assert.notNull(secureRandom);
        this.secureRandom = secureRandom;
    }

    public void setCsrfHeaderName(String csrfHeaderName) {
        Assert.notNull(csrfHeaderName);
        this.csrfHeaderName = csrfHeaderName;
    }

    public void setCsrfParameterName(String csrfParameterName) {
        Assert.notNull(csrfParameterName);
        this.csrfParameterName = csrfParameterName;
    }

    public void setCsrfCookieName(String csrfCookieName) {
        Assert.notNull(csrfCookieName);
        this.csrfCookieName = csrfCookieName;
    }

    public void setCsrfCookiePath(String csrfCookiePath) {
        this.csrfCookiePath = csrfCookiePath;
    }

    public void setCsrfCookieMaxAgeSeconds(int csrfCookieMaxAgeSeconds) {
        this.csrfCookieMaxAgeSeconds = csrfCookieMaxAgeSeconds;
    }
}


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import java.text.ParseException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class JwtEncryption implements TokenEncryption {
    private final Log logger = LogFactory.getLog(this.getClass());
    private final byte[] sessionJwtEncryptionKey;

    private List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers = new ArrayList<>(Collections.singletonList(new ExpirationJwtClaimsSetVerifier()));
    private int jwtExpirationSeconds = 3600;
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    private EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

    public JwtEncryption(String sessionJwtEncryptionKeyBase64) {
        Assert.notNull(sessionJwtEncryptionKeyBase64);
        this.sessionJwtEncryptionKey = Base64.getDecoder().decode(sessionJwtEncryptionKeyBase64);
    }

    @Override
    public String encryptAndSign(String jwtSubject) {
        try {
            Date date = Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(jwtExpirationSeconds).toInstant());
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(jwtSubject).expirationTime(date).build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), claimsSet);
            signedJWT.sign(new MACSigner(sessionJwtEncryptionKey));
            JWEHeader jweHeader = new JWEHeader.Builder(jweAlgorithm, encryptionMethod).contentType("JWT").build();
            JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT));
            jweObject.encrypt(new DirectEncrypter(sessionJwtEncryptionKey));
            return jweObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Could not create JWT", e);
        }
    }

    @Override
    public String decryptAndVerify(String encryptedAndSignedJwt) {
        try {
            JWEObject jweObject = JWEObject.parse(encryptedAndSignedJwt);
            jweObject.decrypt(new DirectDecrypter(sessionJwtEncryptionKey));
            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            if (!signedJWT.verify(new MACVerifier(sessionJwtEncryptionKey))) {
                logger.warn("JWT signature verification failed.");
                return null;
            }
            for (JwtClaimsSetVerifier verifier : jwtClaimsSetVerifiers) {
                if (!verifier.verify(signedJWT.getJWTClaimsSet())) {
                    logger.warn("JWT claims verification failed.");
                    return null;
                }
            }
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Could not parse JWT", e);
        }
    }

    public void setJwtClaimsSetVerifiers(List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers) {
        Assert.notNull(jwtClaimsSetVerifiers);
        this.jwtClaimsSetVerifiers = new ArrayList<>(jwtClaimsSetVerifiers);
    }

    public boolean addJwtClaimsSetVerifier(JwtClaimsSetVerifier jwtClaimsSetVerifier) {
        Assert.notNull(jwtClaimsSetVerifier);
        return this.jwtClaimsSetVerifiers.add(jwtClaimsSetVerifier);
    }

    public void setJwtExpirationSeconds(int jwtExpirationSeconds) {
        this.jwtExpirationSeconds = jwtExpirationSeconds;
    }

    public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
        Assert.notNull(jwsAlgorithm);
        this.jwsAlgorithm = jwsAlgorithm;
    }

    public void setJweAlgorithm(JWEAlgorithm jweAlgorithm) {
        Assert.notNull(jweAlgorithm);
        this.jweAlgorithm = jweAlgorithm;
    }

    public void setEncryptionMethod(EncryptionMethod encryptionMethod) {
        Assert.notNull(encryptionMethod);
        this.encryptionMethod = encryptionMethod;
    }
}
--------------------------------------------------------------------------------------------------------
    @Bean
    ServletListenerRegistrationBean<HttpSessionListener> httpSessionCreatedListener() {
        ServletListenerRegistrationBean<HttpSessionListener> listenerRegistrationBean = new ServletListenerRegistrationBean<>();
        listenerRegistrationBean.setListener(new HttpSessionCreatedListener());
        return listenerRegistrationBean;
    }
	
	import au.gov.dto.servlet.http.HttpSessionCreatedListener;
import au.gov.dto.servlet.http.HttpsOnlyFilter;
import au.gov.dto.servlet.http.NoHttpSessionFilter;
import au.gov.dto.springframework.security.web.context.CookieSecurityContextRepository;
import au.gov.dto.springframework.security.web.context.JwtEncryption;
import au.gov.dto.springframework.security.web.csrf.CookieCsrfTokenRepository;
import au.gov.dto.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.embedded.ServletContextInitializer;
import org.springframework.boot.context.embedded.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.http.HttpSessionListener;
import java.util.Collections;

@Configuration
class AppConfig {
    @Bean
    ServletContextInitializer noSessionTrackingServletContextInitializer() {
        return servletContext -> servletContext.setSessionTrackingModes(Collections.emptySet());
    }

    @Bean
    ServletListenerRegistrationBean<HttpSessionListener> httpSessionCreatedListener() {
        ServletListenerRegistrationBean<HttpSessionListener> listenerRegistrationBean = new ServletListenerRegistrationBean<>();
        listenerRegistrationBean.setListener(new HttpSessionCreatedListener());
        return listenerRegistrationBean;
    }

    @Bean
    FilterRegistrationBean noHttpSessionFilter() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new NoHttpSessionFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    CookieCsrfTokenRepository csrfTokenRepository() {
        return new CookieCsrfTokenRepository();
    }

    @Bean
    @Autowired
    CookieSecurityContextRepository securityContextRepository(@Value("${session.encryption.key.base64}") String sessionEncryptionKeyBase64) {
        return new CookieSecurityContextRepository(new JwtEncryption(sessionEncryptionKeyBase64));
    }

    @Bean
    CookieRequestCache cookieRequestCache() {
        return new CookieRequestCache();
    }

    @Bean
    FilterRegistrationBean httpsOnlyFilter() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new HttpsOnlyFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }
}
--------------------------------------------------------------------------------------------------------

import au.gov.dto.springframework.security.web.authentication.CookieSavedRequestAwareAuthenticationSuccessHandler;
import au.gov.dto.springframework.security.web.authentication.StatelessSimpleUrlAuthenticationFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Autowired
    private CsrfTokenRepository csrfTokenRepository;

    @Autowired
    private RequestCache requestCache;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
            .securityContext()
                .securityContextRepository(securityContextRepository)
                .and()
            .csrf()
                .csrfTokenRepository(csrfTokenRepository)
                .and()
            .requestCache()
                .requestCache(requestCache)
                .and()
            .anonymous()
                .disable()
            .authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .successHandler(new CookieSavedRequestAwareAuthenticationSuccessHandler(requestCache))
                .failureHandler(new StatelessSimpleUrlAuthenticationFailureHandler("/login?error"))
                .permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/")
                .permitAll();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(HttpMethod.GET, "/");
    }

    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
}
--------------------------------------------------------------------------------------------------------
package com.paragon.mailingcontour.commons.rest.handler;

import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class RequestFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String threadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName(String.format("%1$s_[started:%2$s | user:%3$s | uri:%4$s]_%1$s", threadName, timeNow(), user(), uri(request)));
            chain.doFilter(request, response);
        } finally {
            Thread.currentThread().setName(threadName);
        }
    }

    private String uri(ServletRequest request) {
        return ((HttpServletRequest) request).getRequestURI();
    }

    private String timeNow() {
        return ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private String user() {
        return "johndoe";
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}

--------------------------------------------------------------------------------------------------------
/**
 * An enumeration of the different types of operation supported by an endpoint.
 *
 * @author Andy Wilkinson
 * @since 2.0.0
 * @see Operation
 */
public enum OperationType {

	/**
	 * A read operation.
	 */
	READ,

	/**
	 * A write operation.
	 */
	WRITE,

	/**
	 * A delete operation.
	 */
	DELETE

}
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.AsyncConfigurerSupport;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@EnableAsync(proxyTargetClass = true)
@SpringBootApplication
public class Application extends AsyncConfigurerSupport {

  @Override
  public Executor getAsyncExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setTaskDecorator(new MdcTaskDecorator());
    executor.initialize();
    return executor;
  }

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }
--------------------------------------------------------------------------------------------------------
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import java.io.IOException;

@Component
public class MdcFilter extends GenericFilterBean {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      MDC.put("mdcData", "[userId:Duke]");
      chain.doFilter(request, response);
    } finally {
      MDC.clear();
    }
  }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Autowired
@Retention(RetentionPolicy.RUNTIME)
public @interface LocalizedMessage {

  String value() default "";

}
import org.springframework.beans.factory.InjectionPoint;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.annotation.AnnotationUtils;

@Configuration
public class MessageConfig {

  @Bean
  public MessageSource messageSource() {

    ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
    messageSource.setBasename("messages");

    return messageSource;
  }

  @Bean
  @Scope(scopeName = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
  public Message message(InjectionPoint ip) {

    LocalizedMessage localizedMessage = AnnotationUtils
        .getAnnotation(ip.getAnnotatedElement(), LocalizedMessage.class);

    String resourceBundleKey = localizedMessage.value();

    return new Message(messageSource(), resourceBundleKey);
  }

}
--------------------------------------------------------------------------------------------------------
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import javax.validation.constraints.NotNull;

@Aspect
@Component
public class NotNullParameterAspect {

  @Before("@within(com.moelholm.spring43.customannotations.BusinessService)")
  public void before(JoinPoint caller) {

    Method method = getCurrentMethod(caller);

    Object[] parameters = caller.getArgs();

    Annotation[][] parameterAnnotations = method.getParameterAnnotations();

    // Throw exception if a parameter value is null AND
    // at the same time declares that it must be @NotNull
    for (int i = 0; i < parameters.length; i++) {
      Object parameterValue = parameters[i];
      Annotation[] annotationsOnParameter = parameterAnnotations[i];

      if (parameterValue == null && hasNotNullAnnotation(annotationsOnParameter)) {
        String msgTemplate = String.format("Parameter at index %s must not be null", i);
        throw new IllegalArgumentException(msgTemplate);
      }
    }

  }

  private boolean hasNotNullAnnotation(Annotation... annotations) {
    return Arrays.asList(annotations).stream().anyMatch(a -> a.annotationType() == NotNull.class);
  }

  private Method getCurrentMethod(JoinPoint joinPoint) {
    MethodSignature signature = (MethodSignature) joinPoint.getSignature();
    return signature.getMethod();
  }
}
--------------------------------------------------------------------------------------------------------

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@SuppressWarnings("Convert2Lambda")
public class SessionListenerConfig {

    @Autowired
    private ActiveUsersService activeUsersService;

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
    }

    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> userAuthenticated() {
        return new ApplicationListener<AuthenticationSuccessEvent>() {
            @Override
            public void onApplicationEvent(AuthenticationSuccessEvent event) {
                UserDetails userDetails = (UserDetails) event.getAuthentication().getPrincipal();
                activeUsersService.userLoggedIn(userDetails.getUsername());
            }
        };
    }

    @Bean
    public ApplicationListener<SessionDestroyedEvent> sessionDestroyedListener() {
        return new ApplicationListener<SessionDestroyedEvent>() {
            @Override
            public void onApplicationEvent(SessionDestroyedEvent event) {
                UserDetails userDetails = (UserDetails) event.getSecurityContexts().stream()
                        .findFirst().get().getAuthentication().getPrincipal();
                activeUsersService.userLoggedOut(userDetails.getUsername());
            }
        };
    }

}

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.mvc.AbstractMvcEndpoint;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Component
public class ActiveUsersActuatorEndpoint extends AbstractMvcEndpoint {

    @Autowired
    private ActiveUsersService activeUsersService;

    public ActiveUsersActuatorEndpoint() {
        super("/activeusers", false /* sensitive */);
    }

    @RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ActiveUsersResponse listActiveUsers() {
        return new ActiveUsersResponse("Active users right now", activeUsersService.listActiveUsers());
    }

    @JsonPropertyOrder({"info", "activeUsers"})
    public static class ActiveUsersResponse {

        @JsonProperty
        private String info;

        @JsonProperty
        private List<String> activeUsers;

        public ActiveUsersResponse(String info, List<String> activeUsers) {
            this.info = info;
            this.activeUsers = activeUsers;
        }
    }

}
--------------------------------------------------------------------------------------------------------
version: '2'
services:
  cdbookstore-postgresql:
    image: postgres:11.3
    environment:
      - POSTGRES_USER=cdbookstoreDB
      - POSTGRES_PASSWORD=h2g2
    ports:
      - 5432:5432
--------------------------------------------------------------------------------------------------------
import javax.persistence.FetchType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static javax.persistence.FetchType.EAGER;

// @formatter:off
// tag::adocSnippet[]
@Target({METHOD, FIELD})
@Retention(RUNTIME)
public @interface Basic {

  FetchType fetch() default EAGER;
  boolean optional() default true;
}
// end::adocSnippet[]


import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

// @formatter:off
// tag::adocSnippet[]
@Target({METHOD, FIELD})
@Retention(RUNTIME)
public @interface Column {

  String  name()       default "";
  boolean unique()     default false;
  boolean nullable()   default true;
  boolean insertable() default true;
  boolean updatable()  default true;
  String  columnDefinition() default "";
  String  table()      default "";
  int     length()     default 255;
  int     precision()  default 0; // decimal precision
  int     scale()      default 0; // decimal scale
}
// end::adocSnippet[]


import javax.persistence.ForeignKey;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.UniqueConstraint;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static javax.persistence.ConstraintMode.PROVIDER_DEFAULT;

// @formatter:off
// tag::adocSnippet[]
@Target({METHOD, FIELD})
@Retention(RUNTIME)
public @interface JoinTable {

  String name() default "";
  String catalog() default "";
  String schema() default "";
  JoinColumn[] joinColumns() default {};
  JoinColumn[] inverseJoinColumns() default {};
  ForeignKey foreignKey() default @ForeignKey(PROVIDER_DEFAULT);
  ForeignKey inverseForeignKey() default @ForeignKey(PROVIDER_DEFAULT);
  UniqueConstraint[] uniqueConstraints() default {};
  Index[] indexes() default {};
}
// end::adocSnippet[]


import javax.persistence.CascadeType;
import javax.persistence.FetchType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static javax.persistence.FetchType.EAGER;

// @formatter:off
// tag::adocSnippet[]
@Target({METHOD, FIELD})
@Retention(RUNTIME)
public @interface OneToOne {

  Class targetEntity() default void.class;
  CascadeType[] cascade() default {};
  FetchType fetch() default EAGER;
  boolean optional() default true;
  String mappedBy() default "";
  boolean orphanRemoval() default false;
}
// end::adocSnippet[]
--------------------------------------------------------------------------------------------------------
import javax.validation.Constraint;
import javax.validation.Payload;
import javax.validation.ReportAsSingleViolation;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

// tag::adocSnippet[]
@Constraint(validatedBy = {})

@NotNull
@Size(min = 7)
@Pattern(regexp = "[a-f]{1,}")
@ReportAsSingleViolation

@Retention(RUNTIME)
@Target({METHOD, FIELD, PARAMETER, TYPE, ANNOTATION_TYPE, CONSTRUCTOR})
@Documented
public @interface Isbn {

  String message() default "Invalid ISBN number";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
--------------------------------------------------------------------------------------------------------
import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

// @formatter:off
// tag::adocSnippet[]
@Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE})
@Retention(RUNTIME)
@Constraint(validatedBy = {})
@Repeatable(Size.List.class)
@Documented
public @interface Size {

  String message() default "{javax.validation.constraints.Size.message}";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
  int min() default 0;
  int max() default Integer.MAX_VALUE;
  @Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE})
  @Retention(RUNTIME)
  @Documented
  @interface List {
    Size[] value();
  }
}

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * @author Antonio Goncalves
 * http://www.antoniogoncalves.org
 * --
 */
// @formatter:off
// tag::adocSnippet[]
@Constraint(validatedBy = ZipCodeValidator.class)
@Repeatable(ZipCode.List.class)
@Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER})
@Retention(RUNTIME)
@Documented
public @interface ZipCode {

  String message() default "{org.agoncal.fascicle.ZipCode.message}";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
  @Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER})
  @Retention(RUNTIME)
  @Documented
  @interface List {
    ZipCode[] value();
  }
}
--------------------------------------------------------------------------------------------------------
import javax.validation.Constraint;
import javax.validation.Payload;
import javax.validation.ReportAsSingleViolation;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author Antonio Goncalves
 * http://www.antoniogoncalves.org
 * --
 */
@Pattern(regexp = "[A-Z][a-z]{1,}")
@Size(min = 3, max = 20)
@ReportAsSingleViolation
@Constraint(validatedBy = {})
@Documented
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface MusicGenre {

  String message() default "{music.genre}";
  Class<? extends Payload>[] payload() default {};
  Class<?>[] groups() default {};
}
--------------------------------------------------------------------------------------------------------
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/authors")
@Produces(MediaType.TEXT_PLAIN)
@OpenAPIDefinition(
  info = @Info(
    title = "Authors",
    version = "1.0",
    description = "Operations on authors"
  ),
  tags = {
    @Tag(name = "author"),
    @Tag(name = "book")
  }
)
public class AuthorResource {

  String[] scifiAuthors = {"Isaac Asimov", "Ray Bradbury", "Douglas Adams"};

  @GET
  @Operation(summary = "Gets all the sci-fi authors", tags = {"scifi"},
    responses = {
      @ApiResponse(responseCode = "200", description = "Comma-separated list of sci-fi authors")
    })
  public String getAllScifiAuthors() {
    return String.join(", ", scifiAuthors);
  }

  @GET
  @Path("/{index}")
  @Operation(summary = "Gets a sci-fi author by index",
    tags = {"scifi"},
    responses = {
      @ApiResponse(responseCode = "200", description = "A sci-fi author"),
      @ApiResponse(responseCode = "400", description = "Invalid index supplied"),
      @ApiResponse(responseCode = "404", description = "Author not found")}
  )
  public String getScifiAuthor(@Parameter(description = "Author index", required = true) @PathParam("index") int index) {
    return scifiAuthors[index];
  }
}

import org.agoncal.fascicle.jaxrs.invoking.Customer;

import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

/**
 * @author Antonio Goncalves
 * http://www.antoniogoncalves.org
 * --
 */
@Provider
@Produces("custom/format")
public class CustomCustomerWriter implements MessageBodyWriter<Customer> {

  @Override
  public boolean isWriteable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
    return Customer.class.isAssignableFrom(type);
  }

  @Override
  public void writeTo(Customer customer, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, Object> httpHeaders, OutputStream outputStream) throws IOException, WebApplicationException {
    outputStream.write(customer.getId().getBytes());
    outputStream.write('/');
    outputStream.write(customer.getFirstName().getBytes());
    outputStream.write('/');
    outputStream.write(customer.getLastName().getBytes());
  }

  @Override
  public long getSize(Customer customer, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
    return customer.getId().length() + 1 + customer.getFirstName().length() + 1 + customer.getLastName().length();
  }
}


import org.agoncal.fascicle.jaxrs.invoking.Customer;

import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.StringTokenizer;

/**
 * @author Antonio Goncalves
 * http://www.antoniogoncalves.org
 * --
 */
@Provider
@Consumes("custom/format")
public class CustomCustomerReader implements MessageBodyReader<Customer> {

  @Override
  public boolean isReadable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
    return Customer.class.isAssignableFrom(type);
  }

  @Override
  public Customer readFrom(Class<Customer> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, String> httpHeaders, InputStream inputStream) throws IOException, WebApplicationException {

    String str = convertStreamToString(inputStream);
    StringTokenizer s = new StringTokenizer(str, "/");

    Customer customer = new Customer();
    customer.setId(s.nextToken());
    customer.setFirstName(s.nextToken());
    customer.setLastName(s.nextToken());

    return customer;
  }

  public String convertStreamToString(InputStream is)
    throws IOException {

    if (is != null) {
      Writer writer = new StringWriter();

      char[] buffer = new char[1024];
      try {
        Reader reader = new BufferedReader(
          new InputStreamReader(is, "UTF-8"));
        int n;
        while ((n = reader.read(buffer)) != -1) {
          writer.write(buffer, 0, n);
        }
      } finally {
        is.close();
      }
      return writer.toString();
    } else {
      return "";
    }
  }
}


   @GET
   @Produces( {"application/xml", "application/json"})
   @ApiOperation("Lists all the customers")
   public List<Customer> listAll(@QueryParam("start") Integer startPosition, @QueryParam("max") Integer maxResult)
   {
      TypedQuery<Customer> findAllQuery = em.createQuery("SELECT DISTINCT c FROM Customer c LEFT JOIN FETCH c.homeAddress.country ORDER BY c.id", Customer.class);
      if (startPosition != null)
      {
         findAllQuery.setFirstResult(startPosition);
      }
      if (maxResult != null)
      {
         findAllQuery.setMaxResults(maxResult);
      }
      final List<Customer> results = findAllQuery.getResultList();
      return results;
   }
   
   
   
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.io.IOException;
import java.net.URI;

/**
 * Main class.
 *
 */
public class Main {
    // Base URI the Grizzly HTTP server will listen on
    public static final String BASE_URI = "http://localhost:8080/cdbookstore/";

    /**
     * Starts Grizzly HTTP server exposing JAX-RS resources defined in this application.
     * @return Grizzly HTTP server.
     */
    public static HttpServer startServer() {
        // create a resource config that scans for JAX-RS resources and providers
        // in org.agoncal.fascicle.jaxrs.firststep package
        final ResourceConfig rc = new ResourceConfig().packages("org.agoncal.fascicle.commons.restassured");

        // create and start a new instance of grizzly http server
        // exposing the Jersey application at BASE_URI
        return GrizzlyHttpServerFactory.createHttpServer(URI.create(BASE_URI), rc);
    }

    /**
     * Main method.
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        final HttpServer server = startServer();
        System.out.println(String.format("Jersey app started with WADL available at "
                + "%sapplication.wadl\nHit enter to stop it...", BASE_URI));
        System.in.read();
        server.stop();
    }
}
--------------------------------------------------------------------------------------------------------

import org.jackson.views.domain.User;
import org.jackson.views.repository.UserRepository;
import org.hibernate.validator.internal.constraintvalidators.hv.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Authenticate a user from the database.
 */
@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {

    private final Logger log = LoggerFactory.getLogger(DomainUserDetailsService.class);

    private final UserRepository userRepository;

    public DomainUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String login) {
        log.debug("Authenticating {}", login);

        if (new EmailValidator().isValid(login, null)) {
            return userRepository.findOneWithAuthoritiesByEmail(login)
                .map(user -> createSpringSecurityUser(login, user))
                .orElseThrow(() -> new UsernameNotFoundException("User with email " + login + " was not found in the database"));
        }

        String lowercaseLogin = login.toLowerCase(Locale.ENGLISH);
        return userRepository.findOneWithAuthoritiesByLogin(lowercaseLogin)
            .map(user -> createSpringSecurityUser(lowercaseLogin, user))
            .orElseThrow(() -> new UsernameNotFoundException("User " + lowercaseLogin + " was not found in the database"));

    }

    private org.springframework.security.core.userdetails.User createSpringSecurityUser(String lowercaseLogin, User user) {
        if (!user.getActivated()) {
            throw new UserNotActivatedException("User " + lowercaseLogin + " was not activated");
        }
        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
            .map(authority -> new SimpleGrantedAuthority(authority.getName()))
            .collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(user.getLogin(),
            user.getPassword(),
            grantedAuthorities);
    }
}
--------------------------------------------------------------------------------------------------------
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.github.jhipster.config.JHipsterProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class TokenProvider {

    private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private Key key;

    private long tokenValidityInMilliseconds;

    private long tokenValidityInMillisecondsForRememberMe;

    private final JHipsterProperties jHipsterProperties;

    public TokenProvider(JHipsterProperties jHipsterProperties) {
        this.jHipsterProperties = jHipsterProperties;
    }

    @PostConstruct
    public void init() {
        byte[] keyBytes;
        String secret = jHipsterProperties.getSecurity().getAuthentication().getJwt().getSecret();
        if (!StringUtils.isEmpty(secret)) {
            log.warn("Warning: the JWT key used is not Base64-encoded. " +
                "We recommend using the `jhipster.security.authentication.jwt.base64-secret` key for optimum security.");
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        } else {
            log.debug("Using a Base64-encoded JWT secret key");
            keyBytes = Decoders.BASE64.decode(jHipsterProperties.getSecurity().getAuthentication().getJwt().getBase64Secret());
        }
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.tokenValidityInMilliseconds =
            1000 * jHipsterProperties.getSecurity().getAuthentication().getJwt().getTokenValidityInSeconds();
        this.tokenValidityInMillisecondsForRememberMe =
            1000 * jHipsterProperties.getSecurity().getAuthentication().getJwt()
                .getTokenValidityInSecondsForRememberMe();
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity;
        if (rememberMe) {
            validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
        } else {
            validity = new Date(now + this.tokenValidityInMilliseconds);
        }

        return Jwts.builder()
            .setSubject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(key, SignatureAlgorithm.HS512)
            .setExpiration(validity)
            .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(key)
            .parseClaimsJws(token)
            .getBody();

        Collection<? extends GrantedAuthority> authorities =
            Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(authToken);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }
}

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenProvider tokenProvider;

    public JWTConfigurer(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        JWTFilter customFilter = new JWTFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}

  @EntityGraph(attributePaths = "authorities")
    @Cacheable(cacheNames = USERS_BY_EMAIL_CACHE)
    Optional<User> findOneWithAuthoritiesByEmail(String email);

--------------------------------------------------------------------------------------------------------
import org.jackson.views.domain.PersistentAuditEvent;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class AuditEventConverter {

    /**
     * Convert a list of PersistentAuditEvent to a list of AuditEvent
     *
     * @param persistentAuditEvents the list to convert
     * @return the converted list.
     */
    public List<AuditEvent> convertToAuditEvent(Iterable<PersistentAuditEvent> persistentAuditEvents) {
        if (persistentAuditEvents == null) {
            return Collections.emptyList();
        }
        List<AuditEvent> auditEvents = new ArrayList<>();
        for (PersistentAuditEvent persistentAuditEvent : persistentAuditEvents) {
            auditEvents.add(convertToAuditEvent(persistentAuditEvent));
        }
        return auditEvents;
    }

    /**
     * Convert a PersistentAuditEvent to an AuditEvent
     *
     * @param persistentAuditEvent the event to convert
     * @return the converted list.
     */
    public AuditEvent convertToAuditEvent(PersistentAuditEvent persistentAuditEvent) {
        if (persistentAuditEvent == null) {
            return null;
        }
        return new AuditEvent(persistentAuditEvent.getAuditEventDate(), persistentAuditEvent.getPrincipal(),
            persistentAuditEvent.getAuditEventType(), convertDataToObjects(persistentAuditEvent.getData()));
    }

    /**
     * Internal conversion. This is needed to support the current SpringBoot actuator AuditEventRepository interface
     *
     * @param data the data to convert
     * @return a map of String, Object
     */
    public Map<String, Object> convertDataToObjects(Map<String, String> data) {
        Map<String, Object> results = new HashMap<>();

        if (data != null) {
            for (Map.Entry<String, String> entry : data.entrySet()) {
                results.put(entry.getKey(), entry.getValue());
            }
        }
        return results;
    }

    /**
     * Internal conversion. This method will allow to save additional data.
     * By default, it will save the object as string
     *
     * @param data the data to convert
     * @return a map of String, String
     */
    public Map<String, String> convertDataToStrings(Map<String, Object> data) {
        Map<String, String> results = new HashMap<>();

        if (data != null) {
            for (Map.Entry<String, Object> entry : data.entrySet()) {
                // Extract the data that will be saved.
                if (entry.getValue() instanceof WebAuthenticationDetails) {
                    WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) entry.getValue();
                    results.put("remoteAddress", authenticationDetails.getRemoteAddress());
                    results.put("sessionId", authenticationDetails.getSessionId());
                } else {
                    results.put(entry.getKey(), Objects.toString(entry.getValue()));
                }
            }
        }
        return results;
    }
}

import org.jackson.views.security.*;
import org.jackson.views.security.jwt.*;

import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import javax.annotation.PostConstruct;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final UserDetailsService userDetailsService;

    private final TokenProvider tokenProvider;

    private final CorsFilter corsFilter;

    private final SecurityProblemSupport problemSupport;

    public SecurityConfiguration(AuthenticationManagerBuilder authenticationManagerBuilder, UserDetailsService userDetailsService, TokenProvider tokenProvider, CorsFilter corsFilter, SecurityProblemSupport problemSupport) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.userDetailsService = userDetailsService;
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.problemSupport = problemSupport;
    }

    @PostConstruct
    public void init() {
        try {
            authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
        } catch (Exception e) {
            throw new BeanInitializationException("Security configuration failed", e);
        }
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
            .antMatchers(HttpMethod.OPTIONS, "/**")
            .antMatchers("/app/**/*.{js,html}")
            .antMatchers("/i18n/**")
            .antMatchers("/content/**")
            .antMatchers("/h2-console/**")
            .antMatchers("/swagger-ui/index.html")
            .antMatchers("/test/**");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
            .disable()
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
            .authenticationEntryPoint(problemSupport)
            .accessDeniedHandler(problemSupport)
        .and()
            .headers()
            .frameOptions()
            .disable()
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()
            .antMatchers("/api/register").permitAll()
            .antMatchers("/api/activate").permitAll()
            .antMatchers("/api/authenticate").permitAll()
            .antMatchers("/api/account/reset-password/init").permitAll()
            .antMatchers("/api/account/reset-password/finish").permitAll()
            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/health").permitAll()
            .antMatchers("/management/info").permitAll()
            .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
        .and()
            .apply(securityConfigurerAdapter());

    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }
}

import org.jackson.views.aop.logging.LoggingAspect;

import io.github.jhipster.config.JHipsterConstants;

import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;

@Configuration
@EnableAspectJAutoProxy
public class LoggingAspectConfiguration {

    @Bean
    @Profile(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT)
    public LoggingAspect loggingAspect(Environment env) {
        return new LoggingAspect(env);
    }
}

import io.github.jhipster.config.JHipsterConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.config.java.AbstractCloudConfig;
import org.springframework.context.annotation.*;

import javax.sql.DataSource;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Configuration
@Profile(JHipsterConstants.SPRING_PROFILE_CLOUD)
public class CloudDatabaseConfiguration extends AbstractCloudConfig {

    private final Logger log = LoggerFactory.getLogger(CloudDatabaseConfiguration.class);
    
    private final String CLOUD_CONFIGURATION_HIKARI_PREFIX = "spring.datasource.hikari";

    @Bean
    @ConfigurationProperties(CLOUD_CONFIGURATION_HIKARI_PREFIX)
    public DataSource dataSource() {
        log.info("Configuring JDBC datasource from a cloud provider");
        return connectionFactory().dataSource();
    }
}

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        taskRegistrar.setScheduler(scheduledTaskExecutor());
    }

    @Bean
    public Executor scheduledTaskExecutor() {
        return Executors.newScheduledThreadPool(jHipsterProperties.getAsync().getCorePoolSize());
    }
--------------------------------------------------------------------------------------------------------

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Antonio Goncalves
 *         http://www.antoniogoncalves.org
 *         --
 */
@XmlRootElement
@XmlSeeAlso(Customer.class)
public class Customers extends ArrayList<Customer> {

  // ======================================
  // =          Getters & Setters         =
  // ======================================

  @XmlElement(name = "customer")
  public List<Customer> getCustomers() {
    return this;
  }
}
--------------------------------------------------------------------------------------------------------
- mvn install -DskipTests=true -Dmaven.javadoc.skip=true -B -V


os:
  - linux
services:
  - docker
language: java
jdk:
  - oraclejdk8
sudo: false
cache:
  directories:
    - $HOME/.m2
before_install:
  - mvn install -DskipTests=true -Dmaven.javadoc.skip=true -B -V
  - java -version
script:
  - mvn clean test
notifications:
  webhooks:
    on_success: change  # options: [always|never|change] default: always
    on_failure: always  # options: [always|never|change] default: always
    on_start: false     # default: false
--------------------------------------------------------------------------------------------------------
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import java.io.IOException;

@Component
public class MdcFilter extends GenericFilterBean {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      MDC.put("mdcData", "[userId:Duke]");
      chain.doFilter(request, response);
    } finally {
      MDC.clear();
    }
  }
}
--------------------------------------------------------------------------------------------------------
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;

@Repository
class MessageRepository {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  @Async
  Future<List<String>> findAll() {
    logger.info("Repository in action");
    return new AsyncResult<>(Arrays.asList("Hello World", "Spring Boot is awesome"));
  }
}
--------------------------------------------------------------------------------------------------------
   @Component
    @RestControllerEndpoint(id = "remote")
    public class CustomActuator {
        @RequestMapping(value = {"/{actuatorInput}"}, produces = MediaType.APPLICATION_JSON_VALUE, method = RequestMethod.GET)
        @ResponseBody
        public Map<String, Object> feature(@PathVariable("actuatorInput") String actuatorInput) {
            System.out.println("actuatorInput : " + actuatorInput);
            Map<String, Object> details = new HashMap<>();
            details.put("input", actuatorInput);
            return details;
        }
    }
	
	@Component
@Endpoint(id = "custom-health")
public class CustomHealthEndpoint {

    @ReadOperation
    public String customEndPointByName(@Selector String name) {
        return "custom-end-point : " + name;
    }
    @WriteOperation
    public void writeOperation(@Selector String name) {
        System.out.println("Write Operation! :: " + name);
    }
    @DeleteOperation
    public void deleteOperation(@Selector String name){
        System.out.println("Delete Operation! :: " + name);
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;

@Service
public class SessionRegistry {

    private final Map<String, HttpSession> httpSessionMap = new ConcurrentSkipListMap<>();

    public void addSession(HttpSession httpSession) {
        this.httpSessionMap.put(httpSession.getId(), httpSession);
    }

    public void removeSession(HttpSession httpSession) {
        this.httpSessionMap.remove(httpSession.getId());
    }

    public List<HttpSession> getSessions() {
        return new ArrayList<>(httpSessionMap.values());
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.Optional;

@RestController
public class GreetingController {

    @RequestMapping(value = "/greetings/{caller}", produces = MediaType.TEXT_HTML_VALUE)
    public String getGreeting(@PathVariable("caller") String caller, HttpSession httpSession) {

        httpSession.setAttribute("invocationCount", 1 + Optional.ofNullable((Integer) httpSession.getAttribute("invocationCount")).orElse(0));
        httpSession.setAttribute("latestGreetingArgument", caller);

        return new StringBuilder()
                .append("<html><body>")
                .append("Your session id is: [").append(httpSession.getId()).append("]")
                .append("<br> ( Invocation count is : [").append(httpSession.getAttribute("invocationCount")).append("] )")
                .append("</body></html>")
                .toString();
    }

}
--------------------------------------------------------------------------------------------------------
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

public class ExpirationJwtClaimsSetVerifier implements JwtClaimsSetVerifier {
    private final Log logger = LogFactory.getLog(this.getClass());

    private int maxClockSkewSeconds = 60;

    @Override
    public boolean verify(JWTClaimsSet claimsSet) {
        Date now = Date.from(ZonedDateTime.now(ZoneOffset.UTC).toInstant());
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null) {
            logger.warn("Missing expiration date in JWT claims set");
            return false;
        }
        return DateUtils.isAfter(expirationTime, now, maxClockSkewSeconds);
    }

    public void setMaxClockSkewSeconds(int maxClockSkewSeconds) {
        this.maxClockSkewSeconds = maxClockSkewSeconds;
    }
}
--------------------------------------------------------------------------------------------------------
openssl rand 32 | base64

machine:
  java:
    version: oraclejdk8
  post:
    # Install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for build
    - rm -f jce_policy-8.zip
    - "curl -o jce_policy-8.zip -v -j -k -L -H 'Cookie: oraclelicense=accept-securebackup-cookie' http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip"
    - sudo unzip -j -o -d $JAVA_HOME/jre/lib/security jce_policy-8.zip
test:
  override:
    - ./gradlew clean build
  post:
    - mkdir -p $CIRCLE_TEST_REPORTS/junit/
    - find . -type f -regex ".*/build/test-results/.*xml" -exec cp {} $CIRCLE_TEST_REPORTS/junit/ \;
deployment:
  gh-release:
    tag: /^v\d+\.\d+\.\d+$/
    owner: AusDTO
    commands:
      - gradle assemble
      - mkdir -p release
      - cp build/libs/* release/
      - curl -kjLo ghr.zip https://github.com/tcnksm/ghr/releases/download/v0.4.0/ghr_v0.4.0_linux_amd64.zip
      - unzip ghr.zip
      - ./ghr -t $GITHUB_ACCESS_TOKEN -u $CIRCLE_PROJECT_USERNAME -r $CIRCLE_PROJECT_REPONAME $CIRCLE_TAG release/
      - "curl -skL -o /dev/null -c jitpack_cookie.txt https://jitpack.io"
      - "curl -skiL -H 'Referer: https://jitpack.io/' -b jitpack_cookie.txt https://jitpack.io/api/builds/com.github.AusDTO/spring-security-stateless/${CIRCLE_TAG}"

--------------------------------------------------------------------------------------------------------
@Configuration
public class Config {
    @Bean
    public CsrfTokenInterceptor csrfTokenInterceptor() {
        return new CsrfTokenInterceptor();
    }
}
--------------------------------------------------------------------------------------------------------
import java.util.List;

import com.mifmif.networking.mspider.database.dao.api.WebsiteDao;
import com.mifmif.networking.mspider.model.Website;

/**
 * @author y.mifrah
 * 
 */
public class JpaWebsiteDao extends JpaDao<Long, Website> implements WebsiteDao {

	@Override
	public Website finbByHost(String host) {
		List<Website> found = entityManager.createNamedQuery("Website.findByHost", Website.class).setParameter("host", host).getResultList();
		return found.isEmpty() ? null : found.get(0);
	}

}
--------------------------------------------------------------------------------------------------------
app.menus:
  - title: Home
    name: Home
    path: /
  - title: Login
    name: Login
    path: /login
spring:
  mustache:
    expose-request-attributes: true
logging:
  level:
    org.springframework.security: DEBUG
--------------------------------------------------------------------------------------------------------
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;

import java.io.IOException;

public final class ResponseUtil {
    private ResponseUtil() {
    }

    public static void closeResponse(CloseableHttpResponse response) throws IOException {
        if (response == null) {
            return;
        }

        try {
            final HttpEntity entity = response.getEntity();
            if (entity != null) {
                entity.getContent().close();
            }
        } finally {
            response.close();
        }
    }
}
--------------------------------------------------------------------------------------------------------
yarn global add bower• yarn global add gulp-cli
jhipster entity Post --table-name post


@OneToMany(mappedBy = "post")@JsonIgnore@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)private Set<Comment> comments = new HashSet<>();

heroku logs --tail --app <application_name>
--------------------------------------------------------------------------------------------------------
import java.util.Date;import org.springframework.boot.actuate.health.Health;import org.springframework.boot.actuate.health.HealthIndicator;import org.springframework.stereotype.Component;import org.springframework.web.client.RestClientException;import org.springframework.web.client.RestTemplate;@Componentpublic class FeedServerHealthIndicator implements HealthIndicator{    @Override    public Health health() {RestTemplate restTemplate = new RestTemplate();String url = "http://feedserver.com/ping";try {String resp = restTemplate.getForObject(url, String.class);if("OK".equalsIgnoreCase(resp)){return Health.up().build();} else {return Health.down().withDetail("ping_url", url).withDetail("ping_time", new Date()).build();}} catch (RestClientException e) {return Health.down(e).withDetail("ping_url", url).withDetail("ping_time", new Date()).build();}    }}


import org.springframework.beans.factory.annotation.Autowired;import org.springframework.boot.actuate.metrics.CounterService;import org.springframework.stereotype.Service;@Servicepublic class LoginService{@Autowiredprivate CounterService counterService;public boolean login(String email, String password){if("admin@gmail.com".equalsIgnoreCase(email) && "admin".equals(password)){counterService.increment("counter.login.success");return true;} else {counterService.increment("counter.login.failure");return false;}}}
--------------------------------------------------------------------------------------------------------
@BeforeEach
void init(@Mock SettingRepository settingRepository) {
    userService = new DefaultUserService(userRepository, settingRepository, mailClient);
       
    Mockito.lenient().when(settingRepository.getUserMinAge()).thenReturn(10);
         
    when(settingRepository.getUserNameMinLength()).thenReturn(4);
         
    Mockito.lenient().when(userRepository.isUsernameAlreadyExists(any(String.class))).thenReturn(false);
}
--------------------------------------------------------------------------------------------------------
        <dependency>
            <groupId>org.powermock</groupId>
            <artifactId>powermock-module-junit4-rule</artifactId>
            <version>2.0.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.powermock</groupId>
            <artifactId>powermock-classloading-objenesis</artifactId>
            <version>2.0.2</version>
            <scope>test</scope>
        </dependency>
--------------------------------------------------------------------------------------------------------
@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(Parameterized.class)
@PrepareForTest({FinalDemo.class, PrivateFinal.class})
public class FinalDemoTest {

    @Parameterized.Parameter(0)
    public String expected;

    @Parameterized.Parameters(name = "expected={0}")
    public static Collection<?> expections() {
        return java.util.Arrays.asList(new Object[][]{
            {"Hello altered World"}, {"something"}, {"test"}
        });
    }

    @Test
    public void assertMockFinalWithExpectationsWorks() throws Exception {
        final String argument = "hello";

        FinalDemo tested = mock(FinalDemo.class);

        when(tested.say(argument)).thenReturn(expected);

        final String actual = "" + tested.say(argument);

        verify(tested).say(argument);

        assertEquals("Expected and actual did not match", expected, actual);
    }
}
--------------------------------------------------------------------------------------------------------
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;

import java.time.LocalDate;

class SlashyDateConverter implements ArgumentConverter {

    @Override
    public Object convert(Object source, ParameterContext context) throws ArgumentConversionException {
        if (!(source instanceof String))
            throw new IllegalArgumentException("The argument should be a string: " + source);

        try {
            String[] parts = ((String) source).split("/");
            int year = Integer.parseInt(parts[0]);
            int month = Integer.parseInt(parts[1]);
            int day = Integer.parseInt(parts[2]);

            return LocalDate.of(year, month, day);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to convert", e);
        }
    }
}

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.AggregateWith;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PersonUnitTest {

    @ParameterizedTest
    @CsvSource({"Isaac,,Newton, Isaac Newton", "Charles,Robert,Darwin,Charles Robert Darwin"})
    void fullName_ShouldGenerateTheExpectedFullName(ArgumentsAccessor argumentsAccessor) {
        String firstName = argumentsAccessor.getString(0);
        String middleName = (String) argumentsAccessor.get(1);
        String lastName = argumentsAccessor.get(2, String.class);
        String expectedFullName = argumentsAccessor.getString(3);

        Person person = new Person(firstName, middleName, lastName);
        assertEquals(expectedFullName, person.fullName());
    }

    @ParameterizedTest
    @CsvSource({"Isaac Newton,Isaac,,Newton", "Charles Robert Darwin,Charles,Robert,Darwin"})
    void fullName_ShouldGenerateTheExpectedFullName(String expectedFullName,
                                                    @AggregateWith(PersonAggregator.class) Person person) {

        assertEquals(expectedFullName, person.fullName());
    }
}

import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.aggregator.ArgumentsAggregationException;
import org.junit.jupiter.params.aggregator.ArgumentsAggregator;

class PersonAggregator implements ArgumentsAggregator {

    @Override
    public Object aggregateArguments(ArgumentsAccessor accessor, ParameterContext context)
            throws ArgumentsAggregationException {
        return new Person(accessor.getString(1), accessor.getString(2), accessor.getString(3));
    }
}

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

import javax.sql.DataSource;

@Configuration
@ComponentScan("com.baeldung.junit.tags.example")
public class SpringJdbcConfig {

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).addScript("classpath:jdbc/schema.sql").addScript("classpath:jdbc/test-data.sql").build();
    }
}

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages("com.baeldung.tags")
@IncludeTags("UnitTest")
public class EmployeeDAOTestSuite {
}


import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertLinesMatch;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;

@TestMethodOrder(OrderAnnotation.class)
class SharedTemporaryDirectoryUnitTest {

    @TempDir
    static Path sharedTempDir;
    
    @Test
    @Order(1)
    void givenFieldWithSharedTempDirectoryPath_whenWriteToFile_thenContentIsCorrect() throws IOException {
        Path numbers = sharedTempDir.resolve("numbers.txt");

        List<String> lines = Arrays.asList("1", "2", "3");
        Files.write(numbers, lines);

        assertAll(
            () -> assertTrue("File should exist", Files.exists(numbers)),
            () -> assertLinesMatch(lines, Files.readAllLines(numbers)));
        
        Files.createTempDirectory("bpb");
    }

    @Test
    @Order(2)
    void givenAlreadyWrittenToSharedFile_whenCheckContents_thenContentIsCorrect() throws IOException {
        Path numbers = sharedTempDir.resolve("numbers.txt");

        assertLinesMatch(Arrays.asList("1", "2", "3"), Files.readAllLines(numbers));
    }

}import org.junit.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.ExpectedException;

@EnableRuleMigrationSupport
public class RuleMigrationSupportUnitTest {

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void whenExceptionThrown_thenExpectationSatisfied() {
        exceptionRule.expect(NullPointerException.class);
        String test = null;
        test.length();
    }

    @Test
    public void whenExceptionThrown_thenRuleIsApplied() {
        exceptionRule.expect(NumberFormatException.class);
        exceptionRule.expectMessage("For input string");
        Integer.parseInt("1a");
    }
}

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@ExtendWith(TraceUnitExtension.class)
public class RuleExampleUnitTest {

    @Test
    public void whenTracingTests() {
        System.out.println("This is my test");
        /*...*/
    }
}
--------------------------------------------------------------------------------------------------------
sudo add-apt-repository -y ppa:webupd8team/javasudo apt-get updatesudo apt-get install oracle-java8-installersudo apt-get install oracle-java8-set-defaul

sudo add-apt-repository -y ppa:natecarlson/maven3sudo apt-get updatesudo apt-get --assume-yes install maven3sudo ln -sf /usr/bin/mvn3 /usr/bin/mvn

SELECT *
FROM tablename
WHERE 
columnname REGEXP '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'
--------------------------------------------------------------------------------------------------------
language: javajdk:- openjdk8script: mvn clean install -Ptestcache:directories:- $HOME/.m2/deploy:provider: herokuapp: HEROKU-APP-NAMEapi_key:secure: YOUR-API-KEYrun: "DATABASE_URL_JDBC=$DB_PROD mvn liquibase:update -pl liquibase -Pheroku"on: master

./travis-encrypt.sh -r user/repo -e 258cfb90-XXXX-4720-XXX-9bfba5332254

heroku auth:token

heroku addons:create heroku-postgresql:hobby-dev

--------------------------------------------------------------------------------------------------------
/**
 * Interface to build objects in a
 * fluent fashion.
 *
 * @param <T> The type of object being built.
 * @author Rui Vilao (rui.vilao@ed-era.com)
 */
public interface FluentBuilder<T> {
    /**
     * Builds the object.
     *
     * @return The object.
     */
    T build();
}
--------------------------------------------------------------------------------------------------------
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.specification.RequestSpecification;
import org.junit.*;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

public class RestAssuredExercises4Test {

	private static RequestSpecification requestSpec;

	@Rule
	public WireMockRule wireMockRule = new WireMockRule(options().port(9876));

	@BeforeClass
	public static void createRequestSpecification() {

		requestSpec = new RequestSpecBuilder().
			setBaseUri("http://localhost").
			setPort(9876).
			build();
	}

	/*******************************************************
	 * Perform a GET request to /xml/de/24848 to get the
	 * list of places associated with German zip code 24848
	 * in XML format. Assert that the third place in the list
	 * is Kropp
	 ******************************************************/

	@Test
	public void getDeZipCode24848_checkThirdPlaceInList_expectKropp() {

		given().
			spec(requestSpec).
		when().
		then();
	}

	/*******************************************************
	 * Perform a GET request to /xml/de/24848 to get the
	 * list of places associated with German zip code 24848
	 * in XML format. Assert that the latitude for the third
	 * place in the list equal to 54.45
	 ******************************************************/

	@Test
	public void getDeZipCode24848_checkLatitudeForSecondPlaceInList_expect5445() {

		given().
			spec(requestSpec).
		when().
		then();
	}

	/*******************************************************
	 * Perform a GET request to /xml/de/24848 to get the
	 * list of places associated with German zip code 24848
	 * in XML format. Assert that there are 4 places that
	 * have a stateAbbreviation that equals 'SH'
	 ******************************************************/

	@Test
	public void getDeZipCode24848_checkNumberOfPlacesInSH_expect4() {

		given().
			spec(requestSpec).
		when().
		then();
	}


	/*******************************************************
	 * Perform a GET request to /xml/de/24848 to get the
	 * list of places associated with German zip code 24848
	 * in XML format. Assert that there are 3 places that
	 * have a name that starts with 'Klein'
	 ******************************************************/

	@Test
	public void getDeZipCode24848_checkNumberOfPlacesStartingWithKlein_expect3() {

		given().
			spec(requestSpec).
		when().
		then();
	}
}

jumia
finastra
--------------------------------------------------------------------------------------------------------
http://localhost:8080/posts?sort=createdOn,desc
--------------------------------------------------------------------------------------------------------
cp .xinitrc /home/YOUR_USERNAME/.xinitrc 
--------------------------------------------------------------------------------------------------------
@FunctionalInterfacepublic interface HandlerFunction<T extends ServerResponse>{    Mono<T> handle(ServerRequest request);}

@FunctionalInterfacepublic interface HandlerFilterFunction<T extends ServerResponse, R extends ServerResponse>{    Mono<R> filter(ServerRequest request, HandlerFunction<T> next);    //other methods}
--------------------------------------------------------------------------------------------------------
@Controllerpublic class RegistrationController{    @Autowired    private UserValidator userValidator;    @PostMapping("/registration")    public String handleRegistration(@Valid User user, BindingResult result) {userValidator.validate(user, result);if(result.hasErrors()){return "registration";}return "redirect:/registrationsuccess";    }}

spring.servlet.multipart.enabled=truespring.servlet.multipart.max-file-size=2MBspring.servlet.multipart.max-request-size=20MBspring.servlet.multipart.file-size-threshold=5MB
--------------------------------------------------------------------------------------------------------
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(TogglzProperties.class)
    @ConditionalOnClass({EnableWebSecurity.class, AuthenticationEntryPoint.class, SpringSecurityUserProvider.class})
    @Description("Spring security user provider")
    public UserProvider userProvider(final TogglzProperties properties) {
        return new SpringSecurityUserProvider(properties.getConsole().getFeatureAdminAuthority());
    }
--------------------------------------------------------------------------------------------------------
@Test
public void givenFeaturePropertyTrue_whenIncreaseSalary_thenIncrease() 
  throws Exception {
    Employee emp = new Employee(1, 2000);
    employeeRepository.save(emp);
    System.setProperty("employee.feature", "true");
 
    mockMvc.perform(post("/increaseSalary")
      .param("id", emp.getId() + ""))
      .andExpect(status().is(200));
 
    emp = employeeRepository.findById(1L).orElse(null);
    assertEquals("salary incorrect", 2200, emp.getSalary(), 0.5);
}
--------------------------------------------------------------------------------------------------------
public enum MyFeatures implements Feature {
 
    @Label("Employee Management Feature")
    EMPLOYEE_MANAGEMENT_FEATURE;
 
    public boolean isActive() {
        return FeatureContext.getFeatureManager().isActive(this);
    }
}
@Configuration
public class ToggleConfiguration {
 
    @Bean
    public FeatureProvider featureProvider() {
        return new EnumBasedFeatureProvider(MyFeatures.class);
    }
}

public enum MyFeatures implements Feature {
 
    @Label("Employee Management Feature") 
    @EnabledByDefault
    @DefaultActivationStrategy(id = SystemPropertyActivationStrategy.ID, 
      parameters = { 
      @ActivationParameter(
        name = SystemPropertyActivationStrategy.PARAM_PROPERTY_NAME,
        value = "employee.feature"),
      @ActivationParameter(
        name = SystemPropertyActivationStrategy.PARAM_PROPERTY_VALUE,
        value = "true") }) 
    EMPLOYEE_MANAGEMENT_FEATURE;
    //...
}
--------------------------------------------------------------------------------------------------------
@Configuration@EnableWebMvcpublic class WebMvcConfig implements WebMvcConfigurer{@Bean(name="simpleMappingExceptionResolver")public SimpleMappingExceptionResolver simpleMappingExceptionResolver(){SimpleMappingExceptionResolver exceptionResolver = new SimpleMappingException Resolver();Properties mappings = new Properties();mappings.setProperty("DataAccessException", "dbError");mappings.setProperty("RuntimeException", "error");exceptionResolver.setExceptionMappings(mappings);exceptionResolver.setDefaultErrorView("error");return exceptionResolver;}}

@Controllerpublic class CustomerController{@GetMapping("/customers/{id}")public String findCustomer(@PathVariable Long id, Model model){Customer c = customerRepository.findById(id);if(c == null) throw new CustomerNotFoundException();model.add("customer", c);return "view_customer";}@ExceptionHandler(CustomerNotFoundException.class)public ModelAndView handleCustomerNotFoundException(CustomerNotFoundException ex){ModelAndView model = new ModelAndView("error/404");model.addObject("exception", ex);return model;}}

@Controllerpublic class GenericErrorController implements ErrorController{private static final String ERROR_PATH = "/error";@RequestMapping(ERROR_PATH)public String error(){return "errorPage.html";}@Overridepublic String getErrorPath() {return ERROR_PATH;}}

@Configurationpublic class WebConfig implements WebMvcConfigurer{@Overridepublic void addCorsMappings(CorsRegistry registry) {registry.addMapping("/api/**").allowedOrigins("http://localhost:3000").allowedMethods("*").allowedHeaders("*").allowCredentials(false).maxAge(3600);}}
--------------------------------------------------------------------------------------------------------
vue init vuetifyjs/nuxt frontend

spring.devtools.restart.exclude=assets/**,resources/**

spring.devtools.restart.additional-exclude=assets/**,setup-instructions/**spring.devtools.restart.additional-paths=D:/global-overrides/

spring.devtools.restart.trigger-file=restart.txt
java -jar -Dspring.devtools.restart.enabled=false app.jar

spring.datasource.hikari.allow-pool-suspension=truespring.datasource.hikari.connection-test-query=SELECT 1spring.datasource.hikari.transaction-isolation=TRANSACTION_READ_COMMITTEDspring.datasource.hikari.connection-timeout=45000

java -classpath jooq-3.9.3.jar;jooq-meta-3.9.3.jar;jooq-codegen-3.9.3.jar;mysql-connector-java-5.1.18-bin.jar;. org.jooq.util.GenerationTool jooq-config.xml

spring.datasource.driver-class-name=com.mysql.jdbc.Driverspring.datasource.url=jdbc:mysql://localhost:3306/testspring.datasource.username=rootspring.datasource.password=adminspring.jooq.sql-dialect=MYSQ

@Query("{ 'name' : ?0 }")User findByUserName(String name);

keytool -genkey -alias mydomain -keyalg RSA -keysize 2048 -keystore KeyStore.jks -validity 3650
server.port=8443server.ssl.key-store=classpath:KeyStore.jksserver.ssl.key-store-password=mysecretserver.ssl.keyStoreType=JKSserver.ssl.keyAlias=mydomain
--------------------------------------------------------------------------------------------------------
icacls "D:\test" /grant John:(OI)(CI)F /T
According do MS documentation:

F = Full Control
CI = Container Inherit - This flag indicates that subordinate containers will inherit this ACE.
OI = Object Inherit - This flag indicates that subordinate files will inherit the ACE.
/T = Apply recursively to existing files and sub-folders. (OI and CI only apply to new files and sub-folders). Credit: comment by @AlexSpence.
--------------------------------------------------------------------------------------------------------
@Bean    public LocalContainerEntityManagerFactoryBean entityManagerFactory()    {LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();vendorAdapter.setShowSql(Boolean.TRUE);factory.setDataSource(dataSource());factory.setJpaVendorAdapter(vendorAdapter);factory.setPackagesToScan(env.getProperty("packages-to-scan"));Properties jpaProperties = new Properties();jpaProperties.put("hibernate.hbm2ddl.auto", env.getProperty ("hibernate.hbm2ddl.auto"));factory.setJpaProperties(jpaProperties);factory.afterPropertiesSet();factory.setLoadTimeWeaver(new InstrumentationLoadTimeWeaver());return factory;    }
--------------------------------------------------------------------------------------------------------
@Target(ElementType.TYPE)@Retention(RetentionPolicy.RUNTIME)@Documented@Inherited@SpringBootConfiguration@EnableAutoConfiguration@ComponentScan(excludeFilters = {@Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),@Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class) })public @interface SpringBootApplication {    ....    ....}
--------------------------------------------------------------------------------------------------------
@RequestMapping(value = "/{roomId}", method = RequestMethod.GET,   consumes = "application/json;version=2")public RoomDTOv2 getRoomV2(@PathVariable("roomId") long id) {  Room room = inventoryService.getRoom(id);  return new RoomDTOv2(room);}

@RequestMapping(value = "/{roomId}", method = RequestMethod.GET, headers = {"X-API-Version=3"})public RoomDTOv3 getRoomV3(@PathVariable("roomId") long id) {  Room room = inventoryService.getRoom(id);  return new RoomDTOv3(room);}

@RequestMapping(value = "/{roomId}", method = RequestMethod.POST, headers = {"X-HTTP-Method-Override=PUT"})public ApiResponse updateRoomAsPost(@PathVariable("roomId") long   id, @RequestBody RoomDTO updatedRoom) {  return updateRoom(id, updatedRoom);}
--------------------------------------------------------------------------------------------------------
@Configuration@EnableWebMvc@ComponentScanpublic class WebApplicationConfiguration extends WebMvcAutoConfiguration {  @Bean  public Filter etagFilter() {    return new ShallowEtagHeaderFilter();  }}

@RunWith(SpringJUnit4ClassRunner.class)@SpringApplicationConfiguration(classes = WebApplication.class)@WebAppConfiguration@IntegrationTest("integration_server:9000")public class BookingsResourceIntegrationTest {  @Test  public void runTests() {    // ...  }}
--------------------------------------------------------------------------------------------------------
<build>        <plugins>            <plugin>                <artifactId>maven-war-plugin</artifactId>                <version>2.6</version>                <configuration><attachClasses>true</attachClasses>                </configuration>            </plugin>        </plugins>    </build>

<plugin>      <groupId>org.mortbay.jetty</groupId>      <artifactId>jetty-maven-plugin</artifactId>      <configuration>        <useTestScope>true</useTestScope>        <stopPort>8005</stopPort>        <stopKey>DIE!</stopKey>        <systemProperties>          <systemProperty>            <name>jetty.port</name>            <value>8080</value>          </systemProperty>        </systemProperties>      </configuration>    </plugin>
--------------------------------------------------------------------------------------------------------

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@ComponentScan
@EnableAutoConfiguration
@EnableResourceServer
@RestController
public class Application {
	
	@Bean
	public JwtTokenStore tokenStore() throws Exception {
		JwtAccessTokenConverter enhancer = new JwtAccessTokenConverter();
		// N.B. in a real system you would have to configure the verifierKey (or use JdbcTokenStore)
		enhancer.afterPropertiesSet();
		return new JwtTokenStore(enhancer);
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		return "Hello World";
	}

}
--------------------------------------------------------------------------------------------------------
Usage

    Download script travis-encrypt.sh
    Make it executable chmod +x travis-encrypt.sh
    Run the script with ./travis-encrypt.sh -r username/repositoryname -e example
        It will return something like O+woVD9K+PeFrcyu5GCjKSFvfcSPwDW0kyDYEQnNbwt/iSkqjpl2OPA9W//KEKEB9UUSZD+XmQ3Ij0gnvJnOowcWY5sSeJlVEVTrSer0kW6uWpa/uWzDHCBz2YhBnI6u9SfYfMkhDl22pcaCEwaUkmK2gjcVo+v0bS8vAQFz0Na5/WiKj0GkSX50iIGgfaXheuC8KgIC25T0h+czpap7vb13OlblMnClfyTH9+TmAwTlcV7ljXpv1QY+K72L8jK1/CQVZ8quBYrBwwxO2V6cpXRMMCIw4m4lqxUyN4FBGnq7cJ7BWLzeqSMpFBoP+ZxAqS5yem8KLh1VkEo7PVjCkZE6M+2meFf2VJEVUs/KJY9xnH3eDzipWkwXon2qVpCkT7FDEzGFs/DapYsSo7eCO6pUYYhcpaYpWeYV9DSSV0QcrOeZp664iJMHWPSmrs/lESbbHpKWsM/AFVB9X75q/OB+QU0tQxpReZmKw3ZHbDVMlmlwhP8VSiQ05LV2W6gYzADGiUiL6n1X8teeHEVDSZnD7nrxMD/FchnWI5La3tZeFovRMf6hH3NItW+QZaGaGNftJrP488J/F2hCycPJk3+YrxbBCGHE2X379QbkMz3S0B5UiAcJKmwuTstF6X3CCurZVYIkUGGXhnmalPtVpEqxeTiLw5RU6C9z2qSwhhw=
    Use the encrypted secret in your .travis.yml according to https://docs.travis-ci.com/user/encryption-keys/#Usage


#!/bin/bash

usage() { echo -e "Travis Encrypt Script\nUsage:\t$0 \n -r\t<username/repository> \n -e\t<string which should be encrypted>" 1>&2; exit 1; }

while getopts ":r:e:" param; do
  case "${param}" in
    r)
      r=${OPTARG}
      ;;
    e)
      e=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND -1))

if [ -z "${r}" ] || [[ !(${r} =~ [[:alnum:]]/[[:alnum:]]) ]] || [ -z "${e}" ]; then
  usage
fi

key_match="\"key\":\"([^\"]+)\""
key_url="https://api.travis-ci.org/repos/${r}/key"
request_result=$(curl --silent $key_url)

if [[ !($request_result =~ $key_match) ]]; then
  echo "Couldn't retrieve key from ${key_url}. "
  usage
fi

echo -n "${e}" | openssl rsautl -encrypt -pubin -inkey <(echo -e "${BASH_REMATCH[1]}") | openssl base64 -A
echo
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.ApplicationRunner;import org.springframework.boot.SpringApplication;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;@SpringBootApplicationpublic class CalculatorApplication {public static void main(String[] args) {SpringApplication.run(CalculatorApplication.class, args);  }  @Beanpublic ApplicationRunner calculationRunner(Calculator calculator) {return args -> {calculator.calculate(137, 21, '+');calculator.calculate(137, 21, '*');calculator.calculate(137, 21, '-');};  }}
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class)@SpringBootTest(classes = CalculatorApplication.class)public class CalculatorApplicationTests {  @Rulepublic OutputCapture capture = new OutputCapture();  @Autowiredprivate Calculator calculator;  @Testpublic void doingMultiplicationShouldSucceed() {    calculator.calculate(12,13, '*');    capture.expect(Matchers.containsString("12 * 13 = 156"));  }  @Test(expected = IllegalArgumentException.class)public void doingDivisionShouldFail() {    calculator.calculate(12,13, '/');  }}
--------------------------------------------------------------------------------------------------------
spring.http.encoding.charset
spring.mvc.formcontent.filter.enabled
spring.mvc.hiddenmethod.filter.enabled

--------------------------------------------------------------------------------------------------------
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.IOException;

/**
 * A sample web-client class that opens an HTTP connection to a web-server and reads the response from it.
 * 
 * @version $Id$
 */
public class WebClient
{
    public String getContent( URL url )
    {
        StringBuffer content = new StringBuffer();
        try
        {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoInput( true );
            InputStream is = connection.getInputStream();
            byte[] buffer = new byte[2048];
            int count;
            while ( -1 != ( count = is.read( buffer ) ) )
            {
                content.append( new String( buffer, 0, count ) );
            }
        }
        catch ( IOException e )
        {
            return null;
        }
        return content.toString();
    }
}

--------------------------------------------------------------------------------------------------------
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * A sample test-case that demonstrates the parameterized feature of JUnit.
 * 
 * @version $Id$
 */
@RunWith( value = Parameterized.class )
public class TestCalculator
{

    private int expected;

    private int actual;

    @Parameters
    public static Collection<Integer[]> data()
    {
        return Arrays.asList( new Integer[][] { { 1, 1 }, { 2, 4 }, { 3, 9 }, { 4, 16 }, { 5, 25 }, } );
    }

    public TestCalculator( int expected, int actual )
    {
        this.expected = expected;
        this.actual = actual;
    }

    @Test
    public void squareRoot()
    {
        Calculator calculator = new Calculator();
        assertEquals( expected, calculator.squareRoot( actual ) );
    }
}
--------------------------------------------------------------------------------------------------------

import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of the controller.
 * 
 * @version $Id: DefaultController.java 553 2010-03-06 12:29:58Z paranoid12 $
 */
public class DefaultController implements Controller {
	private Map<String, RequestHandler> requestHandlers = new HashMap<String, RequestHandler>();

	protected RequestHandler getHandler(Request request) {
		if (!this.requestHandlers.containsKey(request.getName())) {
			String message = "Cannot find handler for request name " + "["
					+ request.getName() + "]";
			throw new RuntimeException(message);
		}
		return this.requestHandlers.get(request.getName());
	}

	public Response processRequest(Request request) {
		Response response;
		try {
			response = getHandler(request).process(request);
		} catch (Exception exception) {
			response = new ErrorResponse(request, exception);
		}
		return response;
	}

	public void addHandler(Request request, RequestHandler requestHandler) {
		if (this.requestHandlers.containsKey(request.getName())) {
			throw new RuntimeException("A request handler has "
					+ "already been registered for request name " + "["
					+ request.getName() + "]");
		} else {
			this.requestHandlers.put(request.getName(), requestHandler);
		}
	}
}

--------------------------------------------------------------------------------------------------------
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * A sample parameterized test-case.
 * 
 * @version $Id: ParameterizedTest.java 551 2010-03-06 11:37:34Z paranoid12 $
 */
@RunWith(value=Parameterized.class)
public class ParameterizedTest {

    private double expected; 
    private double valueOne; 
    private double valueTwo; 

    @Parameters 
    public static Collection<Integer[]> getTestParameters() {
       return Arrays.asList(new Integer[][] {
          {2, 1, 1},  //expected, valueOne, valueTwo   
          {3, 2, 1},  //expected, valueOne, valueTwo   
          {4, 3, 1},  //expected, valueOne, valueTwo   
       });
    }

    public ParameterizedTest(double expected, 
       double valueOne, double valueTwo) {
       this.expected = expected;
       this.valueOne = valueOne;
       this.valueTwo = valueTwo;
    }

    @Test
    public void sum() {
       Calculator calc = new Calculator();
       assertEquals(expected, calc.add(valueOne, valueTwo), 0);
    } 
}
--------------------------------------------------------------------------------------------------------
  @RunWith(DataProviderRunner.class)
  public class MathUtilsTest {

    private MathUtils mathUtils;

    @Before
    public void setup(){
        mathUtils = new MathUtils();
    }

    @Test
    @UseDataProvider(value = "testAddData", location = MathUtilsDataProviders.class)
    public void add(int inputData[], int expectedOutput) throws Exception {
        assertTrue(mathUtils.add(inputData[0], inputData[1]) == expectedOutput);
    }

    @Test
    @UseDataProvider(value = "testSubtractData", location = MathUtilsDataProviders.class)
    public void subtract(int inputData[], int expectedOutput) throws Exception {
        assertTrue(mathUtils.subtract(inputData[0], inputData[1]) == expectedOutput);
    }

    @Test
    @UseDataProvider(value = "testMultiplyData", location = MathUtilsDataProviders.class)
    public void multiply(int inputData[], int expectedOutput) throws Exception {
        assertTrue(mathUtils.multiply(inputData[0], inputData[1]) == expectedOutput);
    }

    @Test
    @UseDataProvider(value = "testDivideData", location = MathUtilsDataProviders.class)
    public void divide(int inputData[], int expectedOutput) throws Exception {
        assertTrue(mathUtils.divide(inputData[0], inputData[1]) == expectedOutput);
    }

  }
--------------------------------------------------------------------------------------------------------
import static book.twju.timeline.util.Assertion.checkArgument;
import book.twju.timeline.model.Item;
import book.twju.timeline.model.Timeline;

public enum FetchOperation {
  
  NEW {
    @Override
    public <T extends Item> void fetch( Timeline<T> timeline ) {
      checkArgument( timeline != null, TIMELINE_MUST_NOT_BE_NULL );
      
      timeline.fetchNew();
    }
  },
  
  MORE {
    @Override
    public <T extends Item> void fetch( Timeline<T> timeline ) {
      checkArgument( timeline != null, TIMELINE_MUST_NOT_BE_NULL );

      timeline.fetchItems();
    }
  };
  
  static final String TIMELINE_MUST_NOT_BE_NULL = "Argument 'timeline' must not be null.";

  public abstract <T extends Item> void fetch( Timeline<T> timeline );
}
--------------------------------------------------------------------------------------------------------

	public static class OddFilter<T> implements Transformer<T, T> {

		@Override
		public Observable<T> call(Observable<T> observable) {
			return observable
					.lift(new Indexed<T>(1L))
					.filter(pair -> pair.getLeft() % 2 == 1)
					.map(pair -> pair.getRight());
		}
		
	}
--------------------------------------------------------------------------------------------------------
ArgumentCaptor<Memento> captor = forClass( Memento.class );verify( sessionStorage ).store( captor.capture() );assertTrue( !captor.getValue().getItems().isEmpty() 
--------------------------------------------------------------------------------------------------------
public class Indexed<T> implements Operator<Pair<Long, T>, T> {  private final long initialIndex;  public Indexed() {    this(0L);  }  public Indexed(long initial) {    this. initialIndex = initial;  }  @Overridepublic Subscriber<? super T> call(Subscriber<? super Pair<Long, T>>   s) {    return new Subscriber<T>(s) {      private long index = initialIndex;      @Override      public void onCompleted() {        s.onCompleted();      }      @Override      public void onError(Throwable e) {        s.onError(e);      }      @Override      public void onNext(T t) {        s.onNext(new Pair<Long, T>(index++, t));      }    };  }}
--------------------------------------------------------------------------------------------------------
public class ConditionalIgnoreTest {  @Rule  public ConditionalIgnoreRule rule = new ConditionalIgnoreRule();  @Test  @ConditionalIgnore( condition = NotRunningOnWindows.class )  public void focus() {    // ...  }}class NotRunningOnWindows implements IgnoreCondition {  public boolean isSatisfied() {    return      !System.getProperty( "os.name" ).startsWith( "Windows" );  }}

public class ProvideSystemInputExample {  private static final String INPUT = "input";  @Rule  public final TextFromStandardInputStream systemInRule    = TextFromStandardInputStream.emptyStandardInputStream();  @Test  public void stubInput() {    systemInRule.provideLines( INPUT );    assertEquals( INPUT, readLine( System.in ) );  }  private String readLine( InputStream inputstream ) {    return new Scanner( inputstream ).nextLine();  }}

public class CaptureSystemOutputExample {  private static final String OUTPUT = "output";  @Rule  public final SystemOutRule systemOutRule    = new SystemOutRule().enableLog().muteForSuccessfulTests();  @Test  public void captureSystemOutput() {    System.out.print( OUTPUT );    assertEquals( OUTPUT, systemOutRule.getLog() );  }}

public class ProvideSystemPropertyExample {
private static final String JAVA_IO_TMPDIR = "java.io.tmpdir";  private static final String MY_TMPDIR = "/path/to/my/tmpdir";  @Rule  public final ProvideSystemProperty provideCustomTempDirRule    = new ProvideSystemProperty( JAVA_IO_TMPDIR, MY_TMPDIR );  @Test  public void checkTempDir() {    assertEquals( MY_TMPDIR,                  System.getProperty( JAVA_IO_TMPDIR ) );  }}

public class ClearPropertiesExample {  private static final String JAVA_IO_TMPDIR = "java.io.tmpdir";  @Rule  public final ClearSystemProperties clearTempDirRule    = new ClearSystemProperties( JAVA_IO_TMPDIR );  @Test  public void checkTempDir() {    assertNull( System.getProperty( JAVA_IO_TMPDIR ) );  }}

@RunWith( ClasspathSuite.class )@ClassnameFilters( { ".*ServerTest" } )public class ServerIntegrationTestSuite {  @ClassRule  public static TestRule chain = RuleChain    .outerRule( new ServerRule( 4711 ) )    .around( new MyRule() );}

public class ServerRule extends ExternalResource {  private final int port;  public ServerRule( int port ) {    this.port = port;  }  @Override  protected void before() throws Throwable {    System.out.println( "start server on port: " + port );  }  @Override  protected void after() {    System.out.println( "stop server on port: " + port );  }}
--------------------------------------------------------------------------------------------------------
public class MementoAssert  extends AbstractAssert<MementoAssert, Memento>{  private static final String ITEM_PATTERN    = "\nExpected items to be\n  <%s>,\nbut were\n  <%s>.";  private static final String TOP_ITEM_PATTERN    = "\nExpected top item to be\n  <%s>,\nbut was\n  <%s>.";  public static MementoAssert assertThat( Memento actual ) {    return new MementoAssert( actual );  }  public MementoAssert( Memento actual ) {    super( actual, MementoAssert.class );  }  @Override  public MementoAssert isEqualTo( Object expected ) {    hasEqualItems( ( Memento )expected );    hasEqualTopItem( ( Memento )expected );    return this;  }  public MementoAssert hasEqualItems( Memento expected ) {    isNotNull();    if( !actual.getItems().equals( expected.getItems() ) ) {      failWithMessage( ITEM_PATTERN,                       expected.getItems(),                       actual.getItems() );

}    return this;  }  public MementoAssert hasEqualTopItem( Memento expected ) {    isNotNull();    if( !actual.getTopItem().equals( expected.getTopItem() ) ) {      failWithMessage( TOP_ITEM_PATTERN,                       expected.getTopItem(),                       actual.getTopItem() );    }    return this;  }}

assertThat( actual )  .describedAs( description )  .hasMessage( EXPECTED_ERROR_MESSAGE )  .isInstanceOf( NullPointerException.class );
--------------------------------------------------------------------------------------------------------
yum install jenkins
sudo service jenkins start/stop/restart

wget -q -O - http://pkg.jenkins-ci.org/debian/jenkins-ci.org.key | sudo apt-key add -

svnserve -dsvn mkdir svn://localhost/$PATH_REPO/packt-app --username svnpackt

mvn archetype:generate \  -DarchetypeGroupId=org.apache.maven.archetypes \  -DgroupId=com.packt.app \  -DartifactId=packt-app

svnadmin create $PATH_REPO
sudo apt-get install doxygen
--------------------------------------------------------------------------------------------------------

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.boot.actuate.endpoint.AbstractEndpoint;
import org.springframework.boot.actuate.endpoint.Endpoint;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.togglz.core.Feature;
import org.togglz.core.manager.FeatureManager;
import org.togglz.core.repository.FeatureState;
import org.togglz.spring.boot.autoconfigure.TogglzFeature;

/**
 * {@link Endpoint} to expose Togglz info.
 *
 * @author Marcel Overdijk
 */
@ConfigurationProperties(prefix = "togglz.endpoint", ignoreUnknownFields = true)
public class TogglzEndpoint extends AbstractEndpoint<List<TogglzFeature>> {

    private final FeatureManager featureManager;

    public TogglzEndpoint(FeatureManager featureManager) {
        super("togglz");
        Assert.notNull(featureManager, "FeatureManager must not be null");
        this.featureManager = featureManager;
    }

    @Override
    public List<TogglzFeature> invoke() {
        List<TogglzFeature> features = new ArrayList<>();
        for (Feature feature : this.featureManager.getFeatures()) {
            FeatureState featureState = this.featureManager.getFeatureState(feature);
            features.add(new TogglzFeature(feature, featureState));
        }
        Collections.sort(features);
        return features;
    }
}
--------------------------------------------------------------------------------------------------------
public enum MyFeatures implements Feature {

    @EnabledByDefault
    @Label("First Feature")
    FEATURE_ONE,

    @Label("Second Feature")
    FEATURE_TWO;
}

@Bean
public FeatureProvider featureProvider() {
    return new EnumBasedFeatureProvider(MyFeatures.class);
}

@Controller
public class MyClass {
  private FeatureManager manager;

  public MyClass(FeatureManager manager) {
      this.manager = manager;
  }

  @RequestMapping("/")
  public ResponseEntity<?> index() {
      if (manager.isActive(HELLO_WORLD)) {
           ...
      }
  }
}
--------------------------------------------------------------------------------------------------------
/**
	 * The configured features in a format that can be consumed by a
	 * PropertyFeatureProvider.
	 *
	 * @return features in the right format.
	 */
	public Properties getFeatureProperties() {
		Properties properties = new Properties();
		for (String name : features.keySet()) {
			properties.setProperty(name, features.get(name).spec());
		}
		return properties;
	}
--------------------------------------------------------------------------------------------------------
public class TicTacToeSpec {    @Rule    public ExpectedException exception =      ExpectedException.none();    private TicTacToe ticTacToe;    @Before    public final void before() {        ticTacToe = new TicTacToe();    }    @Test    public void whenXOutsideBoardThenRuntimeException()    {        exception.expect(RuntimeException.class);        ticTacToe.validatePosition(5, 2);    }    @Test    public void whenYOutsideBoardThenRuntimeException()    {        exception.expect(RuntimeException.class);        ticTacToe.validatePosition(2, 5);    }}
--------------------------------------------------------------------------------------------------------
@Service("fibonacci")public class FibonacciService {    public static final int LIMIT = 30;    public int getNthNumber(int n) {        if (isOutOfLimits(n) {        throw new IllegalArgumentException(        "Requested number must be a positive " +           number no bigger than " + LIMIT);        if (n == 0) return 0;        if (n == 1 || n == 2) return 1;        int first, second = 1, result = 1;        do {            first = second;            second = result;            result = first + second;            --n;        } while (n > 2);        return result;    }    private boolean isOutOfLimits(int number) {        return number > LIMIT || number < 0;    }}
--------------------------------------------------------------------------------------------------------
apply plugin: 'java'apply plugin: 'application'sourceCompatibility = 1.8version = '1.0'mainClassName = "com.packtpublishing.tddjava.ch09.Application"repositories {    mavenLocal()    mavenCentral()}dependencies {    compile group: 'org.springframework.boot',            name: 'spring-boot-starter-thymeleaf',            version: '1.2.4.RELEASE'    testCompile group: 'junit',    name: 'junit',    version: '4.12'}
--------------------------------------------------------------------------------------------------------
mvn clean jetty:run
--------------------------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;

public class Location {

    private static final int FORWARD = 1;
    private static final int BACKWARD = -1;

    public int getX() {
        return point.getX();
    }

    public int getY() {
        return point.getY();
    }

    private Point point;
    public Point getPoint() {
        return point;
    }

    private Direction direction;
    public Direction getDirection() {
        return this.direction;
    }
    public void setDirection(Direction direction) {
        this.direction = direction;
    }

    public Location(Point point, Direction direction) {
        this.point = point;
        this.direction = direction;
    }

    public boolean forward() {
        return move(FORWARD, new Point(100, 100), new ArrayList<>());
    }
    public boolean forward(Point max) {
        return move(FORWARD, max, new ArrayList<>());
    }
    public boolean forward(Point max, List<Point> obstacles) {
        return move(FORWARD, max, obstacles);
    }

    public boolean backward() {
        return move(BACKWARD, new Point(100, 100), new ArrayList<>());
    }
    public boolean backward(Point max) {
        return move(BACKWARD, max, new ArrayList<>());
    }
    public boolean backward(Point max, List<Point> obstacles) {
        return move(BACKWARD, max, obstacles);
    }

    private boolean move(int fw, Point max, List<Point> obstacles) {
        int x = point.getX();
        int y = point.getY();
        switch(getDirection()) {
            case NORTH:
                y = wrap(getY() - fw, max.getY());
                break;
            case SOUTH:
                y = wrap(getY() + fw, max.getY());
                break;
            case EAST:
                x = wrap(getX() + fw, max.getX());
                break;
            case WEST:
                x = wrap(getX() - fw, max.getX());
                break;
        }
        if (isObstacle(new Point(x, y), obstacles)) {
            return false;
        } else {
            point = new Point(x, y);
            return true;
        }
    }

    private boolean isObstacle(Point point, List<Point> obstacles) {
        for (Point obstacle : obstacles) {
            if (obstacle.getX() == point.getX() && obstacle.getY() == point.getY()) {
                return true;
            }
        }
        return false;
    }

    private int wrap(int point, int maxPoint) {
        if (maxPoint > 0) {
            if (point > maxPoint) {
                return 1;
            } else if (point == 0) {
                return maxPoint;
            }
        }
        return point;
    }

    public void turnLeft() {
        this.direction = direction.turnLeft();
    }

    public void turnRight() {
        this.direction = direction.turnRight();
    }

    public Location copy() {
        return new Location(new Point(point.getX(), point.getY()), direction);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Location location = (Location) o;
        if (getX() != location.getX()) return false;
        if (getY() != location.getY()) return false;
        if (direction != location.direction) return false;
        return true;
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class CustomExceptionMapper implements ExceptionMapper<IllegalArgumentException> {

    @Override
    public Response toResponse(IllegalArgumentException exception) {
        return Response.ok("Illegal Argument Exception Caught").build();
    }
}

--------------------------------------------------------------------------------------------------------
import java.lang.reflect.Method;

import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;

public class FindEventBusSubscribers implements BeanPostProcessor {

	@Autowired
	private EventBus eventBus;
	private static final Logger LOG = Logger.getLogger(FindEventBusSubscribers.class);

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		Method[] beanMethods = bean.getClass().getMethods();
		for (Method beanMethod : beanMethods) {
			if (beanMethod.isAnnotationPresent(Subscribe.class)) {
				eventBus.register(bean);
				LOG.info(String.format("Found event bus subscriber class %s. Subscriber method name=%s", bean
						.getClass().getSimpleName(), beanMethod.getName()));
				break;
			}
		}
		return bean;
	}

}
--------------------------------------------------------------------------------------------------------
<Connector port="8080" protocol="HTTP/1.1"               connectionTimeout="20000"               redirectPort="8443" />

<role rolename="manager-gui"/>  <user username="admin" password="admin" roles="manager-gui"/>

insert into user (host, user, password, select_priv, insert_priv, update_priv)           values ('%', 'user1', password('usper1_pass'),'Y','Y','Y');

<%@ page language="java" contentType="text/html; charset=UTF-8"    pageEncoding="UTF-8"%>

wsimport -keep -p packt.jee.eclipse.ws.soap.client http://localhost:8080/CourseMgmtWSProject/courseService?wsdl


-- MySQL Script generated by MySQL Workbench-- Sun Mar  8 18:17:07 2015-- Model: New Model    Version: 1.0-- MySQL Workbench Forward EngineeringSET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';-- ------------------------------------------------------- Schema course_management-- -----------------------------------------------------DROP SCHEMA IF EXISTS `course_management` ;-- ------------------------------------------------------- Schema course_management-- -----------------------------------------------------CREATE SCHEMA IF NOT EXISTS `course_management` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci ;USE `course_management` ;-- ------------------------------------------------------- Table `course_management`.`Teacher`-- -----------------------------------------------------DROP TABLE IF EXISTS `course_management`.`Teacher` ;CREATE TABLE IF NOT EXISTS `course_management`.`Teacher` (  `id` INT NOT NULL AUTO_INCREMENT,  `first_name` VARCHAR(45) NOT NULL,  `last_name` VARCHAR(45) NULL,  `designation` VARCHAR(45) NOT NULL,  PRIMARY KEY (`id`))ENGINE = InnoDB;-- ------------------------------------------------------- Table `course_management`.`Course`

SET SQL_MODE=@OLD_SQL_MODE;SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;


--------------------------------------------------------------------------------------------------------
LocalDate.of(2017, 1, 31)                         .datesUntil(LocalDate.of(2018, 1, 1), Period.ofMonths(1))         .map(ld -> ld.format(DateTimeFormatter.ofPattern("EEE MMM dd, yyyy")))         .forEach(System.out::println)
long sundaysIn2017 = LocalDate.of(2017, 1, 1)                              .datesUntil(LocalDate.of(2018, 1, 1))                              .filter(ld -> ld.getDayOfWeek() == DayOfWeek.SUNDAY)                              .count(); 

Date dt = new Date();LocalDate ld= dt.toInstant()                 .atZone(ZoneId.systemDefault())                 .toLocalDate();System.out.println("Current Local Date: " + ld);

package com.jdojo.misc;public class SpinWaitTest implements Runnable {    private volatile boolean dataReady = false;    @Override    public void run() {        // Wait while data is ready        while (!dataReady) {            // Hint a spin-wait            Thread.onSpinWait();        }        processData();    }    private void processData() {        // Data processing logic goes here    }    public void setDataReady(boolean dataReady) {        this.dataReady = dataReady;    }}
--------------------------------------------------------------------------------------------------------
javadoc -html5 <other-options>
M/dd/yyyy HH:mm zzzz
M/dd/yyyy HH:mm vvvv
--------------------------------------------------------------------------------------------------------
java -Djdk.serialFilter=maxarray=100;maxdepth=3;com.jdojo.** --module-path com.jdojo.misc\build\classes --module com.jdojo.misc/com.jdojo.misc.ObjectFilterTest

Chapter 20 ■ Other Changes in JDK 9509public class Item implements Serializable {    private int id;        private String name;    private int[] points;    public Item(int id, String name, int[] points) {        this.id = id;        this.name = name;        this.points = points;    }    /* Add getters and setters here */    @Override    public String toString() {        return "[id=" + id + ", name=" + name + ", points=" + Arrays.toString(points) + "]";    }}

import java.io.File;import java.io.FileInputStream;import java.io.FileOutputStream;import java.io.ObjectInputFilter;import java.io.ObjectInputFilter.Config;import java.io.ObjectInputStream;import java.io.ObjectOutputStream;public class ObjectFilterTest {    public static void main(String[] args)  {                 // Relative path of the output/input file        File file = new File("serialized", "item.ser");        // Make sure directories exist        ensureParentDirExists(file);        // Create an Item used in serialization and deserialization        Item item = new Item(100, "Pen", new int[]{1,2,3,4});        // Serialize the item        serialize(file, item);
        // Print the global filter        ObjectInputFilter globalFilter = Config.getSerialFilter();        System.out.println("Global filter: " + globalFilter);        // Deserialize the item        Item item2 = deserialize(file);        System.out.println("Deserialized using global filter: " + item2);        // Use a filter to reject array size > 2        String maxArrayFilterPattern = "maxarray=2";        ObjectInputFilter maxArrayFilter = Config.createFilter(maxArrayFilterPattern);                 Item item3 = deserialize(file, maxArrayFilter);        System.out.println("Deserialized with a maxarray=2 filter: " + item3);        // Create a custom filterArrayLengthObjectFilter customFilter = new ArrayLengthObjectFilter(5);                        Item item4 = deserialize(file, customFilter);        System.out.println("Deserialized with a custom filter (maxarray=5): " + item4);    }    private static void serialize(File file, Item item) {                try (ObjectOutputStream out =  new ObjectOutputStream(new FileOutputStream(file))) {                        out.writeObject(item);            System.out.println("Serialized Item: " + item);        } catch (Exception e) {            e.printStackTrace();        }    }    private static Item deserialize(File file) {try  (ObjectInputStream  in  =   new  ObjectInputStream(new  FileInputStream(file)))  {                                    Item item = (Item)in.readObject();            return item;        } catch (Exception e) {            System.out.println("Could not deserialize item. Error: " + e.getMessage());        }        return null;    }    private static Item deserialize(File file, ObjectInputFilter filter) {        try (ObjectInputStream in =  new ObjectInputStream(new FileInputStream(file))) {                        // Set the object input filter passed in            in.setObjectInputFilter(filter);            Item item = (Item)in.readObject();            return item;        } catch (Exception e) {            System.out.println("Could not deserialize item. Error: " + e.getMessage());                    }        return null;    }
    private static void ensureParentDirExists(File file) {        File parent = file.getParentFile();        if(!parent.exists()) {            parent.mkdirs();        }        System.out.println("Input/output file is " + file.getAbsolutePath());    }}
--------------------------------------------------------------------------------------------------------
ObjectInputFilter.Config class:// Create a filterString pattern = "maxarray=100;maxdepth=3;com.jdojo.**";ObjectInputFilter globalFilter = ObjectInputFilter.Config.createFilter(pattern);// Set a global filterObjectInputFilter.Config.setSerialFilter(lobalFilter);

import java.io.ObjectInputFilter;public class ArrayLengthObjectFilter implements ObjectInputFilter {    private long maxLenth = -1;    public ArrayLengthObjectFilter(int maxLength) {        this.maxLenth = maxLength;    }    @Override    public Status checkInput(FilterInfo info) {        long arrayLength = info.arrayLength();        if (arrayLength >= 0 && arrayLength > this.maxLenth) {            return Status.REJECTED;        }        return Status.ALLOWED;    }}

import java.io.ObjectInputFilter;public class ArrayLengthObjectFilter implements ObjectInputFilter {    private long maxLenth = -1;    public ArrayLengthObjectFilter(int maxLength) {        this.maxLenth = maxLength;    }    @Override    public Status checkInput(FilterInfo info) {        long arrayLength = info.arrayLength();        if (arrayLength >= 0 && arrayLength > this.maxLenth) {            return Status.REJECTED;        }        return Status.ALLOWED;    }}
--------------------------------------------------------------------------------------------------------
java -p lib -m claim/pkg3.Main
ava -Xdiag:resolver -p lib -m claim/pkg3.Main
java --module-path C:\applib;C:\lib other-args-go-here
java -p C:\applib;C:\extlib other-args-go-here
java --module-path=C:\applib;C:\lib other-args-go-here
java --list-modules
java --module-path lib --list-modules
java --list-modules java.sql
javac -d mods --module-source-path src $(find src -name "*.java"
avac -d mods\com.jdojo.intro  --module-version 1.0  src\com.jdojo.intro\module-info.java      src\com.jdojo.intro\com\jdojo\intro\Welcome.java
FOR /F "tokens=1 delims=" %A in ('dir src\*.java /S /B') do javac -d mods --module-source-path src %A
javac -d mods --module-source-path src $(find src -name "*.java")
ar --create --file lib/com.jdojo.intro-1.0.jar --main-class com.jdojo.intro.Welcome --module-version 1.0 -C mods/com.jdojo.intro .
java --module-path <module-path> --module <module>/<main-class>
jar --describe-module --file lib\cglib-2.2.2.jar-plugin













javap -verbose jar:file:lib/com.jdojo.intro-1.0.jar!/module-info.class
javap --module-path lib --module com.jdojo.intro com.jdojo.intro.Welcome
javap jrt:/java.sql/module-info.class
--------------------------------------------------------------------------------------------------------
/env -class-path C:\Java9Revealed\com.jdojo.jshell\build\classes
import java.io.*
import java.math.*
import java.net.*
import java.nio.file.*
import java.util.*
import java.util.concurrent.*
import java.util.function.*
import java.util.prefs.*
import java.util.regex.*
import java.util.stream.*
import java.time.*;
import com.jdojo.jshell.*;
void printf(String format, Object... args) { System.out.printf(format, args); }
--------------------------------------------------------------------------------------------------------
Map<String, Integer> mapNameAge = people.stream()
      .collect(Collectors.toMap(
          Person::getName,
          Person::getAge,
          (u,v) -> { throw new IllegalStateException(String.format("Duplicate key %s", u)); },
          LinkedHashMap::new
          ));
--------------------------------------------------------------------------------------------------------
# itertools.permutations() generates permutations 
# for an iterable. Time to brute-force those passwords ;-)

>>> import itertools
>>> for p in itertools.permutations('ABCD'):
...     print(p)
--------------------------------------------------------------------------------------------------------
BufferedImageimg=null;try{img=ImageIO.read(newFile("Image.png"));intheight=img.getHeight();intwidth=img.getWidth();int[][]data=newint[height][width];for(inti=0;i<height;i++){for(intj=0;j<width;j++){intrgb=img.getRGB(i,j);// negative integersdata[i][j]=rgb;}}}catch(IOExceptione){// handle exception}

intblue=0x0000ff&rgb;intgreen=0x0000ff&(rgb>>8);intred=0x0000ff&(rgb>>16);intalpha=0x0000ff&(rgb>>24);

byte[]pixels=((DataBufferByte)img.getRaster().getDataBuffer()).getData();for(inti=0;i<pixels.length/3;i++){intblue=Byte.toUnsignedInt(pixels[3*i]);intgreen=Byte.toUnsignedInt(pixels[3*i+1]);intred=Byte.toUnsignedInt(pixels[3*i+2]);}

//convert rgb to grayscale (0 to 1) where colors are on a scale of 0 to 255doublegray=(0.2126*red+0.7152*green+0.0722*blue)/255.0
--------------------------------------------------------------------------------------------------------
source <filename>
order by rand() limit 1000
DROPTABLEIFEXISTSdata;CREATETABLEIFNOTEXISTSdata(idINTEGERPRIMARYKEY,yrINTEGER,cityVARCHAR(80));INSERTINTOdata(id,yr,city)VALUES(1,2015,"San Francisco"),(2,2014,"New York"),(3,2012,"Los Angeles")
--------------------------------------------------------------------------------------------------------
intsize=3;RealVectorvector=newArrayRealVector(size);

introwDimension=10;intcolDimension=20;RealMatrixmatrix=newArray2DRowRealMatrix(rowDimension,colDimension);

double[][]data=;RealMatrixblockMatrix=newBlockRealMatrix(data);
intdim=10000;RealVectorsparseVector=newOpenMapRealVector(dim);
--------------------------------------------------------------------------------------------------------
publicclassBasicScatterChartextendsApplication{publicstaticvoidmain(String[]args){launch(args);}@Overridepublicvoidstart(Stagestage)throwsException{int[]xData={1,2,3,4,5};double[]yData={1.3,2.1,3.3,4.0,4.8};/* add Data to a Series */Seriesseries=newSeries();for(inti=0;i<xData.length;i++){series.getData().add(newData(xData[i],yData[i]));}/* define the axes */NumberAxisxAxis=newNumberAxis();xAxis.setLabel("x");NumberAxisyAxis=newNumberAxis();yAxis.setLabel("y");/* create the scatter chart */ScatterChart<Number,Number>scatterChart=newScatterChart<>(xAxis,yAxis);scatterChart.getData().add(series);/* create a scene using the chart */Scenescene=newScene(scatterChart,800,600);/* tell the stage what scene to use and render it! */stage.setScene(scene);stage.show();}}
--------------------------------------------------------------------------------------------------------
scatterChart.setAnimated(false);.../* render the image */stage.show();.../* save the chart to a file AFTER the stage is rendered */WritableImageimage=scatterChart.snapshot(newSnapshotParameters(),null);Filefile=newFile("chart.png");ImageIO.write(SwingFXUtils.fromFXImage(image,null),"png",file);

--------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>

	<groupId>org.demo</groupId>
	<artifactId>demo</artifactId>
	<version>0.0.1-SNAPSHOT</version>

    <packaging>war</packaging>
	<description>Demo project</description>

	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>1.0.0.BUILD-SNAPSHOT</version>
	</parent>

	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
            <exclusions>
                <exclusion>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-tomcat</artifactId>
                </exclusion>
            </exclusions>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
		</dependency>
	</dependencies>

	<properties>
        <start-class>demo.Application</start-class>
		<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		<project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.7</java.version>
	</properties>
	<repositories>
		<repository>
			<id>spring-snapshots</id>
			<name>Spring Snapshots</name>
			<url>http://repo.spring.io/snapshot</url>
			<snapshots>
				<enabled>true</enabled>
			</snapshots>
		</repository>
		<repository>
			<id>spring-milestones</id>
			<name>Spring Milestones</name>
			<url>http://repo.spring.io/milestone</url>
			<snapshots>
				<enabled>false</enabled>
			</snapshots>
		</repository>
	</repositories>
	<pluginRepositories>
		<pluginRepository>
			<id>spring-snapshots</id>
			<name>Spring Snapshots</name>
			<url>http://repo.spring.io/snapshot</url>
			<snapshots>
				<enabled>true</enabled>
			</snapshots>
		</pluginRepository>
		<pluginRepository>
			<id>spring-milestones</id>
			<name>Spring Milestones</name>
			<url>http://repo.spring.io/milestone</url>
			<snapshots>
				<enabled>false</enabled>
			</snapshots>
		</pluginRepository>
	</pluginRepositories>
</project>
--------------------------------------------------------------------------------------------------------
List<Class<?>> getAllClassesInPackageContaining(Class<?> clazz) 
    throws IOException 
{
    String clazzPackageName = clazz
            .getPackage()
            .getName();

    String clazzPath = clazz
            .getResource(".")
            .getPath();

    Path packagePath = Paths.get(clazzPath)
            .getParent();

    final List<Class<?>> packageClasses = new ArrayList<>();

    Files.walkFileTree(packagePath, new SimpleFileVisitor<Path>() {
        @Override
        public FileVisitResult visitFile(
                Path file, BasicFileAttributes attrs) 
                throws IOException 
        {
            String filename = 
                file.getName(file.getNameCount()-1).toString();

            if (filename.endsWith(".class")) {
                String className = filename.replace(".class", "");

                try {
                    Class<?> loadedClazz = Class.forName(
                        clazzPackageName + "." + className);
                        
                    packageClasses.add(loadedClazz);
                }
                catch(ClassNotFoundException e) {
                    System.err.println(
                        "class not found: " + e.getMessage());
                }
            }

            return super.visitFile(file, attrs);
        }
    });

    return packageClasses;
}
--------------------------------------------------------------------------------------------------------
language: java

matrix:
  include:
    - jdk: openjdk8
    - jdk: openjdk10
    - jdk: openjdk11
    - jdk: openjdk-ea
  allow_failures:
    # ErrorProne/javac is not yet working on JDK 11 nor 12 (current -ea)
    - jdk: openjdk11
    - jdk: openjdk-ea

before_install:
  - unset _JAVA_OPTIONS

after_success:
  - .buildscript/deploy_snapshot.sh

env:
  global:
    - secure: "nkVNCk8H2orIZOmow0t+Qub1lFQCYpJgNZf17zYI5x0JVqQNCqkcTYYDHqzwkvkmixXFCrfYZQuXy7x2qg9zjCX+vmhlmiMWwe8dNa34OLTseuuR2irS0C8nRGRYxKM7EGenRZSqbFVUksKRm2iWnHKxtmCzeDaS7MoMit2wdUo="
    - secure: "j8+hPaZnyM+UlOBYOEA96fPbVWbN6bMQ28SGQnFMwxo2axHi9ww9Au1N7002HzHnxX8iyesdWFBigArnEL8zKEoXH9Bmur0sn3Ys4bu72C3ozscP4cjXfYSHj8aVLp1EIMdQPDF7MkCccx9l7ONdsW0ltmdiVUtDxzqkH+63WLU="

branches:
  except:
    - gh-pages

notifications:
  email: false

cache:
  directories:
    - $HOME/.m2
--------------------------------------------------------------------------------------------------------
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@Configuration
public class PlayerRouter {

    @Bean
    public RouterFunction<ServerResponse> route(PlayerHandler playerHandler) {
        return RouterFunctions
                .route(GET("/players/{name}"), playerHandler::getName)
                .filter(new ExampleHandlerFilterFunction());
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.web.reactive.function.server.HandlerFilterFunction;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.FORBIDDEN;

public class ExampleHandlerFilterFunction implements HandlerFilterFunction<ServerResponse, ServerResponse> {

    @Override
    public Mono<ServerResponse> filter(ServerRequest serverRequest, HandlerFunction<ServerResponse> handlerFunction) {
        if (serverRequest.pathVariable("name").equalsIgnoreCase("test")) {
            return ServerResponse.status(FORBIDDEN).build();
        }
        return handlerFunction.handle(serverRequest);
    }
}
--------------------------------------------------------------------------------------------------------
@Testpublic void fetchItemWithExceptionOnStoreTop()  throws IOException{  IOException cause = new IOException();  doThrow( cause ).when( storage ).storeTop( any( Item.class ) );  Throwable actual = thrownBy( () -> timeline.fetchItems() );  assertNotNull( actual );  assertTrue( actual instanceof IllegalStateException );  assertSame( cause, actual.getCause() );  assertEquals( Timeline.ERROR_STORE_TOP, actual.getMessage() );}
--------------------------------------------------------------------------------------------------------
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

public class AdminInterceptor extends HandlerInterceptorAdapter {

   @Override
   public void postHandle(HttpServletRequest req, HttpServletResponse res,
         Object handler, ModelAndView model)  throws Exception {

      System.out.println("Called after handler method request completion,"
            + " before rendering the view");

      LocalTime time = LocalTime.now();
      int hrs = time.getHour();
      if (hrs >= 0 && hrs <= 12) {
         model.addObject("greeting", "Good morning!");
      } else if (hrs > 12 && hrs <= 17) {
         model.addObject("greeting", "Good afternoon!");
      } else {
         model.addObject("greeting", "Good evening!");
      }
   }
}
--------------------------------------------------------------------------------------------------------
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class GuestInterceptor implements HandlerInterceptor {

   // Called before handler method invocation
   @Override
   public boolean preHandle(HttpServletRequest req, HttpServletResponse res,
         Object handler) throws Exception {
      System.out.println("Called before handler method");
      req.setAttribute("fname", "Elizabeth");
      return true;
   }

   // Called after handler method request completion, before rendering the view
   @Override
   public void postHandle(HttpServletRequest req, HttpServletResponse res, 
         Object handler, ModelAndView model)  throws Exception {
      System.out.println("Called after handler method request completion,"
            + " before rendering the view");

      model.addObject("lname", "Brown");
   }

   // Called after rendering the view
   @Override
   public void afterCompletion(HttpServletRequest req, HttpServletResponse res,
         Object handler, Exception ex)  throws Exception {
      System.out.println("Called after rendering the view");
   }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@Component
public class MyWebSocketHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(final WebSocketSession session, final TextMessage message) throws Exception {

        String clientMessage = message.getPayload();

        if (clientMessage.startsWith("Hello") || clientMessage.startsWith("Hi")) {
            session.sendMessage(new TextMessage("Hello! What can i do for you?"));
        } else {
            session.sendMessage(
                new TextMessage("This is a simple hello world example of using Spring WebSocket."));
        }
    }
}
--------------------------------------------------------------------------------------------------------
@Qualifier@Retention(RUNTIME)@Target({ TYPE, METHOD, FIELD, PARAMETER })@Documentedpublic @interface SomeQualifierOne {    public static final class Literalextends AnnotationLiteral<SomeQualifierOne>implements SomeQualifierOne {Chapter 3  IdentIfyIng Beans
71private static final long serialVersionUID = 1L;public static final Literal INSTANCE = new Literal();   }}

@Qualifier@Retention(RUNTIME)@Target({ TYPE, METHOD, FIELD, PARAMETER })@Documentedpublic @interface SomeQualifierOne {    TimeUnit value() default DAYS;    public static final class Literalextends AnnotationLiteral<SomeQualifierOne>implements SomeQualifierOne {private static final long serialVersionUID = 1L;public static final Literal INSTANCE = of(DAYS);private final TimeUnit value;public static Literal of(TimeUnit value) {return new Literal(value);}private Literal(TimeUnit value) {this.value = value;}public TimeUnit value() {return value;}    }}
--------------------------------------------------------------------------------------------------------

import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

import java.util.Objects;

/**
 * Redis data converter implementation
 */
@Configuration
public class RedisDataConverter {

    @Bean
    @ConfigurationPropertiesBinding
    public Str2Host strToHost() {
        return new Str2Host();
    }

    @Bean
    @ConfigurationPropertiesBinding
    public Int2Port intToPort() {
        return new Int2Port();
    }

    /**
     * Custom string to host redis converter {@link Converter}
     */
    public class Str2Host implements Converter<String, RedisData.RedisHost> {
        @Override
        public RedisData.RedisHost convert(final String source) {
            if (StringUtils.isNotBlank(source)) {
                return RedisData.RedisHost.of(source);
            }
            return null;
        }
    }

    /**
     * Custom integer to port redis converter {@link Converter}
     */
    public class Int2Port implements Converter<Integer, RedisData.RedisPort> {
        @Override
        public RedisData.RedisPort convert(final Integer source) {
            if (Objects.nonNull(source)) {
                return RedisData.RedisPort.of(source);
            }
            return null;
        }
    }
}
--------------------------------------------------------------------------------------------------------
@Aspect
@Component
public class FeaturesAspect {

    private static final Logger LOG = LogManager.getLogger(FeaturesAspect.class);

    @Around(value = "@within(featureAssociation) || @annotation(featureAssociation)")
    public Object checkAspect(ProceedingJoinPoint joinPoint, FeatureAssociation featureAssociation) throws Throwable {
        if (featureAssociation.value().isActive()) {
            return joinPoint.proceed();
        } else {
            LOG.info("Feature " + featureAssociation.value().name() + " is not enabled!");
            return null;
        }
    }

}

import java.lang.annotation.*;

/**
 * Api ignore constraint
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE, ElementType.PARAMETER})
public @interface ApiIgnore {

    /**
     * A brief description of why this parameter/operation is ignored
     *
     * @return the description of why it is ignored
     */
    String message() default "{ApiIgnore.message}";
}
--------------------------------------------------------------------------------------------------------
import com.sensiblemetrics.api.sqoola.common.exception.InvalidTokenFormatException;
import org.apache.commons.lang3.StringUtils;

public class KeycloakTokenValidator {
    private static final String BEARER_PREFIX = "Bearer ";

    public static void validate(final String keycloakToken) throws InvalidTokenFormatException {
        if (!isValid(keycloakToken)) {
            throw new InvalidTokenFormatException("Keycloak token must have 'Bearer ' prefix");
        }
    }

    private static boolean isValid(final String keycloakToken) {
        return (StringUtils.isNotBlank(keycloakToken) && keycloakToken.startsWith(BEARER_PREFIX));
    }
}
--------------------------------------------------------------------------------------------------------
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

public class KeycloakRestTemplate extends RestTemplate {

    public KeycloakRestTemplate(final String keycloakToken) {
        if (StringUtils.isNotBlank(keycloakToken)) {
            this.setInterceptors(Collections.singletonList(new KeycloakInterceptor(keycloakToken)));
        }
    }
}

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

public class KeycloakInterceptor implements ClientHttpRequestInterceptor {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakInterceptor.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String REQUEST_ID_MDC_KEY = "req_id";
    private static final String BEARER_PREFIX = "Bearer ";
    private String keycloakToken;

    public KeycloakInterceptor(String keycloakToken) {
        this.keycloakToken = keycloakToken.startsWith(BEARER_PREFIX) ? keycloakToken : BEARER_PREFIX + keycloakToken;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
        throws IOException {
        HttpHeaders headers = request.getHeaders();
        headers.add(AUTHORIZATION_HEADER, keycloakToken);
        headers.add(REQUEST_ID_HEADER, getRequestId());
        return execution.execute(request, body);
    }

    private String getRequestId() {
        String requestId = MDC.get(REQUEST_ID_MDC_KEY);
        LOG.debug("'X-Request-Id' sent {}", requestId);
        return requestId;
    }
}
--------------------------------------------------------------------------------------------------------
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component(SubscriptionOperationServiceAspect.COMPONENT_ID)
public class SubscriptionOperationServiceAspect {

    /**
     * Default component ID
     */
    public static final String COMPONENT_ID = "subscriptionOperationServiceAspect";

    @Before(value = "execution(* com.sensiblemetrics.api.sqoola.common.service.dao.impl.subscription.period.SubscriptionOperationPeriodServiceImpl.*(..))")
    public void subscriptionOperationPeriodBeforeAdvice(final JoinPoint joinPoint) {
        log.info(String.format("SubscriptionOperationServiceAspect: processing model={%s} by method={%s} with args={%s}", joinPoint.getTarget(), joinPoint.getSignature(), joinPoint.getArgs()));
    }

    @After(value = "execution(* com.sensiblemetrics.api.sqoola.common.service.dao.impl.subscription.period.SubscriptionOperationPeriodServiceImpl.*(..))")
    public void subscriptionOperationPeriodAfterAdvice(final JoinPoint joinPoint) {
        log.info(String.format("SubscriptionOperationServiceAspect: model={%s} has been processed", joinPoint.getTarget()));
    }

    @Before(value = "execution(* com.sensiblemetrics.api.sqoola.common.service.dao.impl.subscription.SubscriptionOperationServiceImpl.*(..))")
    public void subscriptionOperationBeforeAdvice(final JoinPoint joinPoint) {
        log.info(String.format("SubscriptionOperationServiceAspect: processing model={%s} by method={%s} with args={%s}", joinPoint.getTarget(), joinPoint.getSignature(), joinPoint.getArgs()));
    }

    @After(value = "execution(* com.sensiblemetrics.api.sqoola.common.service.dao.impl.subscription.SubscriptionOperationServiceImpl.*(..))")
    public void subscriptionOperationAfterAdvice(final JoinPoint joinPoint) {
        log.info(String.format("SubscriptionOperationServiceAspect: model={%s} has been processed", joinPoint.getTarget()));
    }
}
--------------------------------------------------------------------------------------------------------
import com.sensiblemetrics.api.sqoola.common.model.dao.listeners.event.LoadEventListenerImp;
import com.sensiblemetrics.api.sqoola.common.model.dao.listeners.event.RefreshEventListenerImp;
import com.sensiblemetrics.api.sqoola.common.model.dao.listeners.event.SaveUpdateEventListenerImp;
import org.hibernate.boot.Metadata;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;

public class EventListenerIntegrator implements Integrator {

    @Override
    public void integrate(Metadata metadata, SessionFactoryImplementor sessionFactory, SessionFactoryServiceRegistry serviceRegistry) {

        final EventListenerRegistry eventListenerRegistry = serviceRegistry.getService(EventListenerRegistry.class);
        eventListenerRegistry.getEventListenerGroup(EventType.SAVE).appendListener(new SaveUpdateEventListenerImp());
        eventListenerRegistry.getEventListenerGroup(EventType.LOAD).appendListener(new LoadEventListenerImp());
        eventListenerRegistry.getEventListenerGroup(EventType.REFRESH).appendListener(new RefreshEventListenerImp());
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sessionFactory, SessionFactoryServiceRegistry serviceRegistry) {
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.amqp.core.AcknowledgeMode;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.listener.MessageListenerContainer;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MessageListenerContainerFactory {

    @Autowired
    private ConnectionFactory connectionFactory;

    public MessageListenerContainer createMessageListenerContainer(final String queueName) {
        final SimpleMessageListenerContainer mlc = new SimpleMessageListenerContainer(this.connectionFactory);
        mlc.addQueueNames(queueName);
        mlc.setAcknowledgeMode(AcknowledgeMode.AUTO);
        return mlc;
    }
}
 @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME, pattern = DEFAULT_DATE_FORMAT_PATTERN_EXT)
--------------------------------------------------------------------------------------------------------
    @Bean
    public MultipartResolver multipartResolver() {
        final CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
        multipartResolver.setMaxUploadSize(env.getRequiredProperty("sqoola.config.maxUploadSize", Integer.class));
        multipartResolver.setMaxUploadSizePerFile(env.getRequiredProperty("sqoola.config.maxUploadSizePerFile", Integer.class));
        multipartResolver.setResolveLazily(true);
        multipartResolver.setPreserveFilename(false);
        multipartResolver.setDefaultEncoding(StandardCharsets.UTF_8.name());
        return multipartResolver;
    }
--------------------------------------------------------------------------------------------------------
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        final ThemeChangeInterceptor themeChangeInterceptor = new ThemeChangeInterceptor();
        themeChangeInterceptor.setParamName("theme");
        registry.addInterceptor(themeChangeInterceptor);

        final LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName("lang");
        registry.addInterceptor(localeChangeInterceptor);

        // Register guest interceptor with single path pattern
        registry.addInterceptor(new GuestInterceptor()).addPathPatterns("/guest");

        // Register admin interceptor with multiple path patterns
        registry.addInterceptor(new AdminInterceptor()).addPathPatterns(new String[]{"/admin", "/admin/*"});
    }
--------------------------------------------------------------------------------------------------------

@ConfigurationProperties(prefix = "myapp.mail")
@Validated
//@EnableConfigurationProperties(MailProperties.class)
public class MailConfigProperties {

    @Email
    private String to;
    @NotBlank
    private String host;
    private int port;
    private String[] cc;
    private List<String> bcc;

    @Valid
    private Credential credential = new Credential();

    //Setter and Getter methods

    public class Credential {
        @NotBlank
        private String userName;
        @Size(max = 15, min = 6)
        private String password;

        //Setter and Getter methods

    }
}
//myapp:
//    mail:
//    to: sunil@example.com
//    host: mail.example.com
//        port: 250
//        cc:
//        - mike@example.com
//      - david@example.com
//    bcc:
//        - sumit@example.com
//      - admin@example.com
//    credential:
//        user-name: sunil1234
//        password: xyz@1234
--------------------------------------------------------------------------------------------------------

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.dialect.*;
import org.javers.common.exception.JaversException;
import org.javers.common.exception.JaversExceptionCode;
import org.javers.repository.sql.DialectName;

/**
 * Dialect utilities implementation
 */
@Slf4j
@UtilityClass
public class DialectMapper {

    public DialectName map(final Dialect hibernateDialect) {

        if (hibernateDialect instanceof SQLServerDialect) {
            return DialectName.MSSQL;
        }
        if (hibernateDialect instanceof H2Dialect) {
            return DialectName.H2;
        }
        if (hibernateDialect instanceof Oracle8iDialect) {
            return DialectName.ORACLE;
        }
        if (hibernateDialect instanceof PostgreSQL81Dialect) {
            return DialectName.POSTGRES;
        }
        if (hibernateDialect instanceof MySQLDialect) {
            return DialectName.MYSQL;
        }
        throw new JaversException(JaversExceptionCode.UNSUPPORTED_SQL_DIALECT, hibernateDialect.getClass().getSimpleName());
    }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Josh Cummings
 */
@EnableWebSecurity
public class OAuth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests()
				.antMatchers("/message/**").hasAuthority("SCOPE_message:read")
				.anyRequest().authenticated()
				.and()
			.oauth2ResourceServer()
				.jwt();
		// @formatter:on
	}
}
--------------------------------------------------------------------------------------------------------
/**
	 * Reads text from a file
	 * @param file the file to read from
	 * @return the text within the {@link File}
	 */
	static String readTextFrom(File file) {
		assertValidFile(file);
		try {
			return new String(Files.readAllBytes(file.toPath()));
		} catch (IOException e) {
			throw new IllegalArgumentException("Could not read " + file, e);
		}
	}

	/**
	 * Writes text to a file overriding any existing text
	 * @param text the text to write to the {@link File}
	 * @param file the {@link File} to write to
	 */
	static void writeTextTo(String text, File file) {
		if (text == null) {
			throw new IllegalArgumentException("text cannot be null");
		}
		assertValidFile(file);
		try (Writer writer = new OutputStreamWriter(new FileOutputStream(file))) {
			writer.write(text);
		} catch (IOException e) {
			throw new IllegalArgumentException("Could not write to " + file, e);
		}
	}

	private static void assertValidFile(File file) {
		if (file == null) {
			throw new IllegalArgumentException("file cannot be null");
		}
	}
--------------------------------------------------------------------------------------------------------
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: ${mockwebserver.url}/.well-known/jwks.json
--------------------------------------------------------------------------------------------------------

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
class AsgardBpmClientApplicationIT {

    @Autowired
    ApplicationContext ctx;

    @Test
    public void testRun() {
        CommandLineRunner runner = ctx.getBean(CommandLineRunner.class);
        runner.run ( "-k", "arg1", "-i", "arg2");
    }

}
--------------------------------------------------------------------------------------------------------

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import com.sample.myApp.model.MyBean;

@SpringBootApplication
public class Application {

 public static void main(String args[]) {

  ConfigurableApplicationContext configurableApplicationContext = SpringApplication.run(Application.class, args);

  MyBean myBean = configurableApplicationContext.getBean(MyBean.class);
  
  configurableApplicationContext.close();
 }
}
--------------------------------------------------------------------------------------------------------
java -jar swagger-codegen-cli-2.2.1.jar generate -i spec.yaml -l python
--------------------------------------------------------------------------------------------------------
<plugin>
    <groupId>io.swagger</groupId>
    <artifactId>swagger-codegen-maven-plugin</artifactId>
    <version>${swagger-codegen-maven-plugin-version}</version>
    <executions>
        <execution>
            <goals>
                <goal>generate</goal>
            </goals>
            <configuration>
                <inputSpec>${project.basedir}/src/main/resources/yaml/yamlfilename.yaml</inputSpec>
                <!-- language file, like e.g. JavaJaxRSCodegen shipped with swagger -->
                <language>com.my.package.for.GeneratorLanguage</language>
                <templateDirectory>myTemplateDir</templateDirectory>

                <output>${project.build.directory}/generated-sources</output>
                <apiPackage>${default.package}.handler</apiPackage>
                <modelPackage>${default.package}.model</modelPackage>
                <invokerPackage>${default.package}.handler</invokerPackage>
            </configuration>
        </execution>
    </executions>

    <dependencies>
        <dependency>
            <groupId>com.my.generator</groupId>
            <artifactId>customgenerator</artifactId>
            <version>1.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
</plugin>
--------------------------------------------------------------------------------------------------------
2019-10-17T15:34:31.038324Z
2019-10-21T05:07:41.644+03:00
--------------------------------------------------------------------------------------------------------
curl -X POST -H "content-type:application/json" \
-d '{"swaggerUrl":"http://petstore.swagger.io/v2/swagger.json"}' \
http://generator.swagger.io/api/gen/clients/java
--------------------------------------------------------------------------------------------------------
import java.util.concurrent.atomic.*;

/**
 * Created by shiqifeng on 2017/5/5.
 * Mail byhieg@gmail.com
 */
public class AtomFactory {

    private static final AtomFactory atomFactory = new AtomFactory();

    private AtomFactory(){

    }

    public static AtomFactory getInstance(){
        return atomFactory;
    }

    public AtomicInteger createAtomInt(int a){
        return new AtomicInteger(a);
    }

    public AtomicIntegerArray createAtomArray(int[] a) {
        return new AtomicIntegerArray(a);
    }

    public AtomicReference<MyObject> createAtomReference(MyObject object){
        return new AtomicReference<>();
    }

    public AtomicIntegerFieldUpdater<MyObject> createAtomIntegerUpdate(String fieldName) {
        return  AtomicIntegerFieldUpdater.newUpdater(MyObject.class, fieldName);
    }
}
--------------------------------------------------------------------------------------------------------
import java.util.concurrent.BlockingQueue;

/**
 * Created by byhieg on 17/5/3.
 * Mail to byhieg@gmail.com
 */
public class Producer extends Thread {

    private BlockingQueue<String> blockingQueue;
    @Override
    public void run() {
        super.run();
        for (int i = 0 ; i < 5;i++) {
            try {
                blockingQueue.put(i + "");
                System.out.println(getName() + " 生产数据");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public Producer(ArrayBlock arrayBlock){
        this.setName("Producer");
        blockingQueue = arrayBlock.getBlockingQueue();
    }
}
import java.util.concurrent.BlockingQueue;

/**
 * Created by byhieg on 17/5/3.
 * Mail to byhieg@gmail.com
 */
public class Costumer extends Thread{

    private BlockingQueue<String> blockingQueue;

    public Costumer(ArrayBlock arrayBlock) {
        blockingQueue = arrayBlock.getBlockingQueue();
        this.setName("Costumer");
    }

    @Override
    public void run() {
        super.run();
        while (true) {
            try {
                Thread.sleep(5000);
                String str = blockingQueue.take();
                System.out.println(getName() + " 取出数据 " + str);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
--------------------------------------------------------------------------------------------------------
/**
 * Current version of the project. Generated from a template at build time.
 * @author Georgy Vlasov (wlasowegor@gmail.com)
 * @version $Id$
 * @since 0.23
 */
public enum Version {
    /**
     * Current version.
     */
    CURRENT("${project.version}", "${buildNumber}");

    /**
     * Project version.
     */
    private final String version;

    /**
     * Build number.
     */
    private final String build;

    /**
     * Public ctor.
     * @param ver Maven's project.version property
     * @param buildnum Maven's buildNumber property created with
     *  buildnumber-maven-plugin
     */
    Version(final String ver, final String buildnum) {
        this.version = ver;
        this.build = buildnum;
    }

    /**
     * Returns project version number.
     * @return Project version number
     */
    public String projectVersion() {
        return this.version;
    }

    /**
     * Returns project build number.
     * @return Build number
     */
    public String buildNumber() {
        return this.build;
    }
}s
--------------------------------------------------------------------------------------------------------
RequestSpecification requestSpec = new RequestSpecBuilder()
    .setBaseUri("http://localhost")
    .setPort(8080)
    .setAccept(ContentType.JSON)
    .setContentType(ContentType.ANY)
...
    .log(LogDetail.ALL)
    .build();

// можно задать одну спецификацию для всех запросов:
RestAssured.requestSpecification = requestSpec;

// или для отдельного:
given().spec(requestSpec)...when().get(someEndpoint);

ResponseSpecification responseSpec = new ResponseSpecBuilder()
    .expectStatusCode(200)
    .expectBody(containsString("success"))
    .build();

// можно задать одну спецификацию для всех ответов:
RestAssured.responseSpecification = responseSpec;

// или для отдельного:
given()...when().get(someEndpoint).then().spec(responseSpec)...;

// то же самое работает и в обратную сторону:
SomePojo pojo = given().
    .when().get(EndPoints.get)
    .then().extract().body().as(SomePojo.class);
--------------------------------------------------------------------------------------------------------
-Xjsr305={strict|warn|ignore}
--------------------------------------------------------------------------------------------------------
@TestExecutionListeners(MockitoTestExecutionListener.class)
private Duration loginTimeout = Duration.ofSeconds(3);

assertThat(json.write(message))
    .extractingJsonPathNumberValue("@.test.numberValue")
    .satisfies((number) -> assertThat(number.floatValue()).isCloseTo(0.15f, within(0.01f)));
--------------------------------------------------------------------------------------------------------
@ExtendWith(OutputCaptureExtension.class)
class OutputCaptureTests {

    @Test
    void testName(CapturedOutput output) {
        System.out.println("Hello World!");
        assertThat(output).contains("World");
    }

}


spring.webservices.wsdl-locations=classpath:/wsdl



@Bean
public WebServiceTemplate webServiceTemplate(WebServiceTemplateBuilder builder) {
    return builder.messageSenders(new HttpWebServiceMessageSenderBuilder()
            .setConnectTimeout(5000).setReadTimeout(2000).build()).build();
}
--------------------------------------------------------------------------------------------------------
@Configuration(proxyBeanMethods = false)
@EnableKafkaStreams
public static class KafkaStreamsExampleConfiguration {

    @Bean
    public KStream<Integer, String> kStream(StreamsBuilder streamsBuilder) {
        KStream<Integer, String> stream = streamsBuilder.stream("ks1In");
        stream.map((k, v) -> new KeyValue<>(k, v.toUpperCase())).to("ks1Out",
                Produced.with(Serdes.Integer(), new JsonSerde<>()));
        return stream;
    }

}


spring.kafka.consumer.value-deserializer=org.springframework.kafka.support.serializer.JsonDeserializer
spring.kafka.consumer.properties.spring.json.value.default.type=com.example.Invoice
spring.kafka.consumer.properties.spring.json.trusted.packages=com.example,org.acme




spring.kafka.producer.value-serializer=org.springframework.kafka.support.serializer.JsonSerializer
spring.kafka.producer.properties.spring.json.add.type.headers=false

spring.jta.log-dir
spring.jta.atomikos.properties


spring.session.jdbc.table-name=SESSIONS




<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
    <exclusions>
        <exclusion>
            <groupId>org.junit.vintage</groupId>
            <artifactId>junit-vintage-engine</artifactId>
        </exclusion>
    </exclusions>
</dependency>


--------------------------------------------------------------------------------------------------------
@Test
public void whenMeasureResponseTime_thenOK() {
    Response response = RestAssured.get("/users/eugenp");
    long timeInMS = response.time();
    long timeInS = response.timeIn(TimeUnit.SECONDS);
     
    assertEquals(timeInS, timeInMS/1000);
}
@Test
public void whenLogResponseIfErrorOccurred_thenSuccess() {
  
    when().get("/users/eugenp")
      .then().log().ifError();
    when().get("/users/eugenp")
      .then().log().ifStatusCodeIsEqualTo(500);
    when().get("/users/eugenp")
      .then().log().ifStatusCodeMatches(greaterThan(200));
}
--------------------------------------------------------------------------------------------------------
@Test
public void whenLogResponseIfErrorOccurred_thenSuccess() {
  
    when().get("/users/eugenp")
      .then().log().ifError();
    when().get("/users/eugenp")
      .then().log().ifStatusCodeIsEqualTo(500);
    when().get("/users/eugenp")
      .then().log().ifStatusCodeMatches(greaterThan(200));
}
--------------------------------------------------------------------------------------------------------

// методы find, findAll применяются к коллекции для поиска первого и всех вхождений, метод collect для  создания новой коллекции из найденных результатов. 

// переменная it создается неявно и указывает на текущий элемент коллекции
Map<String, ?> map = get(EndPoints.anyendpoint).path("rootelement.find { it.title =~ 'anythingRegExp'}");

// можете явно задать название переменной, указывающей на текущий элемент
Map<String, ?> map = get(EndPoints.anyendpoint).path("rootelement.findAll { element -> element.title.length() > 4 }");

// вы можете использовать методы sum, max, min для суммирования всех значений коллекции, а также поиска максимального и минимально значения

String expensiveCar = get(EndPoints.cars).path("cars.find { it.title == 'Toyota Motor Corporation'}.models.max { it.averagePrice }.title");

--------------------------------------------------------------------------------------------------------
language: java
sudo: false
cache:
  directories:
    - $HOME/.m2
script:
  - set -e
  - mvn clean install -Pqulice --errors --batch-mode
  - mvn clean
  - pdd --source=$(pwd) --file=/dev/null
  - est --dir=est --file=/dev/null
before_install:
  - rvm install 2.6.0
  - rvm use 2.6.0
install:
  - gem install pdd -v 0.20.5
  - gem install est -v 0.3.4
env:
  global:
    - MAVEN_OPTS="-Xmx256m"
    - JAVA_OPTS="-Xmx256m"
jdk:
  - oraclejdk8
  - openjdk7
--------------------------------------------------------------------------------------------------------
    public String getRightestOne(int n){
        int res = n & (~n + 1);
        return Integer.toBinaryString(res);
    }
--------------------------------------------------------------------------------------------------------
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * Created by shiqifeng on 2017/2/23.
 * Mail byhieg@gmail.com
 */
public class BufferedReaderExample {

    public void readFromFile() throws Exception{
        try(BufferedReader reader = new BufferedReader(new FileReader("D:" + File.separator + "read_file.txt"))){
            String str;
            while ((str = reader.readLine()) != null) {
                System.out.println(str);
            }
        }
    }
}
--------------------------------------------------------------------------------------------------------
<plugin>
    <groupId>io.swagger</groupId>
    <artifactId>swagger-codegen-maven-plugin</artifactId>
    <version>2.3.1</version>
    <executions>
        <execution>
            <id>contract-service</id>
            <goals>
                <goal>generate</goal>
            </goals>
            <configuration>
                <inputSpec>${basedir}/src/main/resources/swagger/rest-data-exchange-format.yaml</inputSpec>
                <artifactId>contract-service</artifactId>
                <output>${basedir}/target/generated-sources</output>
                <language>spring</language>
                <modelPackage>ru.payhub.rest.v1.model</modelPackage>
                <apiPackage>ru.payhub.rest.v1.api</apiPackage>
                <!-- <invokerPackage>ru.payhub.rest.v1.handler</invokerPackage> -->
                <generateSupportingFiles>false</generateSupportingFiles>
                <configOptions>
                    <sourceFolder>src/main/java</sourceFolder>
                    <interfaceOnly>true</interfaceOnly>
                    <library>spring-boot</library>
                    <dateLibrary>${generator.datelibrary}</dateLibrary>
                    <configPackage>ru.payhub.config</configPackage>
                    <singleContentTypes>true</singleContentTypes>
                </configOptions>
            </configuration>
        </execution>
    </executions>
</plugin>
--------------------------------------------------------------------------------------------------------
del /f /q /a "C:\git-project\paragon.microservices.distributor\.build\bin"
--------------------------------------------------------------------------------------------------------
List<Enum> enumValues = Arrays.asList(Enum.values());
or

List<Enum> enumValues = new ArrayList<Enum>(EnumSet.allOf(Enum.class));
Using Java 8 features, you can map each constant to its name:

List<String> enumNames = Stream.of(Enum.values())
                               .map(Enum::name)
                               .collect(Collectors.toList());
--------------------------------------------------------------------------------------------------------
enum Primitive<X> {
    INT<Integer>(Integer.class, 0) {
        int mod(int x, int y) { return x % y; }
        int add(int x, int y) { return x + y; }
    },
    FLOAT<Float>(Float.class, 0f)  {
        long add(long x, long y) { return x + y; }
    }, ... ;

    final Class<X> boxClass;
    final X defaultValue;

    Primitive(Class<X> boxClass, X defaultValue) {
        this.boxClass = boxClass;
        this.defaultValue = defaultValue;
    }
}

// class name is awful for this example, but it will make more sense if you
//  read further
public interface MetaDataKey<T extends Serializable> extends Serializable
{
    T getValue();
}

public final class TypeSafeKeys
{
    static enum StringKeys implements MetaDataKey<String>
    {
        A1("key1");

        private final String value;

        StringKeys(String value) { this.value = value; }

        @Override
        public String getValue() { return value; }
    }

    static enum IntegerKeys implements MetaDataKey<Integer>
    {
        A2(0);

        private final Integer value;

        IntegerKeys (Integer value) { this.value = value; }

        @Override
        public Integer getValue() { return value; }
    }

    public static final MetaDataKey<String> A1 = StringKeys.A1;
    public static final MetaDataKey<Integer> A2 = IntegerKeys.A2;
}
--------------------------------------------------------------------------------------------------------
private static WireMockServer wireMockServer
  = new WireMockServer();
 
@BeforeClass
public static void setUp() throws Exception {
    wireMockServer.start();
    configureFor("localhost", 8080);
    stubFor(
      get(urlEqualTo("/user/get"))
        .willReturn(aResponse()
          .withStatus(200)
          .withHeader("Content-Type", "application/json")
          .withBody("{ \"id\": \"1234\", name: \"John Smith\" }")));
 
    stubFor(
      post(urlEqualTo("/user/create"))
        .withHeader("content-type", equalTo("application/json"))
        .withRequestBody(containing("id"))
        .willReturn(aResponse()
          .withStatus(200)
          .withHeader("Content-Type", "application/json")
          .withBody("{ \"id\": \"1234\", name: \"John Smith\" }")));
 
}
 
@AfterClass
public static void tearDown() throws Exception {
    wireMockServer.stop();
}
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------