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