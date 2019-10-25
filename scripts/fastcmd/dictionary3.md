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
