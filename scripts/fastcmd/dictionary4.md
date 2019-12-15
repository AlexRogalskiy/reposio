==============================================================================================================
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.jbehave.core.annotations.Alias;
import org.jbehave.core.annotations.Composite;
import org.jbehave.core.annotations.Given;
import org.jbehave.core.annotations.Named;
import org.jbehave.core.annotations.Then;
import org.jbehave.core.annotations.When;
import org.jbehave.core.model.ExamplesTable;
import org.jbehave.core.steps.Parameters;

public class ExampleSteps {
	private int x;
	private Map<String, Integer> variables;
	private int result;

	@Given("a variable x with value $value")
	@Alias("ist die Variable x mit dem Wert $value")
	public void givenXValue(@Named("value") int value) {
		x = value;
	}

	@When("I multiply x by $value")
	@Alias("ich x mit $value multipliziere")
	public void whenImultiplyXBy(@Named("value") int value) {
		x = x * value;
	}

	@When("I multiply x with all of:$param")
	@Alias("ich x mit folgenden Werten multipliziere:$param")
	public void whenImultiplyXByOneOf(ExamplesTable param) {
		for (Parameters p : param.getRowsAsParameters()) {
			Integer value = p.valueAs("Value", Integer.class);
			x = x * value;
		}
	}

	@Then("x should equal $value")
	@Alias("ist x gleich $value")
	public void thenXshouldBe(@Named("value") int value) {
		assertEquals(value, x);
	}

	@Given("some initialization")
	public void givenSomeInitialization() {
		System.out.println("Init");
	}

	@Given("a Greeting to $somebody")
	public void givenAGreetingToSomebody(@Named("somebody") String somebody) {
		System.out.println("Hello " + somebody);
	}

	@Given("the variables: $variables")
	public void givenTheVariables(ExamplesTable table) {
		variables = new HashMap<>();
		for (Map<String, String> row : table.getRows()) {
			variables.put(row.get("name"), Integer.valueOf(row.get("value")));
		}
	}

	@When("all variables are multiplied")
	public void allVariablesAreMultipled() {
		result = 1;
		for (Integer variable : variables.values()) {
			result *= variable;
		}
	}

	@Then("the result should be $result")
	public void theResultShouldBe(@Named("result") String result) {
		assertEquals(result, "" + this.result);
	}

	@Given("a complex situation")
	@Composite(steps = { "Given a variable x with value 1",
			"When I multiply x by 5" })
	public void aComplexSituation() {
		// This is complex case with single method representing Composite step and Given step at the same time
	}

	@When("this step fails")
	public void thisStepFails() {
		fail("this step failed on purpose");
	}

	@Then("this step is not executed")
	public void thisStepIsNotExecuted() {
		// This step is to help document a scenario where a prior step is expected to fail and this step will not execute.
	}
}

import java.sql.SQLException;

import org.jbehave.core.annotations.AfterScenario;
import org.jbehave.core.annotations.AfterScenario.Outcome;
import org.jbehave.core.annotations.AfterStories;
import org.jbehave.core.annotations.AfterStory;
import org.jbehave.core.annotations.BeforeScenario;
import org.jbehave.core.annotations.BeforeStories;
import org.jbehave.core.annotations.BeforeStory;
import org.jbehave.core.annotations.ScenarioType;

public class InitSteps {
	@BeforeStories
	public void doSomethingBeforeStories() throws SQLException {
		System.out.println("InitSteps.doSomethingBeforeStories()");
		throw new SQLException("DU doof!");
	}

	@BeforeStory(uponGivenStory = true)
	public void doSomethingBeforeGivenStories() {
		System.out.println("InitSteps.doSomethingBeforeGivenStories()");
	}

	@BeforeStory(uponGivenStory = false)
	public void doSomethingBeforeRegularStories() {
		System.out.println("InitSteps.doSomethingBeforeRegularStories()");
	}

	@BeforeScenario(uponType = ScenarioType.NORMAL)
	public void doSomethingBeforeNormalScenario() {
		System.out.println("InitSteps.doSomethingBeforeNormalScenario()");
	}

	@BeforeScenario(uponType = ScenarioType.EXAMPLE)
	public void doSomethingBeforeExample() {
		System.out.println("InitSteps.doSomethingAfterAnyNormalScenario()");
	}

	@AfterScenario(uponType = ScenarioType.EXAMPLE, uponOutcome = Outcome.ANY)
	public void doSomethingAfterAnyExampleScenario() {
		System.out.println("InitSteps.doSomethingAfterAnyExampleScenario()");
	}

	@AfterScenario(uponType = ScenarioType.EXAMPLE, uponOutcome = Outcome.FAILURE)
	public void doSomethingAfterFailedExampleScenario() {
		System.out.println("InitSteps.doSomethingAfterFailedExampleScenario()");
	}

	@AfterScenario(uponType = ScenarioType.EXAMPLE, uponOutcome = Outcome.SUCCESS)
	public void doSomethingAfterSuccessfulExampleScenario() {
		System.out
				.println("InitSteps.doSomethingAfterSuccessfulExampleScenario()");
	}

	@AfterScenario(uponType = ScenarioType.NORMAL, uponOutcome = Outcome.ANY)
	public void doSomethingAfterAnyNormalScenario() {
		System.out.println("InitSteps.doSomethingAfterAnyNormalScenario()");
	}

	@AfterScenario(uponType = ScenarioType.NORMAL, uponOutcome = Outcome.FAILURE)
	public void doSomethingAfterFailedNormalScenario() {
		System.out.println("InitSteps.doSomethingAfterFailedNormalScenario()");
	}

	@AfterScenario(uponType = ScenarioType.NORMAL, uponOutcome = Outcome.SUCCESS)
	public void doSomethingAfterSuccessfulNormalScenario() {
		System.out
				.println("InitSteps.doSomethingAfterSuccessfulNormalScenario()");
	}

	@AfterStory(uponGivenStory = false)
	public void doSomethingAfterRegularStories() {
		System.out.println("InitSteps.doSomethingAfterRegularStories()");
	}

	@AfterStory(uponGivenStory = true)
	public void doSomethingAfterGivenStories() {
		System.out.println("InitSteps.doSomethingAfterGivenStories()");
	}

	@AfterStories
	public void doSomethingAfterStories() {
		System.out.println("InitSteps.doSomethingAfterStories()");
	}
}
==============================================================================================================
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-war-plugin</artifactId>
    <version>2.4</version>
    <configuration>
        <attachClasses>true</attachClasses>
    </configuration>
</plugin>

Feature: calculation

Narrative:
As a user
I want to perform an action
So that I can achieve a business goal

Scenario: 2 squared
Given a variable x with value 2
When I multiply x by 2
Then result should equal 4

Scenario: 3 squared
Given a variable x with value 3
When I multiply x by 3
Then result should equal 9

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

/**
 * Our application has a lot of moving parts so it made sense to wrap some of the operations in an integration test
 * session.
 * Created by andrew on 11/18/15.
 */
@Service
@Scope(value = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class IntegrationTestSession {

    @Autowired
    private ApplicationService applicationService;

    private int x;

    public void setX(int x) {
        this.x = x;
    }

    public int multiply(int y) {
        return applicationService.multiply(x, y);
    }
}

@Component
public class TestSteps {

    @Autowired
    private ApplicationContext applicationContext;

    private IntegrationTestSession testSession;
    private int result;

    @Given("a variable x with value $value")
    public void givenXValue(@Named("value") int value) {
        testSession = applicationContext.getBean(IntegrationTestSession.class);
        testSession.setX(value);
    }

    @When("I multiply x by $value")
    public void whenImultiplyXBy(@Named("value") int value) {
        result = testSession.multiply(value);
    }

    @Then("result should equal $value")
    public void thenXshouldBe(@Named("value") int value) {
        if (value != result)
            throw new RuntimeException("result is " + result + ", but should be " + value);
    }
}

        <dependency>
            <groupId>org.jbehave</groupId>
            <artifactId>jbehave-core</artifactId>
            <version>${jbehave.version}</version>
        </dependency>

        <dependency>
            <groupId>org.jbehave</groupId>
            <artifactId>jbehave-spring</artifactId>
            <version>${jbehave.version}</version>
        </dependency>

        <dependency>
            <groupId>org.jbehave.site</groupId>
            <artifactId>jbehave-site-resources</artifactId>
            <version>3.1.1</version>
            <type>zip</type>
        </dependency>

        <dependency>
            <groupId>org.jbehave</groupId>
            <artifactId>jbehave-core</artifactId>
            <version>${jbehave.version}</version>
            <classifier>resources</classifier>
            <type>zip</type>
        </dependency>
		
		<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>2.17</version>
    <configuration>
        <testSourceDirectory>${basedir}/src/main/java/</testSourceDirectory>
        <testClassesDirectory>${project.build.directory}/classes/</testClassesDirectory>
        <includes>
            <include>example/jbehave/tests/stories/**/*.java</include>
        </includes>
    </configuration>
</plugin>
==============================================================================================================
import example.jbehave.app.domain.Money;
import org.jbehave.core.annotations.AsParameterConverter;
import org.jbehave.core.steps.ParameterConverters;
import org.springframework.util.StringUtils;

@Converter
public class MoneyConverter {

    @AsParameterConverter
    public Money convertPercent(String value) {
        if (StringUtils.isEmpty(value)) {
            return null;
        }

        String[] tokens = value.split("\\s");
        if (tokens.length != 2) {
            throw new ParameterConverters.ParameterConvertionFailed("Expected 2 tokens (amount and currency) but got " + tokens.length + ", value: " + value + ".");
        }

        return new Money(tokens[0], tokens[1]);
    }
}

==============================================================================================================
TASKKILL /IM notepad.exe
    TASKKILL /PID 1230 /PID 1241 /PID 1253 /T
    TASKKILL /F /IM cmd.exe /T
    TASKKILL /F /FI "PID ge 1000" /FI "WINDOWTITLE ne untitle*"
    TASKKILL /F /FI "USERNAME eq NT AUTHORITY\SYSTEM" /IM notepad.exe
    TASKKILL /S system /U domain\username /FI "USERNAME ne NT*" /IM *
    TASKKILL /S system /U username /P password /FI "IMAGENAME eq note*"
==============================================================================================================
import lankydan.tutorial.documents.OrderTransaction;
import lankydan.tutorial.repositories.OrderTransactionRepository;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

@Component
public class OrderTransactionReceiver {

    private final OrderTransactionRepository transactionRepository;

    private int count = 1;

    public OrderTransactionReceiver(OrderTransactionRepository transactionRepository) {
        this.transactionRepository = transactionRepository;
    }

    @JmsListener(destination = "OrderTransactionQueue", containerFactory = "myFactory")
    public void receiveMessage(OrderTransaction transaction) {
        System.out.println("<" + count + "> Received <" + transaction + ">");
        count++;
        transactionRepository.save(transaction);
    }
}

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jms.DefaultJmsListenerContainerFactoryConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.jms.annotation.EnableJms;
import org.springframework.jms.config.DefaultJmsListenerContainerFactory;
import org.springframework.jms.config.JmsListenerContainerFactory;
import org.springframework.jms.support.converter.MappingJackson2MessageConverter;
import org.springframework.jms.support.converter.MessageConverter;
import org.springframework.jms.support.converter.MessageType;

import javax.jms.ConnectionFactory;

@EnableJms
@ComponentScan(basePackages = "lankydan.tutorial")
@EnableMongoRepositories(basePackages = "lankydan.tutorial")
@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  // Only required due to defining myFactory in the receiver
  @Bean
  public JmsListenerContainerFactory<?> myFactory(
      ConnectionFactory connectionFactory,
      DefaultJmsListenerContainerFactoryConfigurer configurer) {
    DefaultJmsListenerContainerFactory factory = new DefaultJmsListenerContainerFactory();
    factory.setErrorHandler(t -> System.out.println("An error has occurred in the transaction"));
    configurer.configure(factory, connectionFactory);
    return factory;
  }

  // Serialize message content to json using TextMessage
  @Bean
  public MessageConverter jacksonJmsMessageConverter() {
    MappingJackson2MessageConverter converter = new MappingJackson2MessageConverter();
    converter.setTargetType(MessageType.TEXT);
    converter.setTypeIdPropertyName("_type");
    return converter;
  }
}






import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import com.datastax.driver.core.schemabuilder.SchemaBuilder;
import com.datastax.driver.mapping.*;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.datastax.driver.core.schemabuilder.SchemaBuilder.createKeyspace;
import static com.datastax.driver.mapping.NamingConventions.*;
import static org.apache.commons.lang3.StringUtils.*;

@Configuration
public class CassandraConfig {

  @Bean
  public Cluster cluster(
      @Value("${cassandra.host:127.0.0.1}") String host,
      @Value("${cassandra.cluster.name:cluster}") String clusterName,
      @Value("${cassandra.port:9042}") int port) {
    return Cluster.builder()
        .addContactPoint(host)
        .withPort(port)
        .withClusterName(clusterName)
        .build();
  }

  @Bean
  public Session session(Cluster cluster, @Value("${cassandra.keyspace}") String keyspace)
      throws IOException {
    //    final Session session = cluster.connect(keyspace);
    final Session session = cluster.connect();
    setupKeyspace(session, keyspace);
    return session;
  }

  private void setupKeyspace(Session session, String keyspace) throws IOException {
    final Map<String, Object> replication = new HashMap<>();
    replication.put("class", "SimpleStrategy");
    replication.put("replication_factor", 1);
    session.execute(createKeyspace(keyspace).ifNotExists().with().replication(replication));
    session.execute("USE " + keyspace);
    //    String[] statements =
    // split(IOUtils.toString(getClass().getResourceAsStream("/cql/setup.cql")), ";");
    //    Arrays.stream(statements).map(statement -> normalizeSpace(statement) +
    // ";").forEach(session::execute);
  }

  @Bean
  public MappingManager mappingManager(Session session) {
    final PropertyMapper propertyMapper =
        new DefaultPropertyMapper()
            .setNamingStrategy(new DefaultNamingStrategy(LOWER_CAMEL_CASE, LOWER_SNAKE_CASE));
    final MappingConfiguration configuration =
        MappingConfiguration.builder().withPropertyMapper(propertyMapper).build();
    return new MappingManager(session, configuration);
  }
}


import com.lankydanblog.tutorial.person.Person;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;

public class Client {

  private WebClient client = WebClient.create("http://localhost:8080");

  public void doStuff() {

    // POST
    final Person record = new Person(UUID.randomUUID(), "John", "Doe", "UK", 50);
    final Mono<ClientResponse> postResponse =
        client
            .post()
            .uri("/people")
            .body(Mono.just(record), Person.class)
            .accept(APPLICATION_JSON)
            .exchange();
    postResponse
        .map(ClientResponse::statusCode)
        .subscribe(status -> System.out.println("POST: " + status.getReasonPhrase()));

    // GET
    client
        .get()
        .uri("/people/{id}", "a4f66fe5-7c1b-4bcf-89b4-93d8fcbc52a4")
        .accept(APPLICATION_JSON)
        .exchange()
        .flatMap(response -> response.bodyToMono(Person.class))
        .subscribe(person -> System.out.println("GET: " + person));

    // ALL
    client
        .get()
        .uri("/people")
        .accept(APPLICATION_JSON)
        .exchange()
        .flatMapMany(response -> response.bodyToFlux(Person.class))
        .subscribe(person -> System.out.println("ALL: " + person));

    // PUT
    final Person updated = new Person(UUID.randomUUID(), "Peter", "Parker", "US", 18);
    client
        .put()
        .uri("/people/{id}", "ec2212fc-669e-42ff-9c51-69782679c9fc")
        .body(Mono.just(updated), Person.class)
        .accept(APPLICATION_JSON)
        .exchange()
        .map(ClientResponse::statusCode)
        .subscribe(response -> System.out.println("PUT: " + response.getReasonPhrase()));

    // DELETE
    client
        .delete()
        .uri("/people/{id}", "ec2212fc-669e-42ff-9c51-69782679c9fc")
        .exchange()
        .map(ClientResponse::statusCode)
        .subscribe(status -> System.out.println("DELETE: " + status));
  }
}




import com.lankydan.event.Event;
import com.lankydan.event.EventKey;
import org.springframework.data.cassandra.repository.CassandraRepository;
import org.springframework.data.cassandra.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface EventRepository extends CassandraRepository<Event, EventKey> {

  @Query("select avg(value) from event where type = ?0 and start_time > ?1")
  long getAverageValueGreaterThanStartTime(final String type, final LocalDateTime startTime);
}

import com.lankydan.event.Event;
import com.lankydan.event.EventKey;
import com.lankydan.event.repository.EventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Component
public class EventCreator {

  private static final Logger LOG = LoggerFactory.getLogger(EventCreator.class);

  private final EventRepository eventRepository;

  public EventCreator(final EventRepository eventRepository) {
    this.eventRepository = eventRepository;
  }

  @Scheduled(fixedRate = 1000)
  public void create() {
    final LocalDateTime start = LocalDateTime.now();
    eventRepository.save(
        new Event(new EventKey("An event type", start, UUID.randomUUID()), Math.random() * 1000));
    LOG.debug("Event created!");
  }
}
==============================================================================================================
import com.tngtech.keycloakmock.api.KeycloakVerificationMock;
import com.tngtech.keycloakmock.api.TokenConfig;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A JUnit5 extension to be used to automatically start and stop the keycloak mock.
 *
 * <p>Example use:
 *
 * <pre><code>
 * {@literal @}RegisterExtension
 *  static KeycloakMock mock = new KeycloakMock();
 *
 * {@literal @}Test
 *  void testStuff() {
 *    String token = mock.getAccessToken(aTokenConfig().build());
 *  }
 * </code></pre>
 */
public class KeycloakMock implements BeforeAllCallback, AfterAllCallback {

  private final KeycloakVerificationMock mock;

  /**
   * Create a mock instance for a given realm.
   *
   * <p>The instance generates tokens for realm 'master'. If you want to use a different realm, use
   * {@link KeycloakMock#KeycloakMock(int, String)} instead.
   *
   * <p>The JWKS endpoint listens at port 8000. If you need a different port, use {@link
   * KeycloakMock#KeycloakMock(int, String)} instead.
   *
   * <p>The JWKS endpoint is served via HTTP. If you need HTTPS, use {@link
   * KeycloakMock#KeycloakMock(int, String, boolean)} instead.
   */
  public KeycloakMock() {
    this(8000, "master", false);
  }

  /**
   * Create a mock instance for a given realm.
   *
   * <p>The JWKS endpoint is served via HTTP. If you need HTTPS, use {@link
   * KeycloakMock#KeycloakMock(int, String, boolean)} instead.
   *
   * @param port the port of the mock to run (e.g. 8000)
   * @param realm the realm for which to provide tokens
   */
  public KeycloakMock(final int port, final String realm) {
    this(port, realm, false);
  }

  /**
   * Create a mock instance for a given realm.
   *
   * <p>Depending on the tls parameter, the JWKS endpoint is served via HTTP or HTTPS.
   *
   * @param port the port of the mock to run (e.g. 8000)
   * @param realm the realm for which to provide tokens
   * @param tls whether to use HTTPS instead of HTTP
   */
  public KeycloakMock(final int port, final String realm, final boolean tls) {
    this.mock = new KeycloakVerificationMock(port, realm, tls);
  }

  /**
   * Get a signed access token for the given parameters.
   *
   * @param tokenConfig the configuration of the token to generate
   * @return an access token in compact JWT form
   * @see TokenConfig.Builder
   */
  public String getAccessToken(final TokenConfig tokenConfig) {
    return mock.getAccessToken(tokenConfig);
  }

  @Override
  public void beforeAll(final ExtensionContext context) {
    mock.start();
  }

  @Override
  public void afterAll(final ExtensionContext context) {
    mock.stop();
  }
}
  @Bean
  public KeycloakSpringBootConfigResolver keycloakConfigResolver() {
    return new KeycloakSpringBootConfigResolver();
  }
  
  
  import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import javax.annotation.Nonnull;

/**
 * A mock of a keycloak instance capable of producing access tokens.
 *
 * <p>This can be used in component tests of REST endpoints that are secured via Keycloak. The mock
 * provides a JWKS endpoint so the signature of the access token can be verified.
 *
 * <p>Typically, you should not need to use this class directly. Consider using {@code
 * com.tngtech.keycloakmock.junit.KeycloakMock} from module mock-junit or {@code
 * com.tngtech.keycloakmock.junit5.KeycloakMock} from module mock-junit5 instead.
 */
public class KeycloakVerificationMock {
  private static final String HTTP = "http";
  private static final String HTTPS = "https";
  @Nonnull private final TokenGenerator tokenGenerator;
  private final int port;
  @Nonnull private final String realm;
  private final boolean tls;
  @Nonnull private final String issuerPrefix;
  protected final Vertx vertx = Vertx.vertx();
  private HttpServer server;

  /**
   * Create a mock instance for a given realm.
   *
   * <p>The JWKS endpoint is served via HTTP. If you need HTTPS, use {@link
   * KeycloakVerificationMock#KeycloakVerificationMock(int, String, boolean)} instead.
   *
   * @param port the port of the mock to run (e.g. 8000)
   * @param realm the realm for which to provide tokens
   */
  public KeycloakVerificationMock(final int port, @Nonnull final String realm) {
    this(port, realm, false);
  }

  /**
   * Create a mock instance for a given realm.
   *
   * <p>Depending on the tls parameter, the JWKS endpoint is served via HTTP or HTTPS.
   *
   * @param port the port of the mock to run (e.g. 8000)
   * @param realm the realm for which to provide tokens
   * @param tls whether to use HTTPS instead of HTTP
   */
  public KeycloakVerificationMock(final int port, @Nonnull final String realm, final boolean tls) {
    this.port = port;
    this.realm = Objects.requireNonNull(realm);
    this.tls = tls;
    this.issuerPrefix = tls ? HTTPS : HTTP + "://localhost:" + port + "/auth/realms/";
    try {
      this.tokenGenerator = new TokenGenerator();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Get a signed access token for the given parameters.
   *
   * @param tokenConfig the configuration of the token to generate
   * @return an access token in compact JWT form
   * @see TokenConfig.Builder
   */
  @Nonnull
  public String getAccessToken(@Nonnull final TokenConfig tokenConfig) {
    return tokenGenerator.getToken(tokenConfig, getIssuer(realm));
  }

  @Nonnull
  protected String getAccessTokenForRealm(
      @Nonnull final TokenConfig tokenConfig, @Nonnull final String realm) {
    return tokenGenerator.getToken(tokenConfig, getIssuer(realm));
  }

  /** Start the server (blocking). */
  public void start() {
    HttpServerOptions options = new HttpServerOptions().setPort(port);
    if (tls) {
      options
          .setSsl(true)
          .setKeyStoreOptions(new JksOptions().setValue(getKeystore()).setPassword(""));
    }
    Router router = configureRouter();
    ResultHandler<HttpServer> startHandler = new ResultHandler<>();
    server =
        vertx
            .createHttpServer(options)
            .requestHandler(router)
            .exceptionHandler(Throwable::printStackTrace)
            .listen(startHandler);
    startHandler.await();
  }

  protected Router configureRouter() {
    Router router = Router.router(vertx);
    router.get("/auth/realms/:realm/protocol/openid-connect/certs").handler(this::getJwksResponse);
    return router;
  }

  /** Stop the server (blocking). */
  public void stop() {
    ResultHandler<Void> stopHandler = new ResultHandler<>();
    server.close(stopHandler);
    stopHandler.await();
  }

  private Buffer getKeystore() {
    try {
      InputStream inputStream = this.getClass().getResourceAsStream("/keystore.jks");
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      byte[] buf = new byte[8192];
      int n;
      while ((n = inputStream.read(buf)) > 0) {
        outputStream.write(buf, 0, n);
      }
      return Buffer.buffer(outputStream.toByteArray());
    } catch (IOException e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }

  private void getJwksResponse(final RoutingContext routingContext) {
    routingContext
        .response()
        .putHeader("content-type", "application/json")
        .end(tokenGenerator.getJwksResponse());
  }

  @Nonnull
  private String getIssuer(@Nonnull final String realm) {
    return issuerPrefix + Objects.requireNonNull(realm);
  }

  private static class ResultHandler<E> implements Handler<AsyncResult<E>> {
    private final CompletableFuture<Void> future = new CompletableFuture<>();

    @Override
    public void handle(AsyncResult<E> result) {
      if (result.succeeded()) {
        future.complete(null);
      } else {
        future.completeExceptionally(result.cause());
      }
    }

    void await() {
      try {
        future.get();
      } catch (InterruptedException | ExecutionException e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      }
    }
  }
}

import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@KeycloakConfiguration
public class WebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    super.configure(http);
    http.csrf()
        .disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers(HttpMethod.OPTIONS, "/**")
        .permitAll()
        .antMatchers("/**")
        .authenticated();
  }

  @Override
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new NullAuthenticatedSessionStrategy();
  }

  @Autowired
  public void configureGlobal(final AuthenticationManagerBuilder auth) {
    auth.authenticationProvider(keycloakAuthenticationProvider());
  }
}


public enum ResolveStrategy {
    /**
     * Strategy which stops after the first resolver returns valid dataproviders (= non-empty list) or no further
     * resolvers are available.
     */
    UNTIL_FIRST_MATCH,

    /**
     * Loops over all resolvers and aggregates all resulting dataproviders.
     */
    AGGREGATE_ALL_MATCHES,
}



import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class Obfuscator {

    private static final String ENCRYPTION_ALGORITHM = "Blowfish";
    private static final String ENCRYPTION_ALGORITHM_MODIFIER = "/ECB/PKCS5Padding";
    private static final String ENCODING = "UTF-8";

    private final Base64.Encoder base64Encoder = Base64.getEncoder();
    private final Base64.Decoder base64Decoder = Base64.getDecoder();
    private final SecretKeySpec dataEncryptionSecretKeySpec;

    public Obfuscator(String password) {
        byte[] salt = {65, 110, 100, 114, 111, 105, 100, 75, 105, 116, 75, 97, 116, 13, 1, 20, 20, 9, 1, 19};
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey tmp = factory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, 100, 128));
            dataEncryptionSecretKeySpec = new SecretKeySpec(tmp.getEncoded(), ENCRYPTION_ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypt and base64-encode a String.
     *
     * @param toEncrypt - the String to encrypt.
     * @return the Blowfish-encrypted and base64-encoded String.
     */
    public String encrypt(String toEncrypt) {
        byte[] encryptedBytes = encryptInternal(dataEncryptionSecretKeySpec, toEncrypt);
        return new String(base64Encoder.encode(encryptedBytes));
    }

    /**
     * Internal Encryption method.
     *
     * @param key       - the SecretKeySpec used to encrypt
     * @param toEncrypt - the String to encrypt
     * @return the encrypted String (as byte[])
     */
    private byte[] encryptInternal(SecretKeySpec key, String toEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM + ENCRYPTION_ALGORITHM_MODIFIER);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(toEncrypt.getBytes(ENCODING));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Exception during decryptInternal: " + e, e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Exception during encryptInternal: " + e, e);
        }
    }

    /**
     * Decrypt an encrypted and base64-encoded String
     *
     * @param toDecrypt - the encrypted and base64-encoded String
     * @return the plaintext String
     */
    public String decrypt(String toDecrypt) {
        byte[] encryptedBytes = base64Decoder.decode(toDecrypt);
        return decryptInternal(dataEncryptionSecretKeySpec, encryptedBytes);
    }

    /**
     * Internal decryption method.
     *
     * @param key            - the SecretKeySpec used to decrypt
     * @param encryptedBytes - the byte[] to decrypt
     * @return the decrypted plaintext String.
     */
    private String decryptInternal(SecretKeySpec key, byte[] encryptedBytes) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM + ENCRYPTION_ALGORITHM_MODIFIER);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, ENCODING);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Exception during decryptInternal: " + e, e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Exception during encryptInternal: " + e, e);
        }
    }
}

import com.tngtech.demo.weather.resources.Paths;
import lombok.AllArgsConstructor;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.QueryParam;

@AllArgsConstructor
public class WeatherQueryParam {
    @QueryParam(Paths.LATITUDE)
    final Double latitude;

    @QueryParam(Paths.LONGITUDE)
    final Double longitude;

    @DefaultValue("250.0")
    @QueryParam(Paths.RADIUS)
    final Double radius;
}


import com.tngtech.demo.weather.domain.gis.Point;
import org.springframework.stereotype.Component;

@Component
public class GeoCalculations {
    private static final double EARTH_RADIUS = 6372.8;

    /**
     * Haversine distance between two points.
     *
     * @param point1
     * @param point2
     * @return the distance in KM
     */

    public double calculateDistance(Point point1, Point point2) {
        double deltaLat = Math.toRadians(point2.latitude() - point1.latitude());
        double deltaLon = Math.toRadians(point2.longitude() - point1.longitude());
        double a = Math.pow(Math.sin(deltaLat / 2), 2) + Math.pow(Math.sin(deltaLon / 2), 2)
                * Math.cos(point1.latitude()) * Math.cos(point2.latitude());
        double c = 2 * Math.asin(Math.sqrt(a));
        return EARTH_RADIUS * c;
    }
}


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tngtech.demo.weather.domain.gis.Point;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@EqualsAndHashCode
@ToString
@Builder
public class Station implements Point {

    public final String name;

    public final double latitude;

    public final double longitude;

    @JsonCreator
    public Station(
            @JsonProperty("name") String name,
            @JsonProperty("latitude") Double latitude,
            @JsonProperty("longitude") Double longitude) {
        this.name = name;
        this.latitude = latitude;
        this.longitude = longitude;
    }

    @Override
    public double latitude() {
        return latitude;
    }

    @Override
    public double longitude() {
        return longitude;
    }
}


/**
 * The various types of data points we can collect.
 */

public enum DataPointType {
    WIND,
    TEMPERATURE,
    HUMIDITY,
    PRESSURE,
    CLOUDCOVER,
    PRECIPITATION
}

https://github.com/TNG/rest-demo-jersey/blob/master/src/main/java/com/tngtech/demo/weather/domain/measurement/AtmosphericData.java

https://askvoprosy.com/tegi/java


import com.gearservice.config.filter.ReCaptchaAuthFilter;
import com.gearservice.config.properties.ReCaptchaProperties;
import com.gearservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * Class SecurityConfiguration is configuration
 * Config for Spring Security
 *
 * @version 1.1
 * @author Dmitry
 * @since 22.01.2016
 */

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(ReCaptchaProperties.class)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final DataSource dataSource;
    private final UserService userDetailsService;
    private final ReCaptchaProperties reCaptchaProperties;

    @Autowired
    public SecurityConfiguration(DataSource dataSource, UserService userDetailsService, ReCaptchaProperties reCaptchaProperties) {
        this.dataSource = dataSource;
        this.userDetailsService = userDetailsService;
        this.reCaptchaProperties = reCaptchaProperties;
    }

    /**
     * Method configureGlobal configures base params.
     * Add overrated userDetailsService, new BCrypt password encoder, new query for searching users
     * @param auth is AuthenticationManagerBuilder for config object
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()).and()
                .jdbcAuthentication().dataSource(dataSource)
                .usersByUsernameQuery(
                        "SELECT username, password, enabled, full_name FROM user WHERE username=?")
                .authoritiesByUsernameQuery(
                        "SELECT username, role FROM authority WHERE username=?");
    }

    /**
     * Method passwordEncoder creates new BCrypt password encoder
     * @return new BCrypt password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {return new BCryptPasswordEncoder();}

    /**
     * Method configure is main config class for http security
     * @param http is HttpSecurity for configuring http security
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic()
                    .authenticationEntryPoint(new RedirectAuthenticationEntryPoint())
                .and().rememberMe()
                    .userDetailsService(userDetailsService)
                    .key("steam")
                    .useSecureCookie(true)
                    .tokenValiditySeconds(25000)
                .and().authorizeRequests()
                    .antMatchers("/index.html", "/", "/login", "/javascript/**", "/fonts/**",
                            "/stylesheets/**", "/images/**", "/api/currency-rate", "/favicon.ico")
                    .permitAll()
                    .antMatchers(HttpMethod.GET, "/attention").hasAnyAuthority("ROLE_ADMIN", "ROLE_ENGINEER", "ROLE_BOSS")
                    .antMatchers(HttpMethod.GET, "/delay").hasAnyAuthority("ROLE_ADMIN", "ROLE_ENGINEER", "ROLE_BOSS")
                    .antMatchers(HttpMethod.POST, "/api/cheques/{\\d+}/diagnostics").hasAnyAuthority("ROLE_ADMIN", "ROLE_ENGINEER", "ROLE_BOSS")
                    .antMatchers(HttpMethod.DELETE, "/api/cheques/{\\d+}/diagnostics/{\\d+}").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.DELETE, "/api/cheques/{\\d+}/notes/{\\d+}").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.DELETE, "/api/cheques/{\\d+}").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.DELETE, "/api/photo/{\\d+}/{\\d+}").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.GET, "/api/currency-rate-list").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.POST, "/api/currency-rate").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.POST, "/api/user").hasAuthority("ROLE_ADMIN")
                    .antMatchers(HttpMethod.DELETE, "/api/user/{\\d+}").hasAuthority("ROLE_ADMIN")
                    .anyRequest().authenticated()
                .and().logout()
                    .logoutSuccessUrl("/")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                .and().csrf()
                    .csrfTokenRepository(csrfTokenRepository())
                .and()
                .addFilterAfter(csrfHeaderFilter(), SessionManagementFilter.class)
                .addFilterBefore(new ReCaptchaAuthFilter(reCaptchaProperties), BasicAuthenticationFilter.class)
                .headers().contentSecurityPolicy("default-src https: 'self'; " +
                    "object-src 'none'; " +
                    "script-src 'self' https://www.google.com https://www.gstatic.com; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data:; " +
                    "connect-src 'self' ws://127.0.0.1:35729")
                .and().addHeaderWriter(new StaticHeadersWriter("Referrer-Policy", "no-referrer-when-downgrade"));
    }

    /**
     * Method RedirectAuthenticationEntryPoint is entry point for correct handling error with unauthorized exception
     */
    private class RedirectAuthenticationEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
        }
    }

    /**
     * Method csrfHeaderFilter creates filter for correct csrf security
     * @return OncePerRequestFilter for correct csrf security
     */
    private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                if (csrf != null) {
                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                    String token = csrf.getToken();
                    if (cookie == null || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie("XSRF-TOKEN", token);
                        cookie.setPath("/");
                        cookie.setSecure(true);
                        response.addCookie(cookie);
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    /**
     * Method csrfTokenRepository creates repository for csrf security token
     * @return repository for csrf security token
     */
    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
}
==============================================================================================================
import org.springframework.boot.autoconfigure.cache.CacheType;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class InfinispanEmbeddedCacheManagerChecker implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String cacheType = context.getEnvironment().getProperty("spring.cache.type");

        return cacheType == null || CacheType.INFINISPAN.name().equalsIgnoreCase(cacheType);
    }
}
==============================================================================================================
	static String render(Map<Option, Object> valueMap) {

		if (valueMap.isEmpty()) {
			return "";
		}

		StringBuilder cql = new StringBuilder(valueMap.size() * 2 * 16);
		// else option value is a non-empty map

		// append { 'name' : 'value', ... }
		cql.append("{ ");
		boolean mapFirst = true;
		for (Map.Entry<Option, Object> entry : valueMap.entrySet()) {
			if (mapFirst) {
				mapFirst = false;
			} else {
				cql.append(", ");
			}

			Option option = entry.getKey();
			cql.append(singleQuote(option.getName())); // entries in map keys are always quoted
			cql.append(" : ");
			Object entryValue = entry.getValue();
			entryValue = entryValue == null ? "" : entryValue.toString();
			if (option.escapesValue()) {
				entryValue = escapeSingle(entryValue);
			}
			if (option.quotesValue()) {
				entryValue = singleQuote(entryValue);
			}
			cql.append(entryValue);
		}
		cql.append(" }");

		return cql.toString();
	}
	
	  @Bean
  public CassandraEntityInformation information(CassandraOperations cassandraTemplate) {
    CassandraPersistentEntity<Person> entity =
        (CassandraPersistentEntity<Person>)
            cassandraTemplate
                .getConverter()
                .getMappingContext()
                .getRequiredPersistentEntity(Person.class);
    return new MappingCassandraEntityInformation<>(entity, cassandraTemplate.getConverter());
  }
==============================================================================================================
	/**
	 * Where clause builder. Collects {@link Clause clauses} and builds the where-clause depending on the WHERE type.
	 *
	 * @author Mark Paluch
	 */
	static class QueryBuilder {

		private List<CriteriaDefinition> criterias = new ArrayList<>();

		CriteriaDefinition and(CriteriaDefinition clause) {
			criterias.add(clause);
			return clause;
		}

		Query create(Sort sort) {

			Query query = Query.query(criterias);

			return query.sort(sort);
		}
	}
	
	
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================