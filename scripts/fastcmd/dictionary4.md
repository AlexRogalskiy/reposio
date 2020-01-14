==============================================================================================================
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import com.icegreen.greenmail.configuration.GreenMailConfiguration;
import com.icegreen.greenmail.util.GreenMailUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("GreenMail with configuration tests")
class WithConfigurationTests {
    @RegisterExtension
    GreenMailExtension greenMail = new GreenMailExtension()
        .withConfiguration(GreenMailConfiguration.aConfig()
            .withUser("to@localhost.com", "login-id", "password"));

    @Test
    @DisplayName("Receive test")
    void testReceive() throws MessagingException {
        GreenMailUtil.sendTextEmailTest("to@localhost.com", "from@localhost.com", "subject", "body");
        final MimeMessage[] emails = greenMail.getReceivedMessages();
        assertEquals(1, emails.length);
        final MimeMessage email = emails[0];
        assertEquals("subject", email.getSubject());
        assertEquals("body", GreenMailUtil.getBody(email));
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
@Bean
public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
    ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory();
    factory.setConsumerFactory(consumerFactory());
    factory.getContainerProperties().setAckOnError(false);
    factory.getContainerProperties().setAckMode(AckMode.RECORD);
    factory.setErrorHandler(new SeekToCurrentErrorHandler());
    return factory;
}

@Bean
public SeekToCurrentErrorHandler errorHandler(BiConsumer<ConsumerRecord<?, ?>, Exception> recoverer) {
    SeekToCurrentErrorHandler handler = new SeekToCurrentErrorHandler(recoverer);
    handler.addNotRetryableException(IllegalArgumentException.class);
    return handler;
}

DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(template,
        (r, e) -> {
            if (e instanceof FooException) {
                return new TopicPartition(r.topic() + ".Foo.failures", r.partition());
            }
            else {
                return new TopicPartition(r.topic() + ".other.failures", r.partition());
            }
        });
ErrorHandler errorHandler = new SeekToCurrentErrorHandler(recoverer, new FixedBackOff(0L, 2L));

@Bean
public KafkaJaasLoginModuleInitializer jaasConfig() throws IOException {
    KafkaJaasLoginModuleInitializer jaasConfig = new KafkaJaasLoginModuleInitializer();
    jaasConfig.setControlFlag("REQUIRED");
    Map<String, String> options = new HashMap<>();
    options.put("useKeyTab", "true");
    options.put("storeKey", "true");
    options.put("keyTab", "/etc/security/keytabs/kafka_client.keytab");
    options.put("principal", "kafka-client-1@EXAMPLE.COM");
    jaasConfig.setOptions(options);
    return jaasConfig;
}

@Bean(name = KafkaStreamsDefaultConfiguration.DEFAULT_STREAMS_CONFIG_BEAN_NAME)
public KafkaStreamsConfiguration kStreamsConfigs() {
    Map<String, Object> props = new HashMap<>();
    ...
    props.put(StreamsConfig.DEFAULT_DESERIALIZATION_EXCEPTION_HANDLER_CLASS_CONFIG,
            RecoveringDeserializationExceptionHandler.class);
    props.put(RecoveringDeserializationExceptionHandler.KSTREAM_DESERIALIZATION_RECOVERER, recoverer());
    ...
    return new KafkaStreamsConfiguration(props);
}

@Bean
public DeadLetterPublishingRecoverer recoverer() {
    return new DeadLetterPublishingRecoverer(kafkaTemplate(),
            (record, ex) -> new TopicPartition("recovererDLQ", -1));
}
==============================================================================================================
@TestPropertySource(locations = "classpath:/test.properties")
@EmbeddedKafka(topics = { "any-topic", "${kafka.topics.another-topic}" },
        brokerProperties = { "log.dir=${kafka.broker.logs-dir}",
                            "listeners=PLAINTEXT://localhost:${kafka.broker.port}",
                            "auto.create.topics.enable=${kafka.broker.topics-enable:true}" }
        brokerPropertiesLocation = "classpath:/broker.properties")
==============================================================================================================
@EmbeddedKafka
public class EmbeddedKafkaConditionTests {

	@Test
	public void test(EmbeddedKafkaBroker broker) {
		String brokerList = broker.getBrokersAsString();
        ...
	}

}
==============================================================================================================
@Bean
public KStream<byte[], byte[]> kStream(StreamsBuilder kStreamBuilder,
        MessagingTransformer<byte[], byte[], byte[]> transformer)  transformer) {
    KStream<byte[], byte[]> stream = kStreamBuilder.stream(STREAMING_TOPIC1);
    stream.mapValues((ValueMapper<byte[], byte[]>) String::toUpperCase)
            ...
            .transform(() -> transformer)
            .to(streamingTopic2);

    stream.print(Printed.toSysOut());

    return stream;
}

@Bean
@DependsOn("flow")
public MessagingTransformer<byte[], byte[], String> transformer(
        MessagingFunction function) {

    MessagingMessageConverter converter = new MessagingMessageConverter();
    converter.setHeaderMapper(new SimpleKafkaHeaderMapper("*"));
    return new MessagingTransformer<>(function, converter);
}

@Bean
public IntegrationFlow flow() {
    return IntegrationFlows.from(MessagingFunction.class)
        ...
        .get();
}
==============================================================================================================
public static String apacheFormat(long millis) throws ParseException {
    return DurationFormatUtils.formatDuration(millis, "HH:mm:ss");
}

public static String formatTimeUnit(long millis) throws ParseException {
String formatted = String.format(
        "%02d:%02d:%02d",
        TimeUnit.MILLISECONDS.toHours(millis),
        TimeUnit.MILLISECONDS.toMinutes(millis)
                - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(millis)),
        TimeUnit.MILLISECONDS.toSeconds(millis)
                - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(millis)));
    return formatted;
}

public static String formatDuration(final long millis) {
    long seconds = (millis / 1000) % 60;
    long minutes = (millis / (1000 * 60)) % 60;
    long hours = millis / (1000 * 60 * 60);

    StringBuilder b = new StringBuilder();
    b.append(hours == 0 ? "00" : hours < 10 ? String.valueOf("0" + hours) : 
    String.valueOf(hours));
    b.append(":");
    b.append(minutes == 0 ? "00" : minutes < 10 ? String.valueOf("0" + minutes) :     
    String.valueOf(minutes));
    b.append(":");
    b.append(seconds == 0 ? "00" : seconds < 10 ? String.valueOf("0" + seconds) : 
    String.valueOf(seconds));
    return b.toString();
}

public static String combinationFormatter(final long millis) {
    long seconds = TimeUnit.MILLISECONDS.toSeconds(millis)
            - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(millis));
    long minutes = TimeUnit.MILLISECONDS.toMinutes(millis)
            - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(millis));
    long hours = TimeUnit.MILLISECONDS.toHours(millis);

    StringBuilder b = new StringBuilder();
    b.append(hours == 0 ? "00" : hours < 10 ? String.valueOf("0" + hours) : 
    String.valueOf(hours));
    b.append(":");
    b.append(minutes == 0 ? "00" : minutes < 10 ? String.valueOf("0" + minutes) : 
    String.valueOf(minutes));
        b.append(":");
    b.append(seconds == 0 ? "00" : seconds < 10 ? String.valueOf("0" + seconds) : 
    String.valueOf(seconds));
    return b.toString(); 
 }
==============================================================================================================
language: java
dist: trusty
jdk:
  - oraclejdk8
env:
  global:
  - secure: D8Z2pmvfy0LETBW5A6xzdU/Q8dEkbVAptbofWZIpHEl4dWC6vVux3A5MeRIXp6Sv5n/Vyw4pIh+dXcUrrLtofhLksTLIEgeNpG6hC+ctMYMxW63U2skIxa6RQ8iZy5/qQ9btJH3hd4hJI3u2sQ2NgHpw/KCj1sRrT8aIrS9QQl4zxxLd8D8HPUlr3O/eV1Ik38quCPmmrp/6jRJnZnE1Y3IcNqt/L0CLsZwqued6WyqWBU/2yskGxmij5i88RPgxN1oau6HUtPW8lqJhwdnTOgi9/t9kDkItopPC25A6gSGwwI75gF1jvWe95aQQfqLwHnOZcjEEBs3836ibQT5PPTr9vtKLssH35uM22pAWIlP38zilOIVN4Jy3nYC983ef7ZtBLuBFBatmOUBYOrlFN4GdlVPUOcbZFsBnjQnDoSADJ+fDt6Q/WJ2knudfc82kle0Jul8fIKP5OIGLk1ZhhuBYkbM6k8l3offk/cRIhVI5D94zm2UJkw+8MAlP6ffcPNMUzCU9YofaB0lX3j5/JKwntph27VnNUsplsUtM0uOEtN+4VuzdzAXDnm1yp4fGObffrMUJ9coG+kEBYaKFoLgFoVv1H76Xn1FLWtbqBOnC6Se5FPoxYVD2eYMjNRuEP9sYs63jS0oYjWj+Z2z1rkH26BgyGcCZxCj7qTzvTwE=
  - secure: DTfPB0fMpchGnbeV5YVevVQBoqow1WCeSZqgjKigsVgkKTFhuX03Wnbjce7E669p2vioPclxrF6jvjegDZCexIjUYNRZhfNZtvaZ6/kzwOC9vlC9b+5WJ6XSG6gm7YZaQ2TP353c8bqBSyVW2LvECtwZZxM3x6pt8zA2UX100uh/+0Ftc3QbBoBXZkgaXfCT84P/OO52hPuZZl04u+TJabrwt3TPxRUIcxTrGUnW37wOPxyYt6qcFZplAmjorm6vFIcE0FNH90yViqEp3rKBtQGgDW0XnmoTYLRCEDDdRmTyGFoOjjnpZuaA41iiUJx6F3H63zAQOpB8mefjvYGKcnvIVHTHWfPOwNycSiATQ9g8QV5Z3y6HE+Kk5wDcL/USiOl4tn651s4eY+tE2sswpRyMfQa/f6x73xYT0Wqa22Xss4uzLtVJhxcZIku8pxDSJg40XQxSUXwuwfU3OJvNjsKVPjXnZ3QYrvQN7A6ZEDRw60BLQ+XVvlHSdLAeWPbtUWeUc1ke/x7QhTGIskkGlvV9AlW6LQDkfX5YwjQ9ZYCyAmfSjmN4J01oBQbbj+/XoS1iIna7VpWEEPbMw6sG+CF3jyk14EwmU2l8G3ZxtXBkzzCH5joIOTQZh8iUZ1BxTqBWlExHlcaUHJxG12udc/MLzkKUDIcOEIOlkzuwfhU=
script:
  - ./gradlew clean check --refresh-dependencies
  - ./gradlew clean check --refresh-dependencies -PfasterxmlVersion=2.8.4
  - ./gradlew clean check --refresh-dependencies -PfasterxmlVersion=2.9.1
  - ./gradlew codeCoverageReport
after_success:
  - bash <(curl -s https://codecov.io/bash)
  - ./gradlew uploadArchives -PnexusUsername="${SONATYPE_USER}" -PnexusPassword="${SONATYPE_PASS}"
==============================================================================================================
@SpringBootApplication
public class KReplyingApplication {

    public static void main(String[] args) {
        SpringApplication.run(KReplyingApplication.class, args);
    }

    @KafkaListener(id="server", topics = "kRequests")
    @SendTo // use default replyTo expression
    public String listen(String in) {
        System.out.println("Server received: " + in);
        return in.toUpperCase();
    }

    @Bean
    public NewTopic kRequests() {
        return new NewTopic("kRequests", 10, (short) 2);
    }

    @Bean // not required if Jackson is on the classpath
    public MessagingMessageConverter simpleMapperConverter() {
        MessagingMessageConverter messagingMessageConverter = new MessagingMessageConverter();
        messagingMessageConverter.setHeaderMapper(new SimpleKafkaHeaderMapper());
        return messagingMessageConverter;
    }

}
==============================================================================================================
#Bean
public ConcurrentKafkaListenerContainerFactory kafkaListenerContainerFactory() {
ConcurrentKafkaListenerContainerFactory factory = new ConcurrentKafkaListenerContainerFactory();
factory.setConsumerFactory(new DefaultKafkaConsumerFactory<>(kafkaProps()));
factory.getContainerProperties().setAckOnError(false);
factory.getContainerProperties().setErrorHandler(new SeekToCurrentErrorHandler());
factory.getContainerProperties().setAckMode(AbstractMessageListenerContainer.AckMode.MANUAL);
return factory;
}

@Bean
public ConcurrentKafkaListenerContainerFactory kafkaListenerContainerFactory(
    ConcurrentKafkaListenerContainerFactoryConfigurer configurer,
    ConsumerFactory<Object, Object> kafkaConsumerFactory,
    KafkaTemplate<Object, Object> template) {
  ConcurrentKafkaListenerContainerFactory<Object, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
  configurer.configure(factory, kafkaConsumerFactory);
  factory.setErrorHandler(new SeekToCurrentErrorHandler(
      new DeadLetterPublishingRecoverer(template), 3));
  return factory;
}

@KafkaListener(id = "fooGroup", topics = "topic1")
public void listen(String in) {
  logger.info("Received: " + in);
  if (in.startsWith("foo")) {
    throw new RuntimeException("failed");
  }
}

@KafkaListener(id = "dltGroup", topics = "topic1.DLT")
public void dltListen(String in) {
  logger.info("Received from DLT: " + in);
}
==============================================================================================================
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MQProducerConfig {
	@Value("${spring.rabbitmq.queuename}")
	private String queueName;
	@Value("${spring.rabbitmq.exchange}")
	private String queueExchange;
	@Value("${spring.rabbitmq.routingkey}")
	private String routingkey;
	 
    @Bean
    public MessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }
    
    @Bean
    @ConfigurationProperties(prefix="spring.rabbitmq")
    public ConnectionFactory connectionFactory(){
    	return new CachingConnectionFactory (); //publisherConfirms 消息确认回调
    }
    
    @Bean
    public RabbitTemplate template(ConnectionFactory connectionFactory, MessageConverter converter) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        //template.setChannelTransacted(false);
        template.setMandatory(true);
        template.setExchange(queueExchange);
        template.setRoutingKey(routingkey);
        template.setMessageConverter(converter);
        return template;
    }

    @Bean
    public Queue queue() {
        return new Queue(queueName, true);
    }
    
}

import java.util.Date;
import java.util.UUID;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.core.RabbitTemplate.ConfirmCallback;
import org.springframework.amqp.rabbit.support.CorrelationData;
import org.springframework.beans.factory.annotation.Value;

public abstract class BasicService implements ConfirmCallback {
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Resource
	public RabbitTemplate rabbitTemplate;
	@Value("${spring.rabbitmq.routingkey}")
	private String routingkey;
	@Value("${spring.rabbitmq.appid}")
	private String appId;

    public void sendMessage(final String serviceName, final String serviceMethodName,final String correlationId, Object request) {
    	logger.info("sendMessage [this.{}, serviceMethodName:{} serviceName:{} correlationId: {}]", this.getClass(), serviceMethodName, serviceName, correlationId);
    	rabbitTemplate.setConfirmCallback(this);
    	rabbitTemplate.setCorrelationKey(correlationId);
    	rabbitTemplate.convertAndSend(routingkey, request, new MessagePostProcessor() {            
        	@Override
            public Message postProcessMessage(Message message) throws AmqpException {
                message.getMessageProperties().setAppId(appId);
                message.getMessageProperties().setTimestamp(new Date());
                message.getMessageProperties().setMessageId(UUID.randomUUID().toString());
                message.getMessageProperties().setCorrelationId(correlationId.getBytes());
                message.getMessageProperties().setHeader("ServiceMethodName", serviceMethodName);
                message.getMessageProperties().setHeader("ServiceName", serviceName);
                return message;
            }
        }, new CorrelationData(correlationId));
    }

    /**
     * 抽象回调方法
     */
	@Override
	public abstract void confirm(CorrelationData correlationData, boolean ack, String cause);
	
}

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.annotation.Resource;

import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.core.ChannelAwareMessageListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import com.rabbitmq.client.Channel;

/**
 * 消息监听
 * @author lonyee
 *
 */
@Component
public class MQAwareListener implements ChannelAwareMessageListener, ApplicationContextAware {

    @Resource
    private MessageConverter messageConverter;
    @Resource
    private RabbitTemplate rabbitTemplate;
	@Value("${spring.rabbitmq.appid}")
	private String appId;

    private ApplicationContext ctx;

    @Override
    public void onMessage(Message message, Channel channel) throws IOException {
        System.out.println("----- received" + message.getMessageProperties());
		try {
			Object msg = messageConverter.fromMessage(message);
			if (!appId.equals(message.getMessageProperties().getAppId())){
		        channel.basicNack(message.getMessageProperties().getDeliveryTag(), false, false);
		        throw new SecurityException("非法应用appId:" + message.getMessageProperties().getAppId());
			}
			Object service = ctx.getBean(message.getMessageProperties().getHeaders().get("ServiceName").toString());
			String serviceMethodName = message.getMessageProperties().getHeaders().get("ServiceMethodName").toString();
			Method method = service.getClass().getMethod(serviceMethodName, msg.getClass());
	        method.invoke(service, msg);
	        //确认消息成功消费
	        channel.basicAck(message.getMessageProperties().getDeliveryTag(), false);
		} catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			System.out.println("------ err"+ e.getMessage());
	        channel.basicNack(message.getMessageProperties().getDeliveryTag(), false, false);
		}
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.ctx = applicationContext;
    }

}

import org.springframework.amqp.core.AcknowledgeMode;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MQConsumerConfig {
	@Value("${spring.rabbitmq.queuename}")
	private String queueName ;
	@Value("${spring.rabbitmq.exchange}")
	private String queueExchange;
	@Value("${spring.rabbitmq.routingkey}")
	private String routingkey;

    @Bean
    public MessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate template(ConnectionFactory connectionFactory, MessageConverter converter) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(converter);
        return template;
    }
    
    @Bean
    public SimpleMessageListenerContainer container(ConnectionFactory connectionFactory, Queue queue, MessageListenerAdapter listenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer(connectionFactory);
        //container.setQueueNames(queueName);
        container.setQueues(queue);
        container.setExposeListenerChannel(true);
        container.setMaxConcurrentConsumers(1);
        container.setConcurrentConsumers(1);
        container.setPrefetchCount(1000);
        container.setAcknowledgeMode(AcknowledgeMode.MANUAL); //设置确认模式手工确认
        container.setMessageListener(listenerAdapter);
        return container;
    }
    
    @Bean
    public MessageListenerAdapter listenerAdapter(MQAwareListener listener, MessageConverter converter) {
        return new MessageListenerAdapter(listener, converter);
    }
    
    @Bean
    public Queue queue() {
        return new Queue(queueName, true);
    }
    
    /**
     * 创建exchange, 可以创建TopicExchange(*、#模糊匹配routing key，routing key必须包含".")，DirectExchange，FanoutExchange(无routing key概念)
     * @return
     */
    @Bean
    public TopicExchange exchange(){
        return new TopicExchange(queueExchange);
    }
    /*@Bean
    public DirectExchange exchange(){
        return new DirectExchange(queueExchange);
    }*/
    
    @Bean
    public Binding binding(Queue queue, TopicExchange exchange){
        return BindingBuilder.bind(queue).to(exchange).with(routingkey);
    }
}



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.social.security.SocialUserDetails;
import org.springframework.social.security.SocialUserDetailsService;

/**
 * This class delegates requests forward to our UserDetailsService implementation.
 * This is possible because we use the username of the user as the account ID.
 * @author Petri Kainulainen
 */
public class SimpleSocialUserDetailsService implements SocialUserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(SimpleSocialUserDetailsService.class);

    private UserDetailsService userDetailsService;

    public SimpleSocialUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Loads the username by using the account ID of the user.
     * @param userId    The account ID of the requested user.
     * @return  The information of the requested user.
     * @throws UsernameNotFoundException    Thrown if no user is found.
     * @throws DataAccessException
     */
    @Override
    public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException, DataAccessException {
        logger.debug("Loading user by user id: {}", userId);

        UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
        logger.debug("Found user details: {}", userDetails);

        return (SocialUserDetails) userDetails;
    }
}


import com.nixmash.blog.solr.common.SolrSettings;
import com.nixmash.blog.solr.repository.simple.SimpleProductRepositoryImpl;
import org.apache.solr.client.solrj.embedded.EmbeddedSolrServer;
import org.apache.solr.core.CoreContainer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.solr.core.SolrTemplate;

import java.nio.file.FileSystems;
import java.nio.file.Path;

@Configuration
@Profile("dev")
public class EmbeddedSolrContext {

	@Autowired
	private SolrSettings solrSettings;

	@Bean(name = "solrClient")
	public EmbeddedSolrServer solrServerFactoryBean() {
		String solrCoreName = solrSettings.getSolrCoreName();
		String solrHome = solrSettings.getSolrEmbeddedPath();
		Path path = FileSystems.getDefault().getPath(solrHome);
		CoreContainer container = CoreContainer.createAndLoad(path);
		return new EmbeddedSolrServer(container, solrCoreName);
	}

	@Bean
	public SolrTemplate solrTemplate() throws Exception {
		String solrCoreName = solrSettings.getSolrCoreName();
		SolrTemplate solrTemplate = new SolrTemplate(solrServerFactoryBean());
		solrTemplate.setSolrCore(solrCoreName);
		return solrTemplate;
	}

	@Bean
	public SimpleProductRepositoryImpl simpleProductRepository() throws Exception {
		SimpleProductRepositoryImpl simpleRepository = new SimpleProductRepositoryImpl();
		simpleRepository.setSolrOperations(solrTemplate());
		return simpleRepository;
	}

}

import com.nixmash.blog.solr.enums.SolrDocType;
import com.nixmash.blog.solr.model.IProduct;
import com.nixmash.blog.solr.model.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.solr.core.query.*;
import org.springframework.data.solr.core.query.result.FacetPage;
import org.springframework.data.solr.repository.support.SimpleSolrRepository;

import java.util.List;

@NoRepositoryBean
public class SimpleProductRepositoryImpl extends SimpleSolrRepository<Product, String> implements SimpleBaseProductRepository {

	@Override
	public List<Product> findByAvailableTrue() {
		Query query = new SimpleQuery(new Criteria(new SimpleField(Criteria.WILDCARD)).expression(Criteria.WILDCARD));
		query.addFilterQuery(new SimpleQuery(new Criteria(IProduct.DOCTYPE_FIELD).is(SolrDocType.PRODUCT)));
		query.setRows(1000);
		Page<Product> results = getSolrOperations().queryForPage(query, Product.class);
		return results.getContent();
	}

	@Override
	public FacetPage<Product> findByFacetOnAvailable(Pageable pageable) {
		FacetQuery query = new SimpleFacetQuery(new
						Criteria(IProduct.DOCTYPE_FIELD).is(SolrDocType.PRODUCT));
		query.setFacetOptions(new FacetOptions(Product.AVAILABLE_FIELD).setFacetLimit(5));
		query.setPageRequest(new PageRequest(0, 100));
		return getSolrOperations().queryForFacetPage(query, Product.class);

	}

	@Override
	public FacetPage<Product> findByFacetOnCategory(Pageable pageable) {

		FacetQuery query = new
				SimpleFacetQuery(new Criteria(IProduct.DOCTYPE_FIELD)
						.is(SolrDocType.PRODUCT));

		query.setFacetOptions(new FacetOptions(Product.CATEGORY_FIELD)
				.setPageable(new PageRequest(0,20)));

		return getSolrOperations().queryForFacetPage(query, Product.class);
	}

}

import com.nixmash.blog.solr.model.IProduct;
import com.nixmash.blog.solr.model.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.geo.Box;
import org.springframework.data.geo.Distance;
import org.springframework.data.geo.Point;
import org.springframework.data.solr.core.query.Query.Operator;
import org.springframework.data.solr.core.query.result.FacetPage;
import org.springframework.data.solr.core.query.result.HighlightPage;
import org.springframework.data.solr.repository.Facet;
import org.springframework.data.solr.repository.Highlight;
import org.springframework.data.solr.repository.Query;
import org.springframework.data.solr.repository.SolrCrudRepository;

import java.util.Collection;
import java.util.List;


public interface CustomProductRepository extends CustomBaseProductRepository, SolrCrudRepository<Product, String> {

	Page<Product> findByPopularityGreaterThanEqual(Integer popularity, Pageable page);

	@Query("name:*?0* AND doctype:product")
	List<Product> findByNameStartingWith(String name);

	List<Product> findByAvailableTrue();

	List<Product> findByAvailableTrueAndDoctype(String docType);

	@Query(IProduct.AVAILABLE_FIELD + ":false")
	Page<Product> findByAvailableFalseUsingAnnotatedQuery(Pageable page);

	public List<Product> findByNameContainsOrCategoriesContains(String title, String category, Sort sort);

	@Query(name = "Product.findByNameOrCategory")
	public List<Product> findByNameOrCategory(String searchTerm, Sort sort);

	@Query("cat:*?0* AND doctype:product")
	public List<Product> findByCategory(String category);

	@Query("(name:*?0* OR cat:*?0*) AND doctype:product")
	public List<Product> findByAnnotatedQuery(String searchTerm, Sort sort);

	@Query("inStock:true AND doctype:product")
	public List<Product> findAvailableProducts();

	@Query("doctype:product")
	public List<Product> findAllProducts();

	@Query("doctype:product")
	public Page<Product> findAllProductsPaged(Pageable page);
	
	@Query(value = "*:*", filters = { "doctype:product" })
	@Facet(fields = IProduct.CATEGORY_FIELD, limit = 6)
	public FacetPage<Product> findProductCategoryFacets(Pageable page);

	@Query("doctype:product")
	@Facet(fields = IProduct.NAME_FIELD, limit = 100)
	public FacetPage<Product> findByNameStartingWith(Collection<String> nameFragments, Pageable pageable);

	public List<Product> findByLocationWithin(Point location, Distance distance);
	
	public List<Product> findByLocationNear(Point location, Distance distance);
	
	public List<Product> findByLocationNear(Box bbox);
	
	@Query("{!geofilt pt=?0 sfield=store d=?1}")
	public List<Product> findByLocationSomewhereNear(Point location, Distance distance);
	
	@Highlight(prefix = "<b>", postfix = "</b>")
	@Query(fields = { IProduct.ID_FIELD, IProduct.NAME_FIELD,
			IProduct.FEATURE_FIELD, IProduct.CATEGORY_FIELD , IProduct.POPULARITY_FIELD, IProduct.LOCATION_FIELD}, defaultOperator = Operator.AND)
	public HighlightPage<Product> findByNameIn(Collection<String> names, Pageable page);

}

import com.nixmash.blog.solr.enums.SolrDocType;
import com.nixmash.blog.solr.model.IProduct;
import com.nixmash.blog.solr.model.Product;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.solr.core.SolrTemplate;
import org.springframework.data.solr.core.query.*;
import org.springframework.data.solr.core.query.result.HighlightPage;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;
import java.util.List;

@Repository
public class CustomProductRepositoryImpl implements CustomBaseProductRepository {

	private static final Logger logger = LoggerFactory.getLogger(CustomBaseProductRepository.class);

	@Resource
	private SolrTemplate solrTemplate;

	@Override
	public Page<Product> findTestCategoryRecords() {
		return solrTemplate.queryForPage(
				new SimpleQuery(new SimpleStringCriteria("cat:test")).setPageRequest(new PageRequest(0, 100)),
				Product.class);
	}

	@Override
	public List<Product> findProductsBySimpleQuery(String userQuery) {

		Query query = new SimpleQuery(userQuery);
		query.addFilterQuery(new SimpleQuery(new Criteria(IProduct.DOCTYPE_FIELD).is(SolrDocType.PRODUCT)));
		query.setRows(1000);

		Page<Product> results = solrTemplate.queryForPage(query, Product.class);
		return results.getContent();
	}

	@Override
	public void updateProductCategory(String productId, List<String> categories) {
		PartialUpdate update = new PartialUpdate(IProduct.ID_FIELD, productId);
		update.setValueOfField(IProduct.CATEGORY_FIELD, categories);
		solrTemplate.saveBean(update);
		solrTemplate.commit();
	}

	@Override
	public void updateProductName(Product product) {
		logger.debug("Performing partial update for todo entry: {}", product);
		PartialUpdate update = new PartialUpdate(Product.ID_FIELD, product.getId());
		update.add(Product.NAME_FIELD, product.getName());
		solrTemplate.saveBean(update);
		solrTemplate.commit();
	}

	@Override
	public List<Product> searchWithCriteria(String searchTerm) {
		logger.debug("Building a product criteria query with search term: {}", searchTerm);

		String[] words = searchTerm.split(" ");

		Criteria conditions = createSearchConditions(words);
		SimpleQuery search = new SimpleQuery(conditions);
		search.addSort(sortByIdDesc());

		Page<Product> results = solrTemplate.queryForPage(search, Product.class);
		return results.getContent();
	}

	@Override
	public HighlightPage<Product> searchProductsWithHighlights(String searchTerm) {
		SimpleHighlightQuery query = new SimpleHighlightQuery();
		String[] words = searchTerm.split(" ");
		Criteria conditions = createHighlightedNameConditions(words);
		query.addCriteria(conditions);

		HighlightOptions hlOptions = new HighlightOptions();
		hlOptions.addField("name");
		hlOptions.setSimplePrefix("<b>");
		hlOptions.setSimplePostfix("</b>");
		query.setHighlightOptions(hlOptions);

		return solrTemplate.queryForHighlightPage(query, Product.class);
	}

	private Criteria createHighlightedNameConditions(String[] words) {
		Criteria conditions = null;

		for (String word : words) {
			if (conditions == null) {
				conditions = new Criteria(Product.NAME_FIELD).contains(word);
			} else {
				conditions = conditions.or(new Criteria(Product.NAME_FIELD).contains(word));
			}
		}

		return conditions;
	}

	private Criteria createSearchConditions(String[] words) {
		Criteria conditions = null;

		for (String word : words) {
			if (conditions == null) {
				conditions = new Criteria(Product.NAME_FIELD).contains(word)
						.or(new Criteria(Product.CATEGORY_FIELD).contains(word));
			} else {
				conditions = conditions.or(new Criteria(Product.NAME_FIELD).contains(word))
						.or(new Criteria(Product.CATEGORY_FIELD).contains(word));
			}
		}

		return conditions;
	}

	public Sort sortByIdDesc() {
		return new Sort(Sort.Direction.DESC, Product.ID_FIELD);
	}
}

import com.nixmash.blog.solr.model.PostDoc;
import org.springframework.data.solr.UncategorizedSolrException;
import org.springframework.data.solr.repository.Query;
import org.springframework.data.solr.repository.SolrCrudRepository;

import java.util.List;

public interface CustomPostDocRepository extends CustomBasePostDocRepository, SolrCrudRepository<PostDoc, String> {

    @Query("doctype:post")
    List<PostDoc> findAllPostDocuments();

    @Query("doctype:post AND id:?0")
    PostDoc findPostDocByPostId(long postId);

    @Query(value = "id:?0", requestHandler = "/mlt", filters = { "posttype:POST" })
    List<PostDoc> findMoreLikeThis(long postId) throws UncategorizedSolrException;

}

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Created by daveburke on 10/25/16.
 */
@SuppressWarnings({"SpringElInspection", "ELValidationInJSP"})
@Caching(

        evict = {
                @CacheEvict(cacheNames= "posts", key = "#result.postId"),
                @CacheEvict(cacheNames= "posts", key = "#result.postName"),
                @CacheEvict(cacheNames= "pagedPosts",
                        allEntries = true,
                        beforeInvocation = true)
        }
)
@Target({ElementType.METHOD})
@Retention(RUNTIME)
public @interface CachePostUpdate {
}



import com.nixmash.blog.jpa.dto.PostDTO;
import com.nixmash.blog.jpa.model.Post;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.*;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.core.job.flow.FlowExecutionStatus;
import org.springframework.batch.core.job.flow.JobExecutionDecider;
import org.springframework.batch.core.launch.support.RunIdIncrementer;
import org.springframework.batch.core.listener.ExecutionContextPromotionListener;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ItemWriter;
import org.springframework.batch.item.database.JpaPagingItemReader;
import org.springframework.batch.item.file.FlatFileItemWriter;
import org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor;
import org.springframework.batch.item.file.transform.DelimitedLineAggregator;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;

import javax.persistence.EntityManagerFactory;

@SuppressWarnings("Convert2Lambda")
@Configuration
public class DemoJobConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(DemoJobConfiguration.class);

    private static final FlowExecutionStatus YES = new FlowExecutionStatus("YES");
    private static final FlowExecutionStatus NO = new FlowExecutionStatus("NO");

    private final JobBuilderFactory jobBuilderFactory;
    private final StepBuilderFactory stepBuilderFactory;
    private final EntityManagerFactory entityManagerFactory;
    private final DemoJobListener demoJobListener;
    private final DemoJobStepListener demoJobStepListener;

    @Autowired
    public DemoJobConfiguration(EntityManagerFactory entityManagerFactory, DemoJobListener demoJobListener, DemoJobStepListener demoJobStepListener, StepBuilderFactory stepBuilderFactory, JobBuilderFactory jobBuilderFactory) {
        this.entityManagerFactory = entityManagerFactory;
        this.demoJobListener = demoJobListener;
        this.demoJobStepListener = demoJobStepListener;
        this.stepBuilderFactory = stepBuilderFactory;
        this.jobBuilderFactory = jobBuilderFactory;
    }

    private String c(FlowExecutionStatus executionStatus) {
        return executionStatus.getName();
    }

    @Bean
    public JpaPagingItemReader<Post> demoJobReader() throws Exception {
        String jpqlQuery = "SELECT p from Post p";

        JpaPagingItemReader<Post> reader = new JpaPagingItemReader<>();
        reader.setQueryString(jpqlQuery);
        reader.setEntityManagerFactory(entityManagerFactory);
        reader.setPageSize(1000);
        reader.afterPropertiesSet();
        reader.setSaveState(true);

        return reader;
    }

    @Bean
    public DemoJobItemProcessor demoJobProcessor() {
        return new DemoJobItemProcessor();
    }

    @Bean
    public ItemWriter<PostDTO> demoJobWriter() {
        FlatFileItemWriter<PostDTO> writer = new FlatFileItemWriter<>();
        writer.setResource(new FileSystemResource("/home/daveburke/web/nixmashspring/posts.csv"));
        DelimitedLineAggregator<PostDTO> delLineAgg = new DelimitedLineAggregator<>();
        delLineAgg.setDelimiter(";");
        BeanWrapperFieldExtractor<PostDTO> fieldExtractor = new BeanWrapperFieldExtractor<>();
        fieldExtractor.setNames(new String[]{"postTitle"});
        delLineAgg.setFieldExtractor(fieldExtractor);
        writer.setLineAggregator(delLineAgg);
        return writer;
    }

    @Bean(name = "demoJob")
    public Job demoJob() throws Exception {
        return jobBuilderFactory.get("demoJob")
                .incrementer(new RunIdIncrementer())
                .listener(demoJobListener)
                .flow(demoStep1())
                .next(decideIfGoodToContinue())
                .on(c(NO))
                .end()
                .on(c(YES))
                .to(optionalStep())
                .end()
                .build();
    }

    @Bean
    public Step demoStep1() throws Exception {
        return stepBuilderFactory.get("demoStep1")
                .<Post, PostDTO>chunk(100)
                .reader(demoJobReader())
                .processor(demoJobProcessor())
                .writer(demoJobWriter())
                .listener(demoPromotionListener())
                .listener(demoJobStepListener)
                .allowStartIfComplete(true)
                .build();
    }

    @Bean
    public JobExecutionDecider decideIfGoodToContinue() {
        return new JobExecutionDecider() {

            int iteration = 0;

            @Override
            public FlowExecutionStatus decide(JobExecution jobExecution, StepExecution stepExecution) {
                long postId = 0;
                try {
                    postId = jobExecution.getExecutionContext().getLong("postId");
                } catch (Exception e) {
                    logger.info("FlowExecution Exception: " + e.getMessage());
                }

                long iterations = jobExecution.getJobParameters().getLong("iterations");
                if(iteration < iterations) {
                    logger.info("ITERATING... POSTID = " + postId);
                    iteration++;
                    return YES;
                } else {
                    logger.info("REPEATED 2X's. SKIPPING OPTIONAL STEP");
                    return NO;
                }
            }
        };
    }

    @Bean
    public Step optionalStep() {
        return stepBuilderFactory.get("optionalStep")
                .tasklet(new Tasklet() {
                    @Override
                    public RepeatStatus execute(StepContribution contribution,
                                                ChunkContext chunkContext) throws Exception {
                        logger.info("IN OPTIONAL STEP ------------------------ */");
                        return RepeatStatus.FINISHED;
                    }
                })
                .build();
    }

    @Bean
    public ExecutionContextPromotionListener demoPromotionListener()
    {
        ExecutionContextPromotionListener listener =
                                                                                    new ExecutionContextPromotionListener();
        listener.setKeys( new String[] { "postId" } );
        return listener;
    }

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.annotation.EnableRabbit;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.web.filter.CharacterEncodingFilter;

@EnableRabbit
@Configuration
public class AmqpConfig {
    public static final String EXCHANGE = "spring.boot.direct";
    public static final String ROUTINGKEY_FAIL = "spring.boot.routingKey.failure";
    public static final String ROUTINGKEY = "spring.boot.routingKey";
    public static final String QUEUE_NAME = "spring.demo";
    public static final String QUEUE_NAME_FAIL = "spring.demo.failure";

    //RabbitMQ的配置信息
    @Value("${spring.rabbitmq.host}")
    private String host;
    @Value("${spring.rabbitmq.port}")
    private Integer port;
    @Value("${spring.rabbitmq.username}")
    private String username;
    @Value("${spring.rabbitmq.password}")
    private String password;
    @Value("${spring.rabbitmq.virtual-host}")
    private String virtualHost;


    //建立一个连接容器，类型数据库的连接池
    @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory connectionFactory =
                new CachingConnectionFactory(host, port);
        connectionFactory.setUsername(username);
        connectionFactory.setPassword(password);
        connectionFactory.setVirtualHost(virtualHost);
        connectionFactory.setPublisherConfirms(true);// 确认机制
        //发布确认，template要求CachingConnectionFactory的publisherConfirms属性设置为true
        return connectionFactory;
    }

    // RabbitMQ的使用入口
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    //必须是prototype类型
    public RabbitTemplate rabbitTemplate() {
        RabbitTemplate template = new RabbitTemplate(this.connectionFactory());
        template.setMessageConverter(this.jsonMessageConverter());
        template.setMandatory(true);
        return template;
    }

    /**
     * 交换机
     * 针对消费者配置
     * FanoutExchange: 将消息分发到所有的绑定队列，无routingkey的概念
     * HeadersExchange ：通过添加属性key-value匹配
     * DirectExchange:按照routingkey分发到指定队列
     * TopicExchange:多关键字匹配
     */
    @Bean
    public DirectExchange exchange() {
        return new DirectExchange(EXCHANGE);
    }

    /**
     * 队列
     *
     * @return
     */
    @Bean
    public Queue queue() {
        return new Queue(QUEUE_NAME, true); //队列持久

    }

    @Bean
    public Queue queueFail() {
        return new Queue(QUEUE_NAME_FAIL, true); //队列持久

    }
    /**
     * 绑定
     *
     * @return
     */
    @Bean
    public Binding binding(Queue queue, DirectExchange exchange) {
        return BindingBuilder.bind(queue()).to(exchange()).with(AmqpConfig.ROUTINGKEY);
    }

    @Bean
    public Binding bindingFail(Queue queue, DirectExchange exchange) {
        return BindingBuilder.bind(queueFail()).to(exchange()).with(AmqpConfig.ROUTINGKEY_FAIL);
    }
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    /**
     * 声明一个监听容器
     *
     * @return
     */
//    @Bean(name="rabbitListenerContainer")
//    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory() {
//        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
//        factory.setMessageConverter(jsonMessageConverter());
//        factory.setConnectionFactory(connectionFactory());
//        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);//设置消费者手动应答
//        factory.setPrefetchCount(1);//从代理接收消息的数目。这个值越大，发送消息就越快，但是导致非顺序处理的风险就越高
//
//        return factory;
//    }

    @Bean
    Receiver receiver(){
        return new Receiver();
    }

    @Bean
    MessageListenerAdapter listenerAdapter(Receiver receiver) {
        return new MessageListenerAdapter(receiver, "onMessage");
    }

    @Bean
    public SimpleMessageListenerContainer messageListenerContainer(MessageListenerAdapter listenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer();
        container.setConnectionFactory(connectionFactory());
        container.setQueueNames(AmqpConfig.QUEUE_NAME);
        container.setExposeListenerChannel(true);
        container.setMaxConcurrentConsumers(1);
        container.setConcurrentConsumers(1);
        container.setAcknowledgeMode(AcknowledgeMode.MANUAL); //设置确认模式手工确认
        container.setMessageListener(listenerAdapter);
        return container;
    }



    @Bean
    public CharacterEncodingFilter characterEncodingFilter() {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        filter.setEncoding("UTF-8");
        filter.setForceEncoding(true);
        return filter;
    }

}


import java.io.Serializable;
import java.lang.reflect.Type;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.config.spi.Converter;

/**
 * @author <a href="http://jmesnil.net/">Jeff Mesnil</a> (c) 2017 Red Hat inc.
 */
class Converters {

    static final Converter<String> STRING_CONVERTER = (Converter & Serializable) value -> value;

    static final Converter<Boolean> BOOLEAN_CONVERTER = (Converter & Serializable) value -> {
        if (value != null) {
            return "TRUE".equalsIgnoreCase(value)
                    || "1".equalsIgnoreCase(value)
                    || "YES".equalsIgnoreCase(value)
                    || "Y".equalsIgnoreCase(value)
                    || "ON".equalsIgnoreCase(value)
                    || "JA".equalsIgnoreCase(value)
                    || "J".equalsIgnoreCase(value)
                    || "OUI".equalsIgnoreCase(value);
        }
        return null;
    };

    static final Converter<Double> DOUBLE_CONVERTER = (Converter & Serializable) value -> value != null ? Double.valueOf(value) : null;

    static final Converter<Float> FLOAT_CONVERTER = (Converter & Serializable) value -> value != null ? Float.valueOf(value) : null;

    static final Converter<Long> LONG_CONVERTER = (Converter & Serializable) value -> value != null ? Long.valueOf(value) : null;

    static final Converter<Integer> INTEGER_CONVERTER = (Converter & Serializable) value -> value != null ? Integer.valueOf(value) : null;

    static final Converter<Duration> DURATION_CONVERTER = (Converter & Serializable) value -> {
        try {
            return value != null ? Duration.parse(value) : null;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(e);
        }
    };

    static final Converter<LocalDate> LOCAL_DATE_CONVERTER = (Converter & Serializable) value -> {
        try {
            return value != null ? LocalDate.parse(value) : null;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(e);
        }
    };

    static final Converter<LocalTime> LOCAL_TIME_CONVERTER = (Converter & Serializable) value -> {
        try {
            return value != null ? LocalTime.parse(value) : null;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(e);
        }
    };

    static final Converter<LocalDateTime> LOCAL_DATE_TIME_CONVERTER = (Converter & Serializable) value -> {
        try {
            return value != null ? LocalDateTime.parse(value) : null;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(e);
        }
    };

    public static final Map<Type, Converter> ALL_CONVERTERS = new HashMap<>();

    static {
        ALL_CONVERTERS.put(String.class, STRING_CONVERTER);

        ALL_CONVERTERS.put(Boolean.class, BOOLEAN_CONVERTER);
        ALL_CONVERTERS.put(Boolean.TYPE, BOOLEAN_CONVERTER);

        ALL_CONVERTERS.put(Double.class, DOUBLE_CONVERTER);
        ALL_CONVERTERS.put(Double.TYPE, DOUBLE_CONVERTER);

        ALL_CONVERTERS.put(Float.class, FLOAT_CONVERTER);
        ALL_CONVERTERS.put(Float.TYPE, FLOAT_CONVERTER);

        ALL_CONVERTERS.put(Long.class, LONG_CONVERTER);
        ALL_CONVERTERS.put(Long.TYPE, LONG_CONVERTER);

        ALL_CONVERTERS.put(Integer.class, INTEGER_CONVERTER);
        ALL_CONVERTERS.put(Integer.TYPE, INTEGER_CONVERTER);

        ALL_CONVERTERS.put(Duration.class, DURATION_CONVERTER);

        ALL_CONVERTERS.put(LocalDate.class, LOCAL_DATE_CONVERTER);

        ALL_CONVERTERS.put(LocalTime.class, LOCAL_TIME_CONVERTER);

        ALL_CONVERTERS.put(LocalDateTime.class, LOCAL_DATE_TIME_CONVERTER);
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
language: go
go:
  - 1.12
script:
  - env GO111MODULE=on make lint
  - env GO111MODULE=on go test -race -coverprofile=coverage.txt -covermode=atomic $(go list ./...)
after_success:
  - bash <(curl -s https://codecov.io/bash)
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
 
import static org.junit.jupiter.api.Assertions.assertNotNull;
 
@DisplayName("Pass the method parameters provided by the @ValueSource annotation")
class ValueSourceExampleTest {
 
    @DisplayName("Should pass a non-null message to our test method")
    @ParameterizedTest(name = "{index} => message=''{0}''")
    @ValueSource(strings = {"Hello", "World"})
    void shouldPassNonNullMessageAsMethodParameter(String message) {
        assertNotNull(message);
    }
}

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
 
import static org.junit.jupiter.api.Assertions.assertNotNull;
 
@DisplayName("Pass enum values to our test method")
class EnumSourceExampleTest {
 
    @DisplayName("Should pass non-null enum values as method parameters")
    @ParameterizedTest(name = "{index} => pet=''{0}''")
    @EnumSource(Pet.class)
    void shouldPassNonNullEnumValuesAsMethodParameter(Pet pet) {
        assertNotNull(pet);
    }
}

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
 
import static org.junit.jupiter.api.Assertions.assertEquals;
 
@DisplayName("Should pass the method parameters provided by the @CsvSource annotation")
class CsvSourceExampleTest {
 
    @DisplayName("Should calculate the correct sum")
    @ParameterizedTest(name = "{index} => a={0}, b={1}, sum={2}")
    @CsvSource({
            "1, 1, 2",
            "2, 3, 5"
    })
    void sum(int a, int b, int sum) {
        assertEquals(sum, a + b);
    }
}import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
 
import java.util.stream.Stream;
 
import static org.junit.jupiter.api.Assertions.assertEquals;
 
@DisplayName("Should pass the method parameters provided by the sumProvider() method")
class MethodSourceExampleTest {
 
    @DisplayName("Should calculate the correct sum")
    @ParameterizedTest(name = "{index} => a={0}, b={1}, sum={2}")
    void sum(int a, int b, int sum) {
        assertEquals(sum, a + b);
    }
 
    private static Stream<Arguments> sumProvider() {
        return Stream.of(
                Arguments.of(1, 1, 2),
                Arguments.of(2, 3, 5)
        );
    }
}


==============================================================================================================
stages:
- dependency_scanning
- maven-build
- sonar
- maven-deploy
- publish-doc

cache:
    paths:
      - .m2/

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=.m2"

maven-build:
  image: maven:3-jdk-8
  stage: maven-build
  script: "mvn clean verify javadoc:javadoc -B"
  artifacts:
    paths:
      - target/
 
dependency_scanning:
  image: docker:stable
  stage: dependency_scanning
  variables:
    DOCKER_DRIVER: overlay2
  allow_failure: true
  services:
    - docker:stable-dind
  script:
    - export SP_VERSION=$(echo "$CI_SERVER_VERSION" | sed 's/^\([0-9]*\)\.\([0-9]*\).*/\1-\2-stable/')
    - docker run
        --env DEP_SCAN_DISABLE_REMOTE_CHECKS="${DEP_SCAN_DISABLE_REMOTE_CHECKS:-false}"
        --volume "$PWD:/code"
        --volume /var/run/docker.sock:/var/run/docker.sock
        "registry.gitlab.com/gitlab-org/security-products/dependency-scanning:$SP_VERSION" /code
  artifacts:
    paths: [gl-dependency-scanning-report.json]
    
pages:
  image: maven:3-jdk-8
  stage: publish-doc
  script:
    - mkdir public
    - cp -r target/site/apidocs/* public/
  artifacts:
    paths:
    - public
  only:
    - master

ossrh-staging:
 stage: maven-deploy
 image: maven:3-jdk-8
 except:
  - features/ossrh
 variables:
  GPG_TTY: "`tty`"
 script:
  - echo "$GPG_PRIVATE_KEY" | gpg --batch --import --passphrase "$GPG_PASSPHRASE" -
  - mvn deploy -s settings.xml
 only:
  - master

sonar:
  image: maven:3-jdk-8
  stage: sonar
  script: "mvn sonar:sonar -s settings.xml"

==============================================================================================================
# To build docker build -t sonar-scanner .
FROM openjdk:11.0.1-jre

LABEL maintainer="Jérôme TAMA <j.tama@groupeonepoint.com>"

WORKDIR /data

RUN curl --insecure -o ./node-v11.6.0-linux-x64.tar.xz -L https://nodejs.org/dist/v11.6.0/node-v11.6.0-linux-x64.tar.xz \
	&& mkdir /usr/local/lib/nodejs \
	&& tar -xJvf node-v11.6.0-linux-x64.tar.xz -C /usr/local/lib/nodejs \ 
	&& mv /usr/local/lib/nodejs/node-v11.6.0-linux-x64 /usr/local/lib/nodejs/node-v11.6.0 \
	&& rm node-v11.6.0-linux-x64.tar.xz \
	&& chmod -R a+x /usr/local/lib/nodejs/node-v11.6.0 \
	&& curl --insecure -o ./sonarscanner.zip -L https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-3.2.0.1227-linux.zip \
	&& unzip sonarscanner.zip \
	&& rm sonarscanner.zip \
	&& mv sonar-scanner-3.2.0.1227-linux /usr/local/lib/sonar-scanner

ENV SONAR_RUNNER_HOME=/usr/local/lib/sonar-scanner
ENV PATH $PATH:/usr/local/lib/sonar-scanner/bin:/usr/local/lib/nodejs/node-v11.6.0/bin
ENV NODEJS_HOME /usr/local/lib/nodejs/node-v11.6.0/bin

CMD sonar-scanner

==============================================================================================================
import com.jcraft.jsch.*;
import fr.onepoint.universaltester.UniversalTesterException;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.text.MessageFormat.format;

public class CloseableSSH implements Closeable, SSH {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSH.class);

    private final Session session;

    public CloseableSSH(String host, String user, String password, int port) {
        LOGGER.debug("Creating new SSH connection to {}@{}:{}", user, host, port);
        JSch jsch = new JSch();
        try {
            session = jsch.getSession(user, host, port);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(30000);
        } catch (JSchException e) {
            throw new UniversalTesterException(e);
        }

    }

    @Override
    public String exec(String command) {
        LOGGER.debug("Executing command {} to {}", command, session.getHost());
        ChannelExec channel = null;
        try {
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            channel.setInputStream(null);
            channel.connect();
            return IOUtils.toString(channel.getInputStream(), StandardCharsets.UTF_8);
        } catch (JSchException | IOException e) {
            LOGGER.error("Fail to execute command {} on {}", command, session.getHost());
            throw new UniversalTesterException(e);
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    @Override
    public Path downloadFile(String distantLocation, Path targetDir) {
        createDirIfNotExists(targetDir);
        LOGGER.debug("Downloading file {} to {}", distantLocation, session.getHost());
        ChannelSftp channel = null;
        try {
            channel = (ChannelSftp) session.openChannel("sftp");
            channel.setInputStream(null);
            channel.connect();
            Path target = targetDir.resolve(FilenameUtils.getName(channel.realpath(distantLocation)));
            channel.get(distantLocation, target.toString());
            LOGGER.debug("File {} downloaded", target);
            return target;
        } catch (JSchException | SftpException e) {
            LOGGER.error("Failed to download file {}", distantLocation);
            throw new UniversalTesterException(e);
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    private void createDirIfNotExists(Path targetDir) {
        File targetDirFile = targetDir.toFile();
        if(!targetDirFile.exists() && !targetDirFile.mkdirs()){
            throw new UncheckedIOException(new IOException(format("Fail to create directory {0}", targetDir)));
        }
    }

    @Override
    public void upload(Path toUpload, String distantRepo) {
        try (InputStream inputStream = Files.newInputStream(toUpload)) {
            this.upload(inputStream, FilenameUtils.getName(toUpload.toString()), distantRepo);
        } catch (IOException e) {
            throw new UniversalTesterException(e);
        }
    }

    private void upload(InputStream toUpload, String filename, String distantRepo) {
        LOGGER.debug("Upload input stream to {}:{}", session.getHost(), distantRepo);
        ChannelSftp channel = null;
        try {
            channel = (ChannelSftp) session.openChannel("sftp");
            channel.setInputStream(null);
            channel.connect();
            String target = distantRepo + filename;
            channel.put(toUpload, target);
            LOGGER.debug("File uploaded to {}", target);
        } catch (JSchException | SftpException e) {
            LOGGER.error("Failed to upload file {}", filename);
            throw new UniversalTesterException(e);
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    @Override
    public void close() {
        if (session != null && session.isConnected()) {
            session.disconnect();
        }
    }
}


import fr.onepoint.universaltester.UniversalTesterException;

import java.nio.file.Path;

public interface SSH {

    /**
     * Run to remote connection a command line.
     * @param command The command line to execute.
     * @return The message printed on standard output during execution.
     * @throws UniversalTesterException When an error occurred during execution.
     */
    String exec(String command);

    /**
     * Copy a file from remote connection to local file system.
     * @param distantLocation The path of the file on the remote file system. It can be relative or absolute.
     * @param targetDir The directory on the local file system to store the downloaded file.
     * @return The path of the copied file on the local file system.
     */
    Path downloadFile(String distantLocation, Path targetDir);

    /**
     * Copy a file frmo the local file system to the remote file system.
     * @param toUpload The file to upload.
     * @param distantRepo The path of the directory on the remote file system to store the uploaded file.
     */
    void upload(Path toUpload, String distantRepo);

}


import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SSHManager {

    private SSHManager(){
        //To avoid instantiation
    }

    private static Map<String, CloseableSSH> sshByHost = new HashMap<>();

    /**
     * Allows to get already opened SSH connection to the specified target
     * @param host the host of the target machine
     * @param user the user used to connect
     * @param port the target port
     * @return An optional valued with the connection if it exists, an empty optional otherwise
     */
    public static Optional<SSH> getSSH(String host, String user, int port){
        String key = getSSHKey(host, user, port);
        return Optional.ofNullable(sshByHost.get(key));
    }

    /**
     * Allows to get and manage an SSH connection to the specified target.
     * If there is already a connection matching the credentials, it will be returned.
     * A new SSH connection will be created otherwise.
     * @param host the host of the target machine
     * @param user the user used to connect
     * @param password the password to use to connect
     * @param port the target port
     * @return An ssh connection matching the credentials.
     */
    public static SSH getSSH(String host, String user, String password, int port) {
        Optional<SSH> ssh = getSSH(host,user,port);
        if(ssh.isPresent()){
            return ssh.get();
        }
        CloseableSSH newSSh = new CloseableSSH(host, user, password, port);
        sshByHost.put(getSSHKey(host, user, port), newSSh);
        return newSSh;
    }

    private static String getSSHKey(String host, String user, int port){
        return String.join(":", host, user, String.valueOf(port));
    }

    /**
     * Close specified ssh connection and remove it from manager.
     * Will do nothing if the connection doesn't exists
     * @param host the host of the ssh connection
     * @param user the user connected with
     * @param port the port connected into
     */
    public static void close(String host, String user, int port){
        String key = getSSHKey(host, user, port);
        CloseableSSH ssh = sshByHost.get(key);
        if(ssh != null){
            ssh.close();
            sshByHost.remove(key);
        }
    }


}

import ch.qos.logback.core.LogbackException;
import ch.qos.logback.core.status.Status;
import ch.qos.logback.core.status.StatusListener;

public class StrictConfigurationWarningStatusListener implements StatusListener {
    @Override
    public void addStatusEvent(Status status) {
        if (status.getEffectiveLevel() == Status.WARN) {
            // might want to consider how best to evaluate whether this is the relevant event
            // this approach is bound to a string and hence will no longer work if Logback changes this event message
            if (status.getMessage().endsWith("occurs multiple times on the classpath.")) {
                throw new LogbackException(status.getMessage());
            }
        }
    }
}


mport io.github.glytching.tranquil.exception.MappingException;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

public interface MappingProvider {

  /**
   * Parse the given {@code source} into a {@link Map}.
   *
   * @param source a source string
   * @return a {@link Map} representation of the given {@code source}
   */
  List<Map<String, Object>> deserialize(String source);

  /**
   * Parse a json string encapsulated in the given {@code sourceStream} into a {@link Map}.
   *
   * @param sourceStream an input stream containing a json string
   * @param charset
   * @return a {@link Map} representation of the given {@code sourceStream}
   */
  List<Map<String, Object>> deserialize(InputStream sourceStream, String charset);

  /**
   * Convert the {@code source} to a string.
   *
   * @param source the object to be converted
   * @return a string representation of the given {@code source}
   */
  String serialize(List<Map<String, Object>> source) throws MappingException;

  /**
   * Convert the {@code source} to an instance of the given {@code targetType}.
   *
   * @param source the object to be converted
   * @param targetType the type to which the given {@code source} should be converted
   * @param <T> the mapped result type
   * @return the converted object
   */
  <T> T serialize(List<Map<String, Object>> source, Class<T> targetType);

  /**
   * Convert the {@code source} to an instance of the given {@code targetType}.
   *
   * @param source the object to be converted
   * @param targetType the type to which the given {@code source} should be converted
   * @param <T> the mapped result type
   * @return the converted object
   */
  <T> T serialize(List<Map<String, Object>> source, TypeRef<T> targetType);
}
==============================================================================================================
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class SubscriptionStreamCompletedEvent extends SubscriptionEvent {

  public SubscriptionStreamCompletedEvent(String subscriptionKey) {
    super(SubscriptionEventType.STREAM_COMPLETED_EVENT, subscriptionKey);
  }

  @SuppressWarnings("EqualsWhichDoesntCheckParameterClass")
  @Override
  public boolean equals(Object obj) {
    return EqualsBuilder.reflectionEquals(this, obj);
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this);
  }
}

import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * A simple (crude, even) stop watch implementation. Yes, there are plenty of existing stop watch
 * implementations out there but we need lap/split features.
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class StopWatch {

  private final org.apache.commons.lang3.time.StopWatch main;
  private Optional<org.apache.commons.lang3.time.StopWatch> split;

  private StopWatch(boolean withSplits) {
    this.main = new org.apache.commons.lang3.time.StopWatch();
    main.start();
    if (withSplits) {
      this.split = Optional.of(new org.apache.commons.lang3.time.StopWatch());
      split.get().start();
    }
  }

  /**
   * Create and start a {@link StopWatch} instance.
   *
   * @return a {@link StopWatch} instance which has already been started
   */
  public static StopWatch start() {
    return new StopWatch(false);
  }

  /**
   * Create and start a {@link StopWatch} instance which can be used to gather split/lap times.
   *
   * @return a {@link StopWatch} instance which has already been started
   */
  public static StopWatch startForSplits() {
    return new StopWatch(true);
  }

  /**
   * Create a split. Note: this will throw an exception if called on a {@link StopWatch} instance
   * which was not started with {@link #startForSplits()}.
   *
   * @return the time since this watch was last split or the time since this watch was started if
   *     this is the first split
   */
  public long split() {
    if (split == null || !split.isPresent()) {
      throw new IllegalStateException(
          "You cannot split a StopWatch which has not been configured withSplits=true!");
    }

    split.get().stop();
    long time = split.get().getTime(TimeUnit.MILLISECONDS);
    split.get().reset();
    split.get().start();
    return time;
  }

  /**
   * Stop this watch.
   *
   * @return the time since this watch was started or if this watch was created for splits the time
   *     since the last split
   */
  public long stop() {
    main.stop();
    if (split != null) {
      split.get().stop();
    }
    return main.getTime(TimeUnit.MILLISECONDS);
  }
}


https://github.com/glytching/dragoman/blob/master/src/main/java/io/github/glytching/dragoman/store/mongo/MongoProviderImpl.java
==============================================================================================================
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;

import javax.swing.text.Segment;
import javax.swing.text.TabExpander;
import javax.swing.text.Utilities;

import org.rosuda.JGR.toolkit.JGRPrefs;

/**
 * Class with several utility functions used by jEdit's syntax colorizing
 * subsystem.
 * 
 * @author Slava Pestov
 * @version $Id: SyntaxUtilities.java,v 1.9 1999/12/13 03:40:30 sp Exp $
 */
public class SyntaxUtilities {
	/**
	 * Checks if a subregion of a <code>Segment</code> is equal to a string.
	 * 
	 * @param ignoreCase
	 *            True if case should be ignored, false otherwise
	 * @param text
	 *            The segment
	 * @param offset
	 *            The offset into the segment
	 * @param match
	 *            The string to match
	 */
	public static boolean regionMatches(boolean ignoreCase, Segment text, int offset, String match) {
		int length = offset + match.length();
		char[] textArray = text.array;
		if (length > text.offset + text.count)
			return false;
		for (int i = offset, j = 0; i < length; i++, j++) {
			char c1 = textArray[i];
			char c2 = match.charAt(j);
			if (ignoreCase) {
				c1 = Character.toUpperCase(c1);
				c2 = Character.toUpperCase(c2);
			}
			if (c1 != c2)
				return false;
		}
		return true;
	}

	/**
	 * Checks if a subregion of a <code>Segment</code> is equal to a character
	 * array.
	 * 
	 * @param ignoreCase
	 *            True if case should be ignored, false otherwise
	 * @param text
	 *            The segment
	 * @param offset
	 *            The offset into the segment
	 * @param match
	 *            The character array to match
	 */
	public static boolean regionMatches(boolean ignoreCase, Segment text, int offset, char[] match) {
		int length = offset + match.length;
		char[] textArray = text.array;
		if (length > text.offset + text.count)
			return false;
		for (int i = offset, j = 0; i < length; i++, j++) {
			char c1 = textArray[i];
			char c2 = match[j];
			if (ignoreCase) {
				c1 = Character.toUpperCase(c1);
				c2 = Character.toUpperCase(c2);
			}
			if (c1 != c2)
				return false;
		}
		return true;
	}

	/**
	 * Returns the default style table. This can be passed to the
	 * <code>setStyles()</code> method of <code>SyntaxDocument</code> to use
	 * the default syntax styles.
	 */
	public static SyntaxStyle[] getDefaultSyntaxStyles() {
		SyntaxStyle[] styles = new SyntaxStyle[Token.ID_COUNT];

		styles[Token.COMMENT1] = new SyntaxStyle(JGRPrefs.COMMENTColor, JGRPrefs.COMMENT_IT, false);
		styles[Token.COMMENT2] = new SyntaxStyle(JGRPrefs.COMMENTColor, JGRPrefs.COMMENT_IT, false);
		styles[Token.KEYWORD1] = new SyntaxStyle(JGRPrefs.KEYWORDColor, false, JGRPrefs.KEYWORD_BOLD);
		styles[Token.KEYWORD2] = new SyntaxStyle(JGRPrefs.OBJECTColor, JGRPrefs.OBJECT_IT, false);
		styles[Token.KEYWORD3] = new SyntaxStyle(Color.darkGray, false, false); //not used?
		styles[Token.LITERAL1] = new SyntaxStyle(JGRPrefs.QUOTEColor, false, false);
		styles[Token.LITERAL2] = new SyntaxStyle(JGRPrefs.KEYWORDColor, false, true);
		styles[Token.LABEL] = new SyntaxStyle(new Color(0x990033), false, true);//not used?
		styles[Token.OPERATOR] = new SyntaxStyle(Color.black, false, true);
		styles[Token.INVALID] = new SyntaxStyle(Color.red, false, true);

		return styles;
	}

	/**
	 * Paints the specified line onto the graphics context. Note that this
	 * method munges the offset and count values of the segment.
	 * 
	 * @param line
	 *            The line segment
	 * @param tokens
	 *            The token list for the line
	 * @param styles
	 *            The syntax style list
	 * @param expander
	 *            The tab expander used to determine tab stops. May be null
	 * @param gfx
	 *            The graphics context
	 * @param x
	 *            The x co-ordinate
	 * @param y
	 *            The y co-ordinate
	 * @return The x co-ordinate, plus the width of the painted string
	 */
	public static int paintSyntaxLine(Segment line, Token tokens, SyntaxStyle[] styles, TabExpander expander, Graphics gfx, int x, int y) {
		Font defaultFont = gfx.getFont();
		Color defaultColor = gfx.getColor();

		int offset = 0;
		for (;;) {
			byte id = tokens.id;
			if (id == Token.END)
				break;

			int length = tokens.length;
			if (id == Token.NULL) {
				if (!defaultColor.equals(gfx.getColor()))
					gfx.setColor(defaultColor);
				if (!defaultFont.equals(gfx.getFont()))
					gfx.setFont(defaultFont);
			} else
				styles[id].setGraphicsFlags(gfx, defaultFont);

			line.count = length;
			x = Utilities.drawTabbedText(line, x, y, gfx, expander, 0);
			line.offset += length;
			offset += length;

			tokens = tokens.next;
		}

		return x;
	}

	// private members
	private SyntaxUtilities() {
	}
}

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Toolkit;

/**
 * A simple text style class. It can specify the color, italic flag, and bold
 * flag of a run of text.
 * 
 * @author Slava Pestov
 * @version $Id: SyntaxStyle.java,v 1.6 1999/12/13 03:40:30 sp Exp $
 */
public class SyntaxStyle {
	/**
	 * Creates a new SyntaxStyle.
	 * 
	 * @param color
	 *            The text color
	 * @param italic
	 *            True if the text should be italics
	 * @param bold
	 *            True if the text should be bold
	 */
	public SyntaxStyle(Color color, boolean italic, boolean bold) {
		this.color = color;
		this.italic = italic;
		this.bold = bold;
	}

	/**
	 * Returns the color specified in this style.
	 */
	public Color getColor() {
		return color;
	}

	/**
	 * Returns true if no font styles are enabled.
	 */
	public boolean isPlain() {
		return !(bold || italic);
	}

	/**
	 * Returns true if italics is enabled for this style.
	 */
	public boolean isItalic() {
		return italic;
	}

	/**
	 * Returns true if boldface is enabled for this style.
	 */
	public boolean isBold() {
		return bold;
	}

	/**
	 * Returns the specified font, but with the style's bold and italic flags
	 * applied.
	 */
	public Font getStyledFont(Font font) {
		if (font == null)
			throw new NullPointerException("font param must not" + " be null");
		lastStyledFont = new Font(font.getFamily(), (bold ? Font.BOLD : 0) | (italic ? Font.ITALIC : 0), font.getSize());
		return lastStyledFont;
	}

	/**
	 * Returns the font metrics for the styled font.
	 */
	public FontMetrics getFontMetrics(Font font) {
		if (font == null)
			throw new NullPointerException("font param must not" + " be null");
		lastStyledFont = new Font(font.getFamily(), (bold ? Font.BOLD : 0) | (italic ? Font.ITALIC : 0), font.getSize());
		fontMetrics = Toolkit.getDefaultToolkit().getFontMetrics(lastStyledFont);
		return fontMetrics;
	}

	/**
	 * Sets the foreground color and font of the specified graphics context to
	 * that specified in this style.
	 * 
	 * @param gfx
	 *            The graphics context
	 * @param font
	 *            The font to add the styles to
	 */
	public void setGraphicsFlags(Graphics gfx, Font font) {
		Font _font = getStyledFont(font);
		gfx.setFont(_font);
		gfx.setColor(color);
	}

	/**
	 * Returns a string representation of this object.
	 */
	public String toString() {
		return getClass().getName() + "[color=" + color + (italic ? ",italic" : "") + (bold ? ",bold" : "") + "]";
	}

	// private members
	private Color color;

	private boolean italic;

	private boolean bold;

	private Font lastStyledFont;

	private FontMetrics fontMetrics;
}


spring.kafka.producer.value-serializer=org.springframework.kafka.support.serializer.JsonSerializer
spring.kafka.producer.properties.spring.json.type.mapping=cat:com.mycat.Cat,hat:com.myhat.Hat


senderProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
senderProps.put(JsonSerializer.TYPE_MAPPINGS, "cat:com.mycat.Cat, hat:com.myhat.hat");
...
consumerProps.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
consumerProps.put(JsonDeSerializer.TYPE_MAPPINGS, "cat:com.yourcat.Cat, hat:com.yourhat.hat");



producerProps.put(DelegatingSerializer.SERIALIZATION_SELECTOR_CONFIG,
    "thing1:com.example.MyThing1Serializer, thing2:com.example.MyThing2Serializer")

consumerProps.put(DelegatingDeserializer.SERIALIZATION_SELECTOR_CONFIG,
    "thing1:com.example.MyThing1Deserializer, thing2:com.example.MyThing2Deserializer")
==============================================================================================================
@Bean
public ConcurrentKafkaListenerContainerFactory kafkaListenerContainerFactory() {
    ConcurrentKafkaListenerContainerFactory<String, String> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
    ...
    factory.getContainerProperties().setIdleEventInterval(60000L);
    ...
    return factory;
}
@Bean
public KafkaMessageListenerContainer(ConsumerFactory<String, String> consumerFactory) {
    ContainerProperties containerProps = new ContainerProperties("topic1", "topic2");
    ...
    containerProps.setIdleEventInterval(60000L);
    ...
    KafkaMessageListenerContainer<String, String> container = new KafKaMessageListenerContainer<>(...);
    return container;
}


public class Listener {

    @KafkaListener(id = "qux", topics = "annotated")
    public void listen4(@Payload String foo, Acknowledgment ack) {
        ...
    }

    @EventListener(condition = "event.listenerId.startsWith('qux-')")
    public void eventHandler(ListenerContainerIdleEvent event) {
        ...
    }
}
==============================================================================================================
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*\
   G E N E R A T O R   C R A F T E D
\*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/



import java.io.Serializable;

import java.util.Collection;

/**
 * Helper to replace reflective array access.
 */
interface ArrayType<T> {
    @SuppressWarnings("unchecked")
    static <T> ArrayType<T> obj() { return (ArrayType<T>) ObjectArrayType.INSTANCE; }

    Class<T> type();
    int lengthOf(Object array);
    T getAt(Object array, int index);

    Object empty();
    void setAt(Object array, int index, T value) throws ClassCastException;
    Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size);

    @SuppressWarnings("unchecked")
    static <T> ArrayType<T> of(Object array)  { return of((Class<T>) array.getClass().getComponentType()); }
    static <T> ArrayType<T> of(Class<T> type) { return !type.isPrimitive() ? obj() : ofPrimitive(type); }
    @SuppressWarnings("unchecked")
    static <T> ArrayType<T> ofPrimitive(Class<T> type) {
        if (boolean.class == type) {
            return (ArrayType<T>) BooleanArrayType.INSTANCE;
        } else if (byte.class == type) {
            return (ArrayType<T>) ByteArrayType.INSTANCE;
        } else if (char.class == type) {
            return (ArrayType<T>) CharArrayType.INSTANCE;
        } else if (double.class == type) {
            return (ArrayType<T>) DoubleArrayType.INSTANCE;
        } else if (float.class == type) {
            return (ArrayType<T>) FloatArrayType.INSTANCE;
        } else if (int.class == type) {
            return (ArrayType<T>) IntArrayType.INSTANCE;
        } else if (long.class == type) {
            return (ArrayType<T>) LongArrayType.INSTANCE;
        } else if (short.class == type) {
            return (ArrayType<T>) ShortArrayType.INSTANCE;
        } else {
            throw new IllegalArgumentException(String.valueOf(type));
        }
    }

    default Object newInstance(int length) { return copy(empty(), length); }

    /** System.arrayCopy with same source and destination */
    default Object copyRange(Object array, int from, int to) {
        final int length = to - from;
        return copy(array, length, from, 0, length);
    }

    /** Repeatedly group an array into equal sized sub-trees */
    default Object grouped(Object array, int groupSize) {
        final int arrayLength = lengthOf(array);
        final Object results = obj().newInstance(1 + ((arrayLength - 1) / groupSize));
        obj().setAt(results, 0, copyRange(array, 0, groupSize));

        for (int start = groupSize, i = 1; start < arrayLength; i++) {
            final int nextLength = Math.min(groupSize, arrayLength - (i * groupSize));
            obj().setAt(results, i, copyRange(array, start, start + nextLength));
            start += nextLength;
        }

        return results;
    }

    /** clone the source and set the value at the given position */
    default Object copyUpdate(Object array, int index, T element) {
        final Object copy = copy(array, index + 1);
        setAt(copy, index, element);
        return copy;
    }

    default Object copy(Object array, int minLength) {
        final int arrayLength = lengthOf(array);
        final int length = Math.max(arrayLength, minLength);
        return copy(array, length, 0, 0, arrayLength);
    }

    /** clone the source and keep everything after the index (pre-padding the values with null) */
    default Object copyDrop(Object array, int index) {
        final int length = lengthOf(array);
        return copy(array, length, index, index, length - index);
    }

    /** clone the source and keep everything before and including the index */
    default Object copyTake(Object array, int lastIndex) {
        return copyRange(array, 0, lastIndex + 1);
    }

    /** Create a single element array */
    default Object asArray(T element) {
        final Object result = newInstance(1);
        setAt(result, 0, element);
        return result;
    }

    /** Store the content of an iterator in an array */
    static Object[] asArray(java.util.Iterator<?> it, int length) {
        final Object[] array = new Object[length];
        for (int i = 0; i < length; i++) {
            array[i] = it.next();
        }
        return array;
    }

    @SuppressWarnings("unchecked")
    static <T> T asPrimitives(Class<?> primitiveClass, Iterable<?> values) {
        final Object[] array = Array.ofAll(values).toJavaArray();
        final ArrayType<T> type = of((Class<T>) primitiveClass);
        final Object results = type.newInstance(array.length);
        for (int i = 0; i < array.length; i++) {
            type.setAt(results, i, (T) array[i]);
        }
        return (T) results;
    }

    final class BooleanArrayType implements ArrayType<Boolean>, Serializable {
        private static final long serialVersionUID = 1L;
        static final BooleanArrayType INSTANCE = new BooleanArrayType();
        static final boolean[] EMPTY = new boolean[0];

        private static boolean[] cast(Object array) { return (boolean[]) array; }

        @Override
        public Class<Boolean> type() { return boolean.class; }

        @Override
        public boolean[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Boolean getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Boolean value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new boolean[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final boolean[] result = new boolean[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class ByteArrayType implements ArrayType<Byte>, Serializable {
        private static final long serialVersionUID = 1L;
        static final ByteArrayType INSTANCE = new ByteArrayType();
        static final byte[] EMPTY = new byte[0];

        private static byte[] cast(Object array) { return (byte[]) array; }

        @Override
        public Class<Byte> type() { return byte.class; }

        @Override
        public byte[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Byte getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Byte value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new byte[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final byte[] result = new byte[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class CharArrayType implements ArrayType<Character>, Serializable {
        private static final long serialVersionUID = 1L;
        static final CharArrayType INSTANCE = new CharArrayType();
        static final char[] EMPTY = new char[0];

        private static char[] cast(Object array) { return (char[]) array; }

        @Override
        public Class<Character> type() { return char.class; }

        @Override
        public char[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Character getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Character value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new char[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final char[] result = new char[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class DoubleArrayType implements ArrayType<Double>, Serializable {
        private static final long serialVersionUID = 1L;
        static final DoubleArrayType INSTANCE = new DoubleArrayType();
        static final double[] EMPTY = new double[0];

        private static double[] cast(Object array) { return (double[]) array; }

        @Override
        public Class<Double> type() { return double.class; }

        @Override
        public double[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Double getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Double value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new double[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final double[] result = new double[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class FloatArrayType implements ArrayType<Float>, Serializable {
        private static final long serialVersionUID = 1L;
        static final FloatArrayType INSTANCE = new FloatArrayType();
        static final float[] EMPTY = new float[0];

        private static float[] cast(Object array) { return (float[]) array; }

        @Override
        public Class<Float> type() { return float.class; }

        @Override
        public float[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Float getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Float value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new float[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final float[] result = new float[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class IntArrayType implements ArrayType<Integer>, Serializable {
        private static final long serialVersionUID = 1L;
        static final IntArrayType INSTANCE = new IntArrayType();
        static final int[] EMPTY = new int[0];

        private static int[] cast(Object array) { return (int[]) array; }

        @Override
        public Class<Integer> type() { return int.class; }

        @Override
        public int[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Integer getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Integer value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new int[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final int[] result = new int[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class LongArrayType implements ArrayType<Long>, Serializable {
        private static final long serialVersionUID = 1L;
        static final LongArrayType INSTANCE = new LongArrayType();
        static final long[] EMPTY = new long[0];

        private static long[] cast(Object array) { return (long[]) array; }

        @Override
        public Class<Long> type() { return long.class; }

        @Override
        public long[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Long getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Long value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new long[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final long[] result = new long[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class ShortArrayType implements ArrayType<Short>, Serializable {
        private static final long serialVersionUID = 1L;
        static final ShortArrayType INSTANCE = new ShortArrayType();
        static final short[] EMPTY = new short[0];

        private static short[] cast(Object array) { return (short[]) array; }

        @Override
        public Class<Short> type() { return short.class; }

        @Override
        public short[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Short getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Short value) throws ClassCastException {
            if (value != null) {
                cast(array)[index] = value;
            } else {
                throw new ClassCastException();
            }
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new short[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final short[] result = new short[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }

    final class ObjectArrayType implements ArrayType<Object>, Serializable {
        private static final long serialVersionUID = 1L;
        static final ObjectArrayType INSTANCE = new ObjectArrayType();
        static final Object[] EMPTY = new Object[0];

        private static Object[] cast(Object array) { return (Object[]) array; }

        @Override
        public Class<Object> type() { return Object.class; }

        @Override
        public Object[] empty() { return EMPTY; }

        @Override
        public int lengthOf(Object array) { return (array != null) ? cast(array).length : 0; }

        @Override
        public Object getAt(Object array, int index) { return cast(array)[index]; }

        @Override
        public void setAt(Object array, int index, Object value) {
            cast(array)[index] = value;
        }

        @Override
        public Object copy(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            return (size > 0)
                    ? copyNonEmpty(array, arraySize, sourceFrom, destinationFrom, size)
                    : new Object[arraySize];
        }
        private static Object copyNonEmpty(Object array, int arraySize, int sourceFrom, int destinationFrom, int size) {
            final Object[] result = new Object[arraySize];
            System.arraycopy(array, sourceFrom, result, destinationFrom, size); /* has to be near the object allocation to avoid zeroing out the array */
            return result;
        }
    }
}
==============================================================================================================
branches:
  only:
  - master
  - /^(\d+\.){2}(\d+){1}(\.[a-zA-Z\d]+)?$/
  - hawkular-1275
==============================================================================================================
<?xml version='1.0' encoding='utf-8'?>
<Context>
    <WatchedResource>WEB-INF/web.xml</WatchedResource>
 
 
 
    <Resource
            factory="org.apache.tomcat.jdbc.pool.DataSourceFactory"
            name="jdbc/tomcatDataSource"
            auth="Container"
            type="javax.sql.DataSource"
            initialSize="1"
            maxActive="20"
            maxIdle="3"
            minIdle="1"
            maxWait="5000"
            username="josediaz"
            password="josediaz"
            driverClassName="org.postgresql.Driver"
            validationQuery="SELECT 'OK'"
            testWhileIdle="true"
            testOnBorrow="true"
            numTestsPerEvictionRun="5"
            timeBetweenEvictionRunsMillis="30000"
            minEvictableIdleTimeMillis="60000"
            url="jdbc:postgresql://localhost:5432/uaiContacts" />
 
</Context>

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.IntegrationFlows;
import org.springframework.integration.dsl.SourcePollingChannelAdapterSpec;
import org.springframework.integration.dsl.kafka.Kafka;
import org.springframework.integration.dsl.kafka.KafkaHighLevelConsumerMessageSourceSpec;
import org.springframework.integration.dsl.support.Consumer;
import org.springframework.integration.kafka.support.ZookeeperConnect;

import de.codecentric.ebss.service.OrderEntryService;

@Configuration
public class CommoditiesReservationConsumerConfiguration {

	private Log log = LogFactory.getLog(getClass());

	@Autowired 
	private OrderEntryService orderEntryService;
	
	@Autowired
	private KafkaConfig kafkaConfig;

	@Bean
	IntegrationFlow consumer() {

		log.info("starting consumer..");

		KafkaHighLevelConsumerMessageSourceSpec messageSourceSpec = Kafka
				.inboundChannelAdapter(
						new ZookeeperConnect(this.kafkaConfig
								.getZookeeperAddress()))
				.consumerProperties(
						props -> props.put("auto.offset.reset", "smallest")
								.put("auto.commit.interval.ms", "100"))
				.addConsumer(
						"myGroup",
						metadata -> metadata
								.consumerTimeout(100)
								.topicStreamMap(
										m -> m.put(this.kafkaConfig.getTopic(),
												1)).maxMessages(1)
								.valueDecoder(String::new));

		Consumer<SourcePollingChannelAdapterSpec> endpointConfigurer = e -> e.poller(p -> p.fixedDelay(100));

		return IntegrationFlows
				.from(messageSourceSpec, endpointConfigurer)
				.<Map<String, ConcurrentHashMap<String, String>>> handle(
						(payload, headers) -> {
							payload.entrySet().forEach(
									e -> orderEntryService.createOrderEntryFromJson(e.getValue()));
							return null;
						}).get();
	}
}
==============================================================================================================
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.solr.core.query.result.FacetPage;
import org.springframework.data.solr.core.query.result.HighlightPage;
import org.springframework.data.solr.repository.Boost;
import org.springframework.data.solr.repository.Facet;
import org.springframework.data.solr.repository.Highlight;
import org.springframework.data.solr.repository.Query;
import org.springframework.data.solr.repository.SolrCrudRepository;

import com.mscharhag.solr.document.Book;

public interface BookRepository extends SolrCrudRepository<Book, String> {

	List<Book> findByName(String name);
	
	Page<Book> findByNameOrDescription(@Boost(2) String name, String description, Pageable pageable);

	@Query("name:?0")
	@Facet(fields = { "categories_txt" }, limit = 5)
	FacetPage<Book> findByNameAndFacetOnCategories(String name, Pageable page);
	
	@Highlight(prefix = "<highlight>", postfix = "</highlight>")
	HighlightPage<Book> findByDescription(String description, Pageable pageable);
	
}

import org.apache.solr.client.solrj.SolrServer;
import org.apache.solr.client.solrj.impl.HttpSolrServer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.solr.core.SolrTemplate;
import org.springframework.data.solr.repository.config.EnableSolrRepositories;

@ComponentScan
@EnableSolrRepositories("com.mscharhag.solr.repository")
public class Application {

	@Bean
	public SolrServer solrServer() {
		return new HttpSolrServer("http://localhost:8983/solr");
	}

	@Bean
	public SolrTemplate solrTemplate(SolrServer server) throws Exception {
		return new SolrTemplate(server);
	}
}
==============================================================================================================
    /**
     * This inner class configures a WebSecurityConfigurerAdapter instance for
     * the Spring Actuator web service context paths.
     * 
     * @author Matt Warman
     */
    @Configuration
    @Order(2)
    public static class ActuatorWebSecurityConfigurerAdapter
            extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            // @formatter:off
            
            http
              .antMatcher("/actuators/**")
                .authorizeRequests()
                  .anyRequest().hasRole("SYSADMIN")
              .and()
              .httpBasic()
              .and()
              .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              .and()
              .csrf()
                .disable();
            
            // @formatter:on

        }

    }
	
	import java.util.Collection;
import java.util.Date;

import org.example.ws.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * The RoleRepository interface is a Spring Data JPA data repository for Role
 * entities. The RoleRepository provides all the data access behaviors exposed
 * by <code>JpaRepository</code> and additional custom behaviors may be defined
 * in this interface.
 * 
 * @author Matt Warman
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    /**
     * Query for a collection of Role entities by the effectiveAt and expiresAt
     * attribute values. Order the collection by the value of the ordinal
     * attribute.
     * 
     * Uses the Query Method approach to search the database.
     * 
     * @param effectiveAt A Date effectiveAt attribute value.
     * @param expiresAt A Date expiresAt attribute value.
     * @return A Collection of Role entity model classes.
     */
    Collection<Role> findByEffectiveAtBeforeAndExpiresAtAfterOrExpiresAtNullOrderByOrdinalAsc(
            Date effectiveAt, Date expiresAt);

    /**
     * Query for a collection of Role entities by the effectiveAt and expiresAt
     * attribute values. Order the collection by the value of the ordinal
     * attribute.
     * 
     * Uses a Query annotated JPQL statement to search the database.
     *
     * @param effectiveAt A Date effectiveAt attribute value.
     * @return A Collection of Role entity model classes.
     */
    @Query("SELECT r FROM Role r WHERE r.effectiveAt <= :effectiveAt AND (r.expiresAt IS NULL OR r.expiresAt > :effectiveAt) ORDER BY r.ordinal ASC")
    Collection<Role> findAllEffective(@Param("effectiveAt") Date effectiveAt);

    /**
     * Query for a single Role entity by the code, effectiveAt, and expiresAt
     * attribute values.
     * 
     * Uses the Query Method approach to search the database.
     * 
     * @param code A String code attribute value.
     * @param effectiveAt A Date effectiveAt attribute value.
     * @param expiresAt A Date expiresAt attribute value.
     * @return A Role object or <code>null</code> if not found.
     */
    Role findByCodeAndEffectiveAtBeforeAndExpiresAtAfterOrExpiresAtNull(
            String code, Date effectiveAt, Date expiresAt);

    /**
     * Query for a single Role entity by the code, effectiveAt, and expiresAt
     * attribute values.
     * 
     * Uses a Query annotated JPQL statement to search the database.
     * 
     * @param code A String code attribute value.
     * @param effectiveAt A Date effectiveAt attribute value.
     * @return A Role object or <code>null</code> if not found.
     */
    @Query("SELECT r FROM Role r WHERE r.code = :code AND r.effectiveAt <= :effectiveAt AND (r.expiresAt IS NULL OR r.expiresAt > :effectiveAt)")
    Role findByCodeAndEffective(@Param("code") String code,
            @Param("effectiveAt") Date effectiveAt);

}
==============================================================================================================
import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;

import org.apache.commons.io.FilenameUtils;
import org.springframework.util.Assert;

import com.google.common.io.Files;

public class ImageHelper {

	/** 背景颜色 */
	private static final Color BACKGROUND_COLOR = Color.white;

	/** 目标图片品质(取值范围: 0 - 100) */
	private static final int DEST_QUALITY = 88;

	public static void zoom(File srcFile, File destFile, int destWidth, int destHeight) {
		Assert.notNull(srcFile);
		Assert.notNull(destFile);
		Assert.state(destWidth > 0);
		Assert.state(destHeight > 0);

		Graphics2D graphics2D = null;
		ImageOutputStream imageOutputStream = null;
		ImageWriter imageWriter = null;
		try {
			BufferedImage srcBufferedImage = ImageIO.read(srcFile);
			int srcWidth = srcBufferedImage.getWidth();
			int srcHeight = srcBufferedImage.getHeight();
			
			if(srcWidth < destWidth || srcHeight < destHeight) {
				Files.copy(srcFile, destFile);
				return;
			}
			
			int width = destWidth;
			int height = destHeight;
			if (srcHeight >= srcWidth) {
				width = (int) Math.round(((destHeight * 1.0 / srcHeight) * srcWidth));
			} else {
				height = (int) Math.round(((destWidth * 1.0 / srcWidth) * srcHeight));
			}
			BufferedImage destBufferedImage = new BufferedImage(destWidth, destHeight, BufferedImage.TYPE_INT_RGB);
			graphics2D = destBufferedImage.createGraphics();
			graphics2D.setBackground(BACKGROUND_COLOR);
			graphics2D.clearRect(0, 0, destWidth, destHeight);
			graphics2D.drawImage(srcBufferedImage.getScaledInstance(width, height, Image.SCALE_SMOOTH),
					(destWidth / 2) - (width / 2), (destHeight / 2) - (height / 2), null);

			imageOutputStream = ImageIO.createImageOutputStream(destFile);
			imageWriter = ImageIO.getImageWritersByFormatName(FilenameUtils.getExtension(destFile.getName())).next();
			imageWriter.setOutput(imageOutputStream);
			ImageWriteParam imageWriteParam = imageWriter.getDefaultWriteParam();
			imageWriteParam.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
			imageWriteParam.setCompressionQuality((float) (DEST_QUALITY / 100.0));
			imageWriter.write(null, new IIOImage(destBufferedImage, null, null), imageWriteParam);
			imageOutputStream.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (graphics2D != null) {
				graphics2D.dispose();
			}
			if (imageWriter != null) {
				imageWriter.dispose();
			}
			if (imageOutputStream != null) {
				try {
					imageOutputStream.close();
				} catch (IOException e) {
				}
			}
		}

	}

}

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;

public class QrCodeHelper {
	public static void writeToFile(String contents, int width, int height, File file) {
		Map<EncodeHintType, Object> hints = new HashMap<>();
		hints.put(EncodeHintType.CHARACTER_SET, "utf-8");

		try {
			BitMatrix bitMatrix = new MultiFormatWriter().encode(contents, BarcodeFormat.QR_CODE, width, height, hints);
			writeToFile(bitMatrix, "png", file);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void writeToStream(String contents, int width, int height, OutputStream outputStream) {
		Map<EncodeHintType, Object> hints = new HashMap<>();
		hints.put(EncodeHintType.CHARACTER_SET, "utf-8");

		try {
			BitMatrix bitMatrix = new MultiFormatWriter().encode(contents, BarcodeFormat.QR_CODE, width, height, hints);
			writeToStream(bitMatrix, "png", outputStream);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static final int BLACK = 0xFF000000;
	private static final int WHITE = 0xFFFFFFFF;

	private static BufferedImage toBufferedImage(BitMatrix matrix) {
		int width = matrix.getWidth();
		int height = matrix.getHeight();
		BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		for (int x = 0; x < width; x++) {
			for (int y = 0; y < height; y++) {
				image.setRGB(x, y, matrix.get(x, y) ? BLACK : WHITE);
			}
		}
		return image;
	}

	private static void writeToFile(BitMatrix matrix, String format, File file) throws IOException {
		BufferedImage image = toBufferedImage(matrix);
		if (!ImageIO.write(image, format, file)) {
			throw new IOException("Could not write an image of format " + format + " to " + file);
		}
	}

	private static void writeToStream(BitMatrix matrix, String format, OutputStream stream) throws IOException {
		BufferedImage image = toBufferedImage(matrix);
		if (!ImageIO.write(image, format, stream)) {
			throw new IOException("Could not write an image of format " + format);
		}
	}
}
==============================================================================================================
import java.util.Collection;
import java.util.Set;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.infinispan.commons.api.BasicCache;
import org.springframework.util.Assert;

public class ShiroCache<K, V> implements Cache<K, V> {

	private final BasicCache<K, V> nativeCache;

	public ShiroCache(final BasicCache<K, V> nativeCache) {
		Assert.notNull(nativeCache, "A non-null Infinispan cache implementation is required");
		this.nativeCache = nativeCache;
	}

	@Override
	public V get(K key) throws CacheException {
		return this.nativeCache.get(key);
	}

	@Override
	public V put(K key, V value) throws CacheException {
		return this.nativeCache.put(key, value);
	}

	@Override
	public V remove(K key) throws CacheException {
		return this.nativeCache.remove(key);
	}

	@Override
	public void clear() throws CacheException {
		this.nativeCache.clear();
	}

	@Override
	public int size() {
		return this.nativeCache.size();
	}

	@Override
	public Set<K> keys() {
		return this.nativeCache.keySet();
	}

	@Override
	public Collection<V> values() {
		return this.nativeCache.values();
	}

}
==============================================================================================================
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.SessionValidationScheduler;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.whenling.module.security.shiro.cache.infinispan.ShiroCacheManager;

/**
 * 安全配置
 * 
 * @作者 孔祥溪
 * @博客 http://ken.whenling.com
 * @创建时间 2016年3月1日 下午7:08:55
 */
@Configuration
public class SecurityConfiguration {

	@Value("#{T(org.apache.shiro.codec.Base64).decode('asdqwe123')}")
	private byte[] cipherKey;

	@Bean
	public SecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setCacheManager(shiroCacheManager());
//		securityManager.setSessionManager(sessionManager());
//		securityManager.setRememberMeManager(rememberMeManager());
		// securityManager.setRealm(databaseRealm());
		return securityManager;
	}

	@Bean
	public RememberMeManager rememberMeManager() {
		CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
		rememberMeManager.setCipherKey(cipherKey);
		rememberMeManager.setCookie(rememberMeCookie());
		return rememberMeManager;
	}

	// @Bean
	// public Cookie sessionIdCookie() {
	// SimpleCookie cookie = new SimpleCookie("sid");
	// cookie.setMaxAge(-1);
	// return cookie;
	// }

	@Bean
	public Cookie rememberMeCookie() {
		SimpleCookie cookie = new SimpleCookie("rememberMe");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(31536000);
		return cookie;
	}

	@Bean
	public SessionManager sessionManager() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(1000 * 60 * 30);
		sessionManager.setDeleteInvalidSessions(true);
		sessionManager.setSessionValidationSchedulerEnabled(true);
		SessionValidationScheduler sessionValidationScheduler = new ExecutorServiceSessionValidationScheduler(sessionManager);
		sessionManager.setSessionValidationScheduler(sessionValidationScheduler);
		sessionManager.setSessionDAO(sessionDAO());
//		sessionManager.setSessionIdCookieEnabled(true);
//		sessionManager.setSessionIdCookie(sessionIdCookie());
		return sessionManager;
	}

	@Bean
	public SessionDAO sessionDAO() {
		EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
		sessionDAO.setActiveSessionsCacheName("sessionCache");
		sessionDAO.setSessionIdGenerator(sessionIdGenerator());
		return sessionDAO;
	}

	@Bean
	public SessionIdGenerator sessionIdGenerator() {
		JavaUuidSessionIdGenerator sessionIdGenerator = new JavaUuidSessionIdGenerator();
		return sessionIdGenerator;
	}

	@Bean
	public MethodInvokingFactoryBean setSecurityManager() {
		MethodInvokingFactoryBean factoryBean = new MethodInvokingFactoryBean();
		factoryBean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
		factoryBean.setArguments(new Object[] { securityManager() });
		return factoryBean;
	}

	@Bean(name = "lifecycleBeanPostProcessor")
	public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}

	@Bean
	public CacheManager shiroCacheManager() {
		ShiroCacheManager shiroCacheManager = new ShiroCacheManager();
		return shiroCacheManager;
	}
}
==============================================================================================================
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import com.google.common.io.Closeables;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisShardInfo;
import redis.clients.jedis.Pipeline;
import redis.clients.jedis.ShardedJedis;
import redis.clients.jedis.ShardedJedisPipeline;
import redis.clients.jedis.ShardedJedisPool;
import redis.clients.jedis.Transaction;

public class RedisExample {

	public static void main(String[] args) {
		new RedisExample().testNormal();
	}

	// 普通同步方式
	public void testNormal() {// 12.526秒
		Jedis jedis = new Jedis("120.25.241.144", 6379);
		jedis.auth("b840fc02d52404542994");

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {
			jedis.set("n" + i, "n" + i);
			System.out.println(i);
		}
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		jedis.disconnect();
		try {
			Closeables.close(jedis, true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// 事务方式(Transactions)
	public void testTrans() {// 0.304秒
		Jedis jedis = new Jedis("120.25.241.144", 6379);
		jedis.auth("b840fc02d52404542994");

		long start = System.currentTimeMillis();
		Transaction tx = jedis.multi();
		for (int i = 0; i < 1000; i++) {
			tx.set("n" + i, "n" + i);
			System.out.println(i);
		}
		tx.exec();
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		jedis.disconnect();
		try {
			Closeables.close(jedis, true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 管道(Pipelining)
	public void testPipelined() {// 0.076秒
		Jedis jedis = new Jedis("120.25.241.144", 6379);
		jedis.auth("b840fc02d52404542994");

		long start = System.currentTimeMillis();
		Pipeline pipeline = jedis.pipelined();
		for (int i = 0; i < 1000; i++) {
			pipeline.set("n" + i, "n" + i);
			System.out.println(i);
		}
		pipeline.syncAndReturnAll();
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		jedis.disconnect();
		try {
			Closeables.close(jedis, true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 管道中调用事务
	public void testCombPipelineTrans() {// 0.099秒
		Jedis jedis = new Jedis("120.25.241.144", 6379);
		jedis.auth("b840fc02d52404542994");

		long start = System.currentTimeMillis();
		Pipeline pipeline = jedis.pipelined();
		pipeline.multi();
		for (int i = 0; i < 1000; i++) {
			pipeline.set("n" + i, "n" + i);
			System.out.println(i);
		}
		pipeline.exec();
		pipeline.syncAndReturnAll();
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		jedis.disconnect();
		try {
			Closeables.close(jedis, true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 分布式直连同步调用
	public void testShardNormal() {// 13.619秒
		JedisShardInfo jedis = new JedisShardInfo("120.25.241.144", 6379);
		jedis.setPassword("b840fc02d52404542994");

		List<JedisShardInfo> shards = Arrays.asList(jedis);
		ShardedJedis sharding = new ShardedJedis(shards);

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {
			sharding.set("n" + i, "n" + i);
			System.out.println(i);
		}
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		sharding.disconnect();
		try {
			Closeables.close(sharding, true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 分布式直连异步调用
	public void testShardPipelined() {// 0.127秒
		JedisShardInfo jedis = new JedisShardInfo("120.25.241.144", 6379);
		jedis.setPassword("b840fc02d52404542994");

		List<JedisShardInfo> shards = Arrays.asList(jedis);
		ShardedJedis sharding = new ShardedJedis(shards);
		ShardedJedisPipeline pipeline = sharding.pipelined();

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {
			pipeline.set("n" + i, "n" + i);
			System.out.println(i);
		}
		pipeline.syncAndReturnAll();
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		sharding.disconnect();
		try {
			Closeables.close(sharding, true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 分布式连接池同步调用
	public void testShardSimplePool() {// 12.642秒
		JedisShardInfo jedis = new JedisShardInfo("120.25.241.144", 6379);
		jedis.setPassword("b840fc02d52404542994");

		List<JedisShardInfo> shards = Arrays.asList(jedis);
		ShardedJedisPool pool = new ShardedJedisPool(new JedisPoolConfig(), shards);

		ShardedJedis sharding = pool.getResource();

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {
			sharding.set("n" + i, "n" + i);
			System.out.println(i);
		}
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		sharding.disconnect();
		pool.destroy();
		try {
			Closeables.close(sharding, true);
			Closeables.close(pool, true);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	// 分布式连接池异步调用
	public void testShardPipelinnedPool() {// 0.124秒
		JedisShardInfo jedis = new JedisShardInfo("120.25.241.144", 6379);
		jedis.setPassword("b840fc02d52404542994");

		List<JedisShardInfo> shards = Arrays.asList(jedis);
		ShardedJedisPool pool = new ShardedJedisPool(new JedisPoolConfig(), shards);

		ShardedJedis sharding = pool.getResource();
		ShardedJedisPipeline pipeline = sharding.pipelined();

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {
			pipeline.set("n" + i, "n" + i);
			System.out.println(i);
		}
		pipeline.syncAndReturnAll();
		long end = System.currentTimeMillis();
		System.out.println("共花费：" + (end - start) / 1000.0 + "秒");

		sharding.disconnect();
		pool.destroy();

		try {
			Closeables.close(sharding, true);
			Closeables.close(pool, true);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
}
==============================================================================================================
import org.springframework.beans.factory.config.PlaceholderConfigurerSupport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.whenling.module.base.config.ConfigurationPropertySourcesPlaceholderConfigurer;
import com.whenling.module.base.config.StaticConfigurationSupplier;

/**
 * serlvet配置
 * 
 * @作者 孔祥溪
 * @博客 http://ken.whenling.com
 * @创建时间 2016年1月6日 上午12:00:05
 */
@Configuration
@ComponentScan(basePackages = { "com.whenling" }, useDefaultFilters = false, includeFilters = { @Filter({ Controller.class }),
		@Filter({ ServletSupport.class }) }, nameGenerator = FullBeanNameGenerator.class)
@EnableWebMvc
@EnableAspectJAutoProxy
public class ServletConfiguration {

	@Bean
	public static PlaceholderConfigurerSupport placeholderConfigurer() {
		return new ConfigurationPropertySourcesPlaceholderConfigurer(StaticConfigurationSupplier.getConfiguration());
	}
}

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.FilterType;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * 根配置
 * 
 * @作者 孔祥溪
 * @博客 http://ken.whenling.com
 * @创建时间 2016年1月5日 下午11:59:47
 */
@Configuration
@ComponentScan(basePackages = { "com.whenling" }, excludeFilters = {
		@ComponentScan.Filter(value = Controller.class, type = FilterType.ANNOTATION),
		@ComponentScan.Filter(value = EnableWebMvc.class, type = FilterType.ANNOTATION),
		@ComponentScan.Filter(value = ServletSupport.class, type = FilterType.ANNOTATION) })
@EnableAspectJAutoProxy
public class RootConfiguration {

	@Bean
	public TaskExecutor taskExecutor() {
		ThreadPoolTaskExecutor threadPoolTaskExecutor = new ThreadPoolTaskExecutor();
		threadPoolTaskExecutor.setCorePoolSize(5);
		threadPoolTaskExecutor.setMaxPoolSize(50);
		threadPoolTaskExecutor.setQueueCapacity(1000);
		threadPoolTaskExecutor.setKeepAliveSeconds(60);
		return threadPoolTaskExecutor;
	}
}
==============================================================================================================
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.util.WebUtils;

/**
 * web工具
 * 
 * @作者 孔祥溪
 * @博客 http://ken.whenling.com
 * @创建时间 2016年3月1日 下午4:49:04
 */
public class WebHelper {

	static String phoneReg = "\\b(ip(hone|od)|android|opera m(ob|in)i" + "|windows (phone|ce)|blackberry"
			+ "|s(ymbian|eries60|amsung)|p(laybook|alm|rofile/midp" + "|laystation portable)|nokia|fennec|htc[-_]"
			+ "|mobile|up.browser|[1-4][0-9]{2}x[1-4][0-9]{2})\\b";
	static String tableReg = "\\b(ipad|tablet|(Nexus 7)|up.browser" + "|[1-4][0-9]{2}x[1-4][0-9]{2})\\b";

	// 移动设备正则匹配：手机端、平板
	static Pattern phonePat = Pattern.compile(phoneReg, Pattern.CASE_INSENSITIVE);
	static Pattern tablePat = Pattern.compile(tableReg, Pattern.CASE_INSENSITIVE);

	public static boolean isAjax(HttpServletRequest request) {
		return (request.getHeader("X-Requested-With") != null
				&& "XMLHttpRequest".equals(request.getHeader("X-Requested-With").toString()));
	}

	/**
	 * 判断是否是手机访问
	 */
	public static boolean isMobileAccess(HttpServletRequest request) {
		boolean isFromMobile = false;
		// 检查是否已经记录访问方式（移动端或pc端）
		Object ua = WebUtils.getSessionAttribute(request, "ua");
		if (null == ua) {
			try {
				String userAgent = request.getHeader("USER-AGENT").toLowerCase();
				if (null == userAgent) {
					userAgent = "";
				}
				isFromMobile = checkUserAgent(userAgent);
				// 判断是否为移动端访问
				if (isFromMobile) {
					WebUtils.setSessionAttribute(request, "ua", "mobile");
				} else {
					WebUtils.setSessionAttribute(request, "ua", "pc");
				}
			} catch (Exception e) {
			}
		} else {
			isFromMobile = ua.equals("mobile");
		}

		return isFromMobile;
	}

	private static boolean checkUserAgent(String userAgent) {
		if (null == userAgent) {
			userAgent = "";
		}
		// 匹配
		Matcher matcherPhone = phonePat.matcher(userAgent);
		Matcher matcherTable = tablePat.matcher(userAgent);
		if (matcherPhone.find() || matcherTable.find()) {
			return true;
		} else {
			return false;
		}
	}
}
==============================================================================================================
@Value("${hibernate.query.substitutions?:true 1, false 0}")
jpaProperties.put("hibernate.cache.infinispan.cfg", hibernateCacheInfinispanCfg);
jpaProperties.put("javax.persistence.sharedCache.mode", javaxPersistenceSharedCacheMode);
==============================================================================================================
<configuration>
    <conversionRule conversionWord="a" converterClass="com.sap.core.js.logging.converter.ACHPatternConverter"/>
    <conversionRule conversionWord="b" converterClass="com.sap.core.js.logging.converter.BundleNamePatternConverter"/>
    <conversionRule conversionWord="s" converterClass="com.sap.core.js.logging.converter.DSRPatternConverter"/>
    <conversionRule conversionWord="z" converterClass="com.sap.core.js.logging.converter.SpaceApplPatternConverter"/>
    <conversionRule conversionWord="u" converterClass="com.sap.core.js.logging.converter.UserPatternConverter"/>
    <conversionRule conversionWord="o" converterClass="com.sap.core.js.logging.converter.UTFOffsetPatternConverter"/>

    <jmxConfigurator/>

    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>
==============================================================================================================
@Override
	public int compareTo(ProductImage o) {
		return new CompareToBuilder().append(getSortNo(), o.getSortNo()).toComparison();
	}
	
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.FlushModeType;
import javax.persistence.PersistenceContext;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import com.whenling.extension.mall.product.model.Goods;
import com.whenling.extension.mall.product.model.Product;

public class ProductRepositoryImpl implements ProductRepositoryCustom {

	@PersistenceContext
	protected EntityManager entityManager;

	@Override
	public List<Product> findByGoodsWithExcludes(Goods goods, Set<Product> excludes) {
		CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
		CriteriaQuery<Product> criteriaQuery = criteriaBuilder.createQuery(Product.class);
		Root<Product> root = criteriaQuery.from(Product.class);
		criteriaQuery.select(root);
		Predicate restrictions = criteriaBuilder.conjunction();
		if (goods != null) {
			restrictions = criteriaBuilder.and(restrictions, criteriaBuilder.equal(root.get("goods"), goods));
		}
		if (excludes != null && !excludes.isEmpty()) {
			restrictions = criteriaBuilder.and(restrictions, criteriaBuilder.not(root.in(excludes)));
		}
		criteriaQuery.where(restrictions);
		return entityManager.createQuery(criteriaQuery).setFlushMode(FlushModeType.COMMIT).getResultList();
	}

}

@Digits(integer = 12, fraction = 3)
private static final String MOBILE_PHONE_NUMBER_PATTERN = "^$|^0{0,1}(13[0-9]|15[0-9]|14[0-9]|17[0-9]|18[0-9])[0-9]{8}$";
==============================================================================================================
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import org.hibernate.SessionFactory;
import org.hibernate.cfg.Environment;
import org.hibernate.jpa.HibernateEntityManagerFactory;
import org.hibernate.tool.hbm2ddl.MultipleLinesSqlCommandExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.datatables.repository.DataTablesRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.orm.jpa.AbstractEntityManagerFactoryBean;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Spring JavaConfig configuration for general infrastructure.
 */
@Configuration
@EnableJpaRepositories(repositoryFactoryBeanClass = DataTablesRepositoryFactoryBean.class,
    basePackages = { "org.springframework.data.jpa.datatables.model", "org.springframework.data.jpa.datatables.repository" })
public class Config {

  @Bean
  @Profile({"default", "h2"})
  public DataSource dataSource_H2() throws SQLException {
    return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
  }

  @Bean
  @Profile("mysql")
  public DataSource dataSource_MySQL() throws SQLException {
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("com.mysql.jdbc.Driver");
    dataSource.setUrl("jdbc:mysql://127.0.0.1/test");
    dataSource.setUsername("root");
    dataSource.setPassword("");
    return dataSource;
  }

  @Bean
  @Profile("pgsql")
  public DataSource dataSource_PostgreSQL() throws SQLException {
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("org.postgresql.Driver");
    dataSource.setUrl("jdbc:postgresql://127.0.0.1/test");
    dataSource.setUsername("postgres");
    dataSource.setPassword("");
    return dataSource;
  }

  @Bean
  public PlatformTransactionManager transactionManager() throws SQLException {
    return new JpaTransactionManager();
  }

  @Bean
  public AbstractEntityManagerFactoryBean entityManagerFactory(DataSource dataSource)
      throws SQLException {

    HibernateJpaVendorAdapter jpaVendorAdapter = new HibernateJpaVendorAdapter();
    jpaVendorAdapter.setGenerateDdl(true);

    LocalContainerEntityManagerFactoryBean bean = new LocalContainerEntityManagerFactoryBean();
    bean.setJpaVendorAdapter(jpaVendorAdapter);
    bean.setPackagesToScan(Config.class.getPackage().getName());
    bean.setDataSource(dataSource);

    return bean;
  }

  @Bean
  public SessionFactory sessionFactory(AbstractEntityManagerFactoryBean entityManagerFactory)
      throws SQLException {
    return ((HibernateEntityManagerFactory) entityManagerFactory.getObject()).getSessionFactory();
  }

}
==============================================================================================================
var gulp = require('gulp');
var url = require('url');
var proxy = require('proxy-middleware');
var templateCache = require('gulp-angular-templatecache');
var browserSync = require("browser-sync").create();

$ = require('gulp-load-plugins')();

gulp.task('clean', function () {
    return gulp.src(['dist/', '.tmp/'])
            .pipe($.clean());
});

gulp.task('templates', function () {
    return gulp.src('app/views/**/*.html')
            .pipe(templateCache({module: 'exampleApp.templates', standalone: true}))
            .pipe($.wrap('(function () {<%=contents%>}());'))
            .pipe(gulp.dest('.tmp/scripts/'));
});

gulp.task('serve', ['templates'], function () {
    var proxyOptions = url.parse('http://localhost:9000/api');
    proxyOptions.route = '/api';
    browserSync.init({
        notify: false,
        // Customize the Browsersync console logging prefix
        logPrefix: 'WSK',
        // Allow scroll syncing across breakpoints
        //scrollElementMapping: ['main', '.mdl-layout'],
        // Run as an https by uncommenting 'https: true'
        // Note: this uses an unsigned certificate which on first access
        //       will present a certificate warning in the browser.
        // https: true,
        server: {
            baseDir: ['.tmp', 'app'],
            middleware: [proxy(proxyOptions)]
        },
        port: 3000
    });

    gulp.watch(['app/**/*.html', 'app/styles/**/*.{scss,css}', 'app/scripts/**/*.js', 'app/images/**/*'], ['templates', browserSync.reload]);
//  gulp.watch(['app/styles/**/*.{scss,css}'], ['styles', browserSync.reload]);
//  gulp.watch(['app/scripts/**/*.js'], ['lint', 'scripts']);
//  gulp.watch(['app/images/**/*'], browserSync.reload);
});

gulp.task('copy-fonts', function () {
    gulp.src(
            [
                'bower_components/font-awesome/fonts/*.*',
                'bower_components/bootstrap-material-design/fonts/*.*',
                'bower_components/bootstrap/fonts/*.*'
            ],
            {cwd: 'app/'})
            .pipe(gulp.dest('dist/fonts/'));
});

gulp.task('copy-images', function () {
    gulp.src(['images/**'],
            {cwd: 'app/'})
            .pipe($.cache($.imagemin({optimizationLevel: 5, progressive: true, interlaced: true})))
            .pipe(gulp.dest('dist/images/'));
});

gulp.task('copy-i18n', function () {
    gulp.src(['i18n/**'],{cwd: 'app/'})
            .pipe(gulp.dest('dist/i18n/'));
});

gulp.task('copy', ['copy-fonts', 'copy-images', 'copy-i18n'], function () {});

//gulp.task('less', function () {
//  return gulp.src(['bower_components/bootstrap/less/bootstrap.less', 'bower_components/font-awesome/less/font-awesome.less'])
//    .pipe($.less())
//    .pipe($.concat())
//    .pipe(gulp.dest('./tmp/styles'));
//});
//
//var sass = require('gulp-ruby-sass');
//gulp.task('sass', function() {
//    return sass('src/scss/style.scss', {style: 'compressed'})
//        .pipe(rename({suffix: '.min'}))
//        .pipe(gulp.dest('build/css'));
//});

gulp.task('usemin', ['copy'], function () {
    return gulp.src('app/index.html')
            .pipe($.usemin({
                css: [
                    $.minifyCss(),
                    'concat',
                    $.rev()
                ],
                appcss: [
                    $.minifyCss(),
                    $.rev()
                ],
                js: [
                    $.uglify(),
                    $.rev()
                ],
                ngjs: [
                    $.stripDebug(),
                    $.ngAnnotate(),
                    //'concat'
                    $.uglify(),
                    $.rev()
                ],
                tpljs: [
                    $.ngAnnotate(),
                    $.uglify(),
                    $.rev()
                ]
            }))
            .pipe(gulp.dest('dist/'));
});
// Tell Gulp what to do when we type "gulp" into the terminal
gulp.task('default', function (cb) {
    $.sequence('clean', 'templates', 'usemin')(cb);
});
==============================================================================================================
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    gzip  on;

    include /etc/nginx/conf.d/*.conf;

    server {
        listen 80;
        server_name atseashop.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443;
        ssl on;
        ssl_certificate /run/secrets/revprox_cert;
        ssl_certificate_key /run/secrets/revprox_key;
        server_name atseashop.com;
        access_log /dev/stdout;
        error_log /dev/stderr;

        location / {
            proxy_pass http://appserver:8080;
        }
    }
}

    @ElementCollection
    @MapKeyColumn(name="productid")
    @Column(name = "productsordered")
    @CollectionTable(name="orderquantities", joinColumns=@JoinColumn(name="orderid"))
    Map<Integer, Integer> productsOrdered = new HashMap<Integer, Integer>();
==============================================================================================================
    public static void main(String[] args) {
        SpringApplication.run(MultipleSourceMain.class, args);
    }


    /**
     * 第一个数据源
     * @return 数据源实例
     */
    @Bean(name = "primaryDataSource")
    @Qualifier("primaryDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.primary")
    public DataSource primaryDataSource() {
        return DataSourceBuilder.create().build();
    }

    /**
     * 第二个数据源
     * @return 数据源实例
     */
    @Bean(name = "secondaryDataSource")
    @Qualifier("secondaryDataSource")
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource.secondary")
    public DataSource secondaryDataSource() {
        return DataSourceBuilder.create().build();
    }

    /**
     * 第一个JDBC模板
     * @param dataSource dataSource
     * @return JDBC模板
     */
    @Bean(name = "primaryJdbcTemplate")
    public JdbcTemplate primaryJdbcTemplate(
            @Qualifier("primaryDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * 第二个JDBC模板
     * @param dataSource dataSource
     * @return JDBC模板
     */
    @Bean(name = "secondaryJdbcTemplate")
    public JdbcTemplate secondaryJdbcTemplate(
            @Qualifier("secondaryDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
	
	import info.xiaomo.mybatis.domain.User;
import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Map;

/**
 * @author : xiaomo
 */
@Mapper
public interface UserMapper {

    @Results({
            @Result(property = "name", column = "name"),
            @Result(property = "age", column = "age")
    })

    /**
     * 根据名字查
     * @param name
     * @return user
     */
    @Select("SELECT * FROM USER WHERE NAME = #{name}")
    User findByName(@Param("name") String name);

    /**
     * 插入
     *
     * @param name
     * @param age
     * @return
     */
    @Insert("INSERT INTO USER(NAME, AGE) VALUES(#{name}, #{age})")
    int insert(@Param("name") String name, @Param("age") Integer age);

    /**
     * 查所有
     *
     * @return
     */
    @Select("SELECT * FROM USER WHERE 1=1")
    List<User> findAll();

    /**
     * 更新
     *
     * @param user
     */
    @Update("UPDATE USER SET age=#{age} WHERE name=#{name}")
    void update(User user);

    /**
     * 删除
     *
     * @param id
     */
    @Delete("DELETE FROM USER WHERE id =#{id}")
    void delete(Long id);

    /**
     * 添加
     *
     * @param user
     * @return
     */
    @Insert("INSERT INTO USER(name, age) VALUES(#{name}, #{age})")
    int insertByUser(User user);

    /**
     * 添加
     *
     * @param map
     * @return
     */
    @Insert("INSERT INTO user(name, age) VALUES(#{name,jdbcType=VARCHAR}, #{age,jdbcType=INTEGER})")
    int insertByMap(Map<String, Object> map);

}
==============================================================================================================
import com.hellokoding.auth.model.User;
import com.hellokoding.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UserValidator implements Validator {
    @Autowired
    private UserService userService;

    @Override
    public boolean supports(Class<?> aClass) {
        return User.class.equals(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
        User user = (User) o;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "NotEmpty");
        if (user.getUsername().length() < 6 || user.getUsername().length() > 32) {
            errors.rejectValue("username", "Size.userForm.username");
        }
        if (userService.findByUsername(user.getUsername()) != null) {
            errors.rejectValue("username", "Duplicate.userForm.username");
        }

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "password", "NotEmpty");
        if (user.getPassword().length() < 8 || user.getPassword().length() > 32) {
            errors.rejectValue("password", "Size.userForm.password");
        }

        if (!user.getPasswordConfirm().equals(user.getPassword())) {
            errors.rejectValue("passwordConfirm", "Diff.userForm.passwordConfirm");
        }
    }
}
==============================================================================================================
    @Bean
    public Jackson2ObjectMapperBuilder objectMapperBuilder(JsonComponentModule jsonComponentModule) {
   
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
            builder
    //                .serializerByType(ZonedDateTime.class, new JsonSerializer<ZonedDateTime>() {
    //                    @Override
    //                    public void serialize(ZonedDateTime zonedDateTime, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonProcessingException {
    //                        jsonGenerator.writeString(DateTimeFormatter.ISO_ZONED_DATE_TIME.format(zonedDateTime));
    //                    }
    //                })
                .serializationInclusion(JsonInclude.Include.NON_EMPTY)
                .featuresToDisable(
                        SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                        DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
                        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
                )
                .featuresToEnable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
                .indentOutput(true)
                .modulesToInstall(jsonComponentModule);
    
        return builder;
    } 
==============================================================================================================
/**
 * <p>Copyright (c) 2014 ZhaoQian.All Rights Reserved.</p>
 * @author <a href="zhaoqianjava@foxmail.com">ZhaoQian</a>
 */
package org.zhaoqian.security.shiro.authc.token;

import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * @author Credo
 * @date: 2014年8月1日
 */
public class CaptchaUsernamePasswordToken extends UsernamePasswordToken
{

	private static final long serialVersionUID = -4746028009681958929L;

	private String kaptcha;

	public CaptchaUsernamePasswordToken(String username, char[] password, boolean rememberMe, String host, String kaptcha)
	{
		super(username, password, rememberMe, host);
		this.kaptcha = kaptcha;
	}

	public String getKaptcha()
	{
		return kaptcha;
	}

	public void setKaptcha(String kaptcha)
	{
		this.kaptcha = kaptcha;
	}

}
==============================================================================================================
import org.springframework.data.domain.Pageable;
import org.springframework.data.solr.core.query.Query.Operator;
import org.springframework.data.solr.core.query.result.FacetPage;
import org.springframework.data.solr.core.query.result.HighlightPage;
import org.springframework.data.solr.repository.Facet;
import org.springframework.data.solr.repository.Highlight;
import org.springframework.data.solr.repository.Query;
import org.springframework.data.solr.repository.SolrCrudRepository;
import org.springframework.data.solr.showcase.product.model.Product;

/**
 * @author Christoph Strobl
 */
interface ProductRepository extends SolrCrudRepository<Product, String> {

	@Highlight(prefix = "<b>", postfix = "</b>")
	@Query(fields = { SearchableProductDefinition.ID_FIELD_NAME, SearchableProductDefinition.NAME_FIELD_NAME,
			SearchableProductDefinition.PRICE_FIELD_NAME, SearchableProductDefinition.FEATURES_FIELD_NAME,
			SearchableProductDefinition.AVAILABLE_FIELD_NAME }, defaultOperator = Operator.AND)
	HighlightPage<Product> findByNameIn(Collection<String> names, Pageable page);

	@Facet(fields = { SearchableProductDefinition.NAME_FIELD_NAME })
	FacetPage<Product> findByNameStartsWith(Collection<String> nameFragments, Pageable pagebale);

}
==============================================================================================================
		<executions>
					<execution>
						<goals>
							<goal>test-process</goal>
						</goals>
						<configuration>
							<outputDirectory>target/generated-sources/java</outputDirectory>
							<processor>com.querydsl.apt.jpa.JPAAnnotationProcessor</processor>
						</configuration>
					</execution>
				</executions>
==============================================================================================================
import com.hazelcast.query.Predicate;

import java.io.Serializable;
import java.util.Map;

import org.apache.shiro.session.Session;

/**
 * Hazelcast query predicate for Shiro session attributes.
 */
public class SessionAttributePredicate<T> implements
        Predicate<Serializable, Session> {

    private final String attributeName;
    private final T attributeValue;

    public SessionAttributePredicate(String attributeName, T attributeValue) {
        this.attributeName = attributeName;
        this.attributeValue = attributeValue;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public T getAttributeValue() {
        return attributeValue;
    }

    @Override
    public boolean apply(Map.Entry<Serializable, Session> sessionEntry) {
        final T attribute = (T) sessionEntry.getValue().getAttribute(attributeName);
        return attribute.equals(attributeValue);
    }
}
==============================================================================================================
<build>
    <plugins>
        <plugin>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>2.22.2</version>
            <configuration>
                <groups>acceptance | !feature-a</groups>
                <excludedGroups>integration, regression</excludedGroups>
            </configuration>
        </plugin>
    </plugins>
</build>
==============================================================================================================
class WebServerDemo {

    @RegisterExtension
    static WebServerExtension server = WebServerExtension.builder()
        .enableSecurity(false)
        .build();

    @Test
    void getProductList() {
        WebClient webClient = new WebClient();
        String serverUrl = server.getServerUrl();
        // Use WebClient to connect to web server using serverUrl and verify response
        assertEquals(200, webClient.get(serverUrl + "/products").getResponseStatus());
    }

}

-Djunit.jupiter.conditions.deactivate=org.junit.*DisabledCondition
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.google.common.base.Supplier;
import io.searchbox.client.JestClientFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.aws.core.region.RegionProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import vc.inreach.aws.request.AWSSigner;
import vc.inreach.aws.request.AWSSigningRequestInterceptor;

/**
 * Jest Elasticsearch for signing request on AWS configuration.
 * @author Julien Roy
 */
@Configuration
@ConditionalOnClass(AWSSigner.class)
@AutoConfigureAfter(name = "org.springframework.cloud.aws.autoconfigure.context.ContextRegionProviderAutoConfiguration")
public class ElasticsearchJestAWSAutoConfiguration {

	private static final String AWS_SERVICE = "es";
	private static final Supplier<LocalDateTime> CLOCK = () -> LocalDateTime.now(ZoneOffset.UTC);

	@Autowired
	private ElasticsearchJestProperties properties;

	@Autowired
	@Qualifier("elasticsearchJestAwsRegion")
	private String regionName;

	@Bean
	@ConditionalOnMissingBean(AWSCredentialsProvider.class)
	public AWSCredentialsProvider awsCredentialsProvider() {
		return new DefaultAWSCredentialsProviderChain();
	}

	@Bean
	public JestClientFactory jestClientFactory(AWSCredentialsProvider credentialsProvider) {

		final AWSSigner awsSigner = new AWSSigner(credentialsProvider, getRegion(), AWS_SERVICE, CLOCK);

		final AWSSigningRequestInterceptor requestInterceptor = new AWSSigningRequestInterceptor(awsSigner);
		return new JestClientFactory() {
			@Override
			protected HttpClientBuilder configureHttpClient(HttpClientBuilder builder) {
				builder.addInterceptorLast(requestInterceptor);
				return builder;
			}
			@Override
			protected HttpAsyncClientBuilder configureHttpClient(HttpAsyncClientBuilder builder) {
				builder.addInterceptorLast(requestInterceptor);
				return builder;
			}
		};
	}

	/**
	 * Return configured region if exist, else try to use auto-discovered region.
	 * @return Region name
	 */
	private String getRegion() {
		// Use specific user configuration
		if (StringUtils.hasText(properties.getAwsRegion())) {
			return properties.getAwsRegion();
		}

		return regionName;
	}

	@ConditionalOnMissingBean(name = "elasticsearchJestAwsRegion")
	@Bean(name = "elasticsearchJestAwsRegion")
	public String regionFromEC2() {

		// Try to determine current region ( work on EC2 instance )
		Region region = Regions.getCurrentRegion();
		if (region != null) {
			return region.getName();
		}

		// Nothing else , back to default
		return Regions.DEFAULT_REGION.getName();
	}

	@ConditionalOnClass(RegionProvider.class)
	@ConditionalOnBean(RegionProvider.class)
	private final static class RegionFromSpringCloudConfiguration {

		@Bean(name = "elasticsearchJestAwsRegion")
		public String regionFromSpringCloud(RegionProvider regionProvider) {

			// Try to use SpringCloudAWS region
			return regionProvider.getRegion().getName();
		}
	}
}

@Document(indexName = "test-product-index", type = "test-product-type", shards = 1, replicas = 0, refreshInterval = "-1")
==============================================================================================================
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

/**
 * @author volodymyr.tsukur
 */
public class AdValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return Ad.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Ad ad = (Ad) target;
        if (ad.getAmount().intValue() <= 0) {
            errors.rejectValue("amount", "Ad.amount.not.positive", "Amount should be positive");
        }
    }

}

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

public class SessionHandlerInterceptor extends HandlerInterceptorAdapter {

    @Autowired
    private SessionData sessionData;

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) throws Exception {
        // Register functionality is authorized for anonymous user
    	if (request.getMethod().equals(HttpMethod.POST.toString()) && request.getRequestURI().indexOf("/account") > 0) {
        	return true;
        }
    	
    	if (sessionData.getUser() == null) {
        	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
            return false;
        } else {
            return true;
        }
    }
}

    @Id
    @GenericGenerator(name="snowflake",strategy = SnowflakeGenerator.TYPE)
    @GeneratedValue(generator = "snowflake")
    private PK id;
==============================================================================================================
<?xml version="1.0" encoding="utf-8" ?>
<sqls xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns="http://www.slyak.com/schema/templatequery"
      xsi:schemaLocation="http://www.slyak.com/schema/templatequery http://www.slyak.com/schema/templatequery.xsd">

    <sql name="findByContent">
        <![CDATA[
          SELECT * FROM t_sample WHERE 1=1
          <#if content??>
            AND content LIKE :content
          </#if>
        ]]>
    </sql>
    <sql name="countContent">
        <![CDATA[
          SELECT count(*) FROM t_sample WHERE 1=1
          <#if content??>
            AND content LIKE :content
          </#if>
        ]]>
    </sql>
    <sql name="findDtos">
        <![CDATA[
          SELECT id,content as contentShow FROM t_sample
        ]]>
    </sql>
    <sql name="findByTemplateQueryObject">
        <![CDATA[
          SELECT * FROM t_sample WHERE 1=1
          <#if content??>
            AND content LIKE :content
          </#if>
        ]]>
    </sql>
</sqls>
==============================================================================================================
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.elasticsearch.annotations.Document;

@Document(indexName = "topqueries", type = "custquery", indexStoreType = "fs", shards = 1, replicas = 0, refreshInterval = "-1")
public class CustomerTopQuery {

	@Id
	private String id;
	@Version
	private Long version;

	private Long customerId;

	private String queryString;

	private int count;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public Long getVersion() {
		return version;
	}

	public void setVersion(Long version) {
		this.version = version;
	}

	public Long getCustomerId() {
		return customerId;
	}

	public void setCustomerId(Long customerId) {
		this.customerId = customerId;
	}

	public String getQueryString() {
		return queryString;
	}

	public void setQueryString(String queryString) {
		this.queryString = queryString;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}
}
==============================================================================================================
@NamedNativeQuery(name = "Manufacturer.getAllThatSellAcoustics", 
		query = "SELECT m.id, m.name, m.foundedDate, m.averageYearlySales, m.location_id as headquarters_id, m.active "
	    + "FROM Manufacturer m "
		+ "LEFT JOIN Model mod ON (m.id = mod.manufacturer_id) "
		+ "LEFT JOIN ModelType mt ON (mt.id = mod.modeltype_id) "
	    + "WHERE (mt.name = ?)", resultClass = Manufacturer.class)
==============================================================================================================
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-aws</artifactId>
            <version>${springcloudaws}</version>
            <optional>true</optional>
            <exclusions>
                <exclusion>
                    <groupId>com.amazonaws</groupId>
                    <artifactId>*</artifactId>
                </exclusion>
                <exclusion>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-actuator</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
        <dependency>
            <groupId>com.amazonaws</groupId>
            <artifactId>aws-java-sdk-core</artifactId>
            <version>${aws}</version>
            <optional>true</optional>
        </dependency>
==============================================================================================================
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
      .withUser("admin")
      .password("{noop}password") //{noop} makes sure that the password encoder doesn't do anything
      .roles("USER", "ADMIN") // Role of the user
      .and()
      .withUser("user")
      .password("{noop}password")
      .credentialsExpired(true)
      .accountExpired(true)
      .accountLocked(true)
      .roles("USER");
  }

  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    http.authorizeRequests().antMatchers("/css/**").permitAll();
    http.authorizeRequests().anyRequest().fullyAuthenticated().and()
      .formLogin()
      .loginPage("/login")
      .failureUrl("/login?error").permitAll();
  }
}
==============================================================================================================
static {
    EmbeddedKafkaHolder.getEmbeddedKafka().addTopics(topic1, topic2);
}

private static EmbeddedKafkaRule embeddedKafka = EmbeddedKafkaHolder.getEmbeddedKafka();
==============================================================================================================
Map<String, Object> consumerProps = KafkaTestUtils.consumerProps("testT", "false", embeddedKafka);
DefaultKafkaConsumerFactory<Integer, String> cf = new DefaultKafkaConsumerFactory<Integer, String>(
        consumerProps);
Consumer<Integer, String> consumer = cf.createConsumer();
embeddedKafka.consumeFromAllEmbeddedTopics(consumer);

<int-kafka:outbound-channel-adapter id="kafkaOutboundChannelAdapter"
                                    kafka-template="template"
                                    auto-startup="false"
                                    channel="inputToKafka"
                                    topic="foo"
                                    sync="false"
                                    message-key-expression="'bar'"
                                    send-failure-channel="failures"
                                    send-success-channel="successes"
                                    error-message-strategy="ems"
                                    partition-id-expression="2">
</int-kafka:outbound-channel-adapter>

<bean id="template" class="org.springframework.kafka.core.KafkaTemplate">
    <constructor-arg>
        <bean class="org.springframework.kafka.core.DefaultKafkaProducerFactory">
            <constructor-arg>
                <map>
                    <entry key="bootstrap.servers" value="localhost:9092" />
                    ... <!-- more producer properties -->
                </map>
            </constructor-arg>
        </bean>
    </constructor-arg>
</bean>



@Bean
public KafkaMessageDrivenChannelAdapter<String, String>
            adapter(KafkaMessageListenerContainer<String, String> container) {
    KafkaMessageDrivenChannelAdapter<String, String> kafkaMessageDrivenChannelAdapter =
            new KafkaMessageDrivenChannelAdapter<>(container, ListenerMode.record);
    kafkaMessageDrivenChannelAdapter.setOutputChannel(received());
    return kafkaMessageDrivenChannelAdapter;
}

@Bean
public KafkaMessageListenerContainer<String, String> container() throws Exception {
    ContainerProperties properties = new ContainerProperties(this.topic);
    // set more properties
    return new KafkaMessageListenerContainer<>(consumerFactory(), properties);
}

@Bean
public ConsumerFactory<String, String> consumerFactory() {
    Map<String, Object> props = new HashMap<>();
    props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, this.brokerAddress);
    // set more properties
    return new DefaultKafkaConsumerFactory<>(props);
}
==============================================================================================================
@Bean
public KafkaListenerContainerFactory<ConcurrentMessageListenerContainer<Integer, String>>
        kafkaListenerContainerFactory() {
    ConcurrentKafkaListenerContainerFactory<Integer, String> factory =
            new ConcurrentKafkaListenerContainerFactory<>();
    ...
    factory.getContainerProperties().setBatchErrorHandler(myBatchErrorHandler);
    ...
    return factory;
}
==============================================================================================================
@KafkaListener(id="validated", topics = "annotated35", errorHandler = "validationErrorHandler",
      containerFactory = "kafkaJsonListenerContainerFactory")
public void validatedListener(@Payload @Valid ValidatedClass val) {
    ...
}

@Bean
public KafkaListenerErrorHandler validationErrorHandler() {
    return (m, e) -> {
        ...
    };
}


@Configuration
@EnableKafka
public class Config implements KafkaListenerConfigurer {

    @Autowired
    private LocalValidatorFactoryBean validator;
    ...

    @Override
    public void configureKafkaListeners(KafkaListenerEndpointRegistrar registrar) {
      registrar.setValidator(this.validator);
    }
}
==============================================================================================================
@Bean
public ConcurrentKafkaListenerContainerFactory<Integer, String> kafkaListenerContainerFactory() {
    ConcurrentKafkaListenerContainerFactory<Integer, String> factory =
        new ConcurrentKafkaListenerContainerFactory<>();
    factory.setConsumerFactory(cf());
    factory.setReplyTemplate(template());
    factory.setReplyHeadersConfigurer(new ReplyHeadersConfigurer() {

      @Override
      public boolean shouldCopy(String headerName, Object headerValue) {
        return false;
      }

      @Override
      public Map<String, Object> additionalHeaders() {
        return Collections.singletonMap("qux", "fiz");
      }

    });
    return factory;
}
==============================================================================================================
@Configuration
@EnableKafka
@EnableKafkaStreams
public static class KafkaStreamsConfig {

    @Bean(name = KafkaStreamsDefaultConfiguration.DEFAULT_STREAMS_CONFIG_BEAN_NAME)
    public KafkaStreamsConfiguration kStreamsConfigs() {
        Map<String, Object> props = new HashMap<>();
        props.put(StreamsConfig.APPLICATION_ID_CONFIG, "testStreams");
        props.put(StreamsConfig.KEY_SERDE_CLASS_CONFIG, Serdes.Integer().getClass().getName());
        props.put(StreamsConfig.VALUE_SERDE_CLASS_CONFIG, Serdes.String().getClass().getName());
        props.put(StreamsConfig.TIMESTAMP_EXTRACTOR_CLASS_CONFIG, WallclockTimestampExtractor.class.getName());
        return new KafkaStreamsConfiguration(props);
    }

    @Bean
    public KStream<Integer, String> kStream(StreamsBuilder kStreamBuilder) {
        KStream<Integer, String> stream = kStreamBuilder.stream("streamingTopic1");
        stream
                .mapValues(String::toUpperCase)
                .groupByKey()
                .reduce((String value1, String value2) -> value1 + value2,
                		TimeWindows.of(1000),
                		"windowStore")
                .toStream()
                .map((windowedId, value) -> new KeyValue<>(windowedId.key(), value))
                .filter((i, s) -> s.length() > 40)
                .to("streamingTopic2");

        stream.print();

        return stream;
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
:host,
:root {
  --scrollbar-color: var(--opera-dark-scrollbar-color);
  --scrollbar-hover-color: var(--opera-dark-scrollbar-hover-color);
}

:host-context(html.dark-theme) {
  --scrollbar-color: var(--opera-light-scrollbar-color);
  --scrollbar-hover-color: var(--opera-light-scrollbar-hover-color);
}

::-webkit-scrollbar {
  height: 12px;
  width: 12px;
}

::-webkit-scrollbar-thumb {
  background-clip: padding-box;
  background-color: var(--scrollbar-color);
  border: 2px solid transparent;
  border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
  background-color: var(--scrollbar-hover-color);
}

::-webkit-scrollbar-corner {
  background-color: transparent;
}

var restman = restman || {};
restman.ui = restman.ui || {};

(function() {
    'use strict';

    restman.ui.editors = {
        _editors: {},

        create: function(textareaId, readonly) {
            var options = { 'lineNumbers': true, 'matchBrackets': true }
            if (readonly) {
                options['readOnly'] = true;
            }
            restman.ui.editors._editors[textareaId] = CodeMirror.fromTextArea($(textareaId)[0], options);
            return textareaId;
        },

        get: function(id) {
            return restman.ui.editors._editors[id];
        },

        setValue: function(id, value) {
            var e = restman.ui.editors.get(id);
            e.setValue(value);
            e.refresh();
        }
    };
})();
==============================================================================================================
uuidgen

alias ts='date +%s'

random-string()
{
    cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n ${1:-1}
}

random-string 10 4
==============================================================================================================
language: java
sudo: false

jdk:
 - openjdk8

install:
  - mvn --settings .travis/settings.xml install -DskipTests=true -Dgpg.skip -Dmaven.javadoc.skip=true -B -V

before_install:
  - if [ ! -z "$GPG_SECRET_KEYS" ]; then echo $GPG_SECRET_KEYS | base64 --decode | $GPG_EXECUTABLE --import; fi
  - if [ ! -z "$GPG_OWNERTRUST" ]; then echo $GPG_OWNERTRUST | base64 --decode | $GPG_EXECUTABLE --import-ownertrust; fi


after_success:
  - bash <(curl -s https://codecov.io/bash)

deploy:
  - provider: script
    script: .travis/deploy.sh
    skip_cleanup: true
    on:
      repo: lanwen/wiremock-junit5
      branch: master
  - provider: script
    script: .travis/deploy.sh
    skip_cleanup: true
    on:
      repo: lanwen/wiremock-junit5
      tags: true

notifications:
 email: false

cache:
  directories:
    - $HOME/.m2
	
	
if [ ! -z "$TRAVIS_TAG" ]
then
    echo "on a tag -> set pom.xml <version> to $TRAVIS_TAG"
    mvn --settings .travis/settings.xml org.codehaus.mojo:versions-maven-plugin:2.1:set -DnewVersion=$TRAVIS_TAG 1>/dev/null 2>/dev/null
else
    echo "not on a tag -> keep SNAPSHOT version in pom.xml"
fi

mvn clean deploy --settings .travis/settings.xml -DskipTests=true -B -U
==============================================================================================================
// get the data	
d3.csv("data/spinningheart.csv", function(error, links) {
			
	var nodes = {};

	// process the incoming data
	links.forEach(function(link) {
	    link.source = nodes[link.source] || 
	        (nodes[link.source] = {name: link.source});
	    link.target = nodes[link.target] || 
	        (nodes[link.target] = {name: link.target});
	    link.value = +link.value;
	});
	
	var width = 900,
	    height = 600;

	var color = d3.scale.category20();

	var force = d3.layout.force()
	    // negative value results in node repulsion
	    .charge(-150)
	    // sets the target distance between linked
	    .linkDistance(275)
	    .size([width, height]);

	var svg = d3.select("#graph").append("svg")
	    .attr("width", width)
	    .attr("height", height);
				
	force.nodes(d3.values(nodes))
		.links(links)
		.start();
		
	// add the connections	
	var link = svg.selectAll(".link")
		.data(links)
		.enter().append("line")
		.attr("class", "link")
 		.style("stroke-width", function(d) { return Math.sqrt(d.value); });
						
	// create the groups					
	var node = svg.selectAll(".node")
		.data(force.nodes())
		.enter()
		.append("g")
		.attr("class", "node")
		.style("fill", function(d) { return color(d.group); })
		.call(force.drag);

	// assign a circle to each group
	node.append("circle")
		.attr("r", 5);
	
	node.append("text")
	.attr({
	    "x": 12,
	    "y": ".35em",
	    "class":"nodelabel",
        "stroke":"grey"
        })
		.text(function(d) { return d.name; });

	force.on("tick", function() {
		link.attr("x1", function(d) { return d.source.x; })
			.attr("y1", function(d) { return d.source.y; })
		  .attr("x2", function(d) { return d.target.x; })
		  .attr("y2", function(d) { return d.target.y; });

		node
			.attr("cx", function(d) { return d.x; })
			.attr("cy", function(d) { return d.y; });
		
		node
			.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });		
	});
});
==============================================================================================================
/* Defaults (light theme) */

:root,
:host {
  --opera-blue: #0199ff;
  --opera-blue-secondary: #0199ffa0;
  --opera-red: #f54a4b;

  --opera-primary-color: var(--opera-blue);
  --opera-secondary-color: var(--opera-blue-secondary);
}

:root,
:host {
  --opera-blue-hover: #008ae6;
  --opera-blue-pressed: #0077e6;

  --opera-icon-size: 20px;
  --opera-logo-size: 32px;
  --opera-menu-width: 240px;
  --opera-menu-item-height: 32px;
  --opera-section-spacing: 56px;

  --opera-header-height: 64px;
  --opera-header-padding: 16px 30px;
  --opera-header-title-padding: 0 0 0 44px;
  --opera-header-font-size: 17px;
  --opera-header-font-weight: 450;

  --max-search-box-width: 620px;

  --opera-default-font-weight: 500;
  /*  /*   */

  --opera-default-font-size: 13px;
  --opera-headline-font-size: 36px;

  --opera-section-font-size: 15px;
  --opera-section-font-weight: 500;
  --opera-section-margin: 26px 0 12px 0;

  --opera-uppercase-font-size: 14px;

  --opera-background-color: #f5f5f7;
  --opera-secondary-background-color: #ffffff;
  --opera-secondary-background-hover-color: #f8f8fa;

  --opera-tile-background-color: #ffffff;
  --opera-tile-text-color: #000000;

  --opera-separator-color: #e6e6e6;
  --opera-search-border-color: transparent;

  --opera-focus-outline-color: rgba(1, 153, 255, .4);

  --opera-font-family: system-ui;
  --opera-font-color: #121314;
  --opera-secondary-font-color: #6a6a75;
  --opera-hint-font-color: #6e767a;

  --opera-folder-background-color: #E6EEF5;

  --opera-article-font-size: 16px;
  --opera-article-font-weight: 600;

  --opera-input-background-color: #ffffff;
  --opera-input-background-color-hover: #fafafa;
  --opera-input-background-color-pressed: #ededed;
  --opera-input-font-size: 13px;
  --opera-input-border-color: #cdcdd4;
  --opera-input-border-radius: 3px;
  --opera-input-border-width: 1px;
  --opera-input-padding: 8px 16px;
  --opera-input-height: 32px;
  --opera-rounded-input-border-radius: 16px;

  --opera-search-icon-color: var(--opera-secondary-font-color);
  --opera-search-background-size: 16px;
  --opera-search-padding: 7px 36px 7px 15px;

  --opera-button-font-color: var(--opera-font-color);
  --opera-button-background-color: var(--opera-input-background-color);
  --opera-button-background-color-hover: #f8f8fa;
  --opera-button-border-color: var(--opera-input-border-color);
  --opera-button-padding: 6px 12px;

  --opera-button-disabled-background-color: #ffffff;
  --opera-button-disabled-border-color: #ebebee;
  --opera-button-disabled-font-color: #a0a1a1;

  --opera-primary-button-font-color: #fff;
  --opera-primary-button-background-color: var(--opera-blue);
  --opera-primary-button-background-color-hover: var(--opera-blue-hover);
  --opera-primary-button-background-color-pressed: var(--opera-blue-pressed);
  --opera-primary-button-border-color: #0084ff;
  --opera-primary-button-padding: 6px 16px;

  --opera-primary-button-disabled-background-color: var(--opera-button-background-color);
  --opera-primary-button-disabled-border-color: var(--opera-separator-color);
  --opera-primary-button-disabled-font-color: var(--opera-separator-color);

  --opera-switch-color: #ceced4;
  --opera-switch-color-hover: #bcbcc6;
  --opera-switch-color-pressed: #ceced4;
  --opera-switch-active-color: var(--opera-blue);
  --opera-switch-active-color-hover: var(--opera-blue-hover);
  --opera-switch-active-color-pressed: var(--opera-blue-pressed);
  --opera-switch-toggle-color: #fff;
  --opera-switch-height: 20px;
  --opera-switch-width: 40px;

  --opera-pad-border-radius: 5px;
  --opera-pad-padding: 20px;
  --opera-pad-shadow: 0 10px 20px -8px rgba(0, 0, 0, 0.04);
  --opera-box-shadow: 0 10px 20px -8px rgba(0, 0, 0, 0.24);

  --opera-link-color: rgba(0, 122, 204, 1);
  --opera-link-hover-background-color: rgba(0, 122, 204,.08);
  --opera-link-focus-background-color: rgba(0, 122, 204,.24);

  --opera-text-line-height: 1.5;

  --opera-navbar-background-color: #ffffff;
  --opera-navbar-separator-color: #e6e6e6;
  --opera-navbar-width: 0px;

  --opera-progress-border-radius: 3px;
  --opera-progress-bar-color: #0199ff;
  --opera-progress-bar-secondary-color: #5dbae9;
  --opera-progress-background-color: rgb(231, 231, 231);

  --opera-scrollbar-width: 12px;

  --opera-dark-scrollbar-color: #9995;
  --opera-dark-scrollbar-hover-color: #6668;
  --opera-light-scrollbar-color: #6665;
  --opera-light-scrollbar-hover-color: #9998;

  --speeddial-tile-width: 140px;
  --speeddial-tile-height: 89px;
  --speeddial-tile-spacing: 20px;

  --opera-drop-shadow-filter: none;

  --opera-settings-menu-width: 240px;

  --opera-modal-border-width: 0;
  --opera-modal-background-color: var(--opera-secondary-background-color);
  --opera-modal-header-color: var(--opera-secondary-background-color);
  --opera-modal-header-font-color: var(--opera-secondary-font-color);
}

/* Dark theme */

:root.dark-theme,
:host-context(html.dark-theme) {

  --opera-blue: #45b0e6;
  --opera-blue-secondary: #45b0e6a0;
  --opera-blue-hover: #49baf2;
  --opera-blue-pressed: #3d9ccc;
  --opera-red: #ff776c;

  --opera-background-color: #121314;
  --opera-secondary-background-color: #1c1d1f;
  --opera-secondary-background-hover-color: #222325;

  --opera-tile-background-color: var(--opera-folder-background-color);
  --opera-tile-text-color: #f0f0f0;

  --opera-separator-color: #333435;

  --opera-focus-outline-color: rgba(69, 176, 230, .48);

  --opera-font-color: #fafafa;
  --opera-secondary-font-color: #a8abad;
  --opera-hint-font-color: #b4c1cc;

  --opera-folder-background-color: #2a343d;

  --opera-input-background-color: #3d4042;
  --opera-input-border-color: #404547;
  --opera-input-background-color-hover: #494c4f;
  --opera-input-background-color-pressed: #262729;

  --opera-button-disabled-background-color: #292b2c;
  --opera-button-disabled-border-color: #292b2c;
  --opera-button-disabled-font-color: #757576;

  --opera-switch-color: #3d4042;
  --opera-switch-color-hover: #494c4f;
  --opera-switch-color-pressed: #3d4042;

  --opera-pad-shadow: 0 10px 20px -8px rgba(0, 0, 0, 0.25);

  --opera-button-background-color-hover: #494c4f;

  --opera-primary-button-font-color: var(--opera-font-color);
  --opera-primary-button-border-color: #4993b8;

  --opera-primary-button-disabled-font-color: var(--opera-separator-color);
  --opera-primary-button-disabled-background-color: var(--opera-button-background-color);
  --opera-primary-button-disabled-border-color: var(--opera-button-background-color);

  --opera-navbar-background-color: #171819;
  --opera-navbar-separator-color: #000000;

  --opera-link-color: #96ddff;
  --opera-link-hover-background-color: rgba(150, 221, 255, .24);
  --opera-link-focus-background-color: rgba(150, 221, 255, .48);

  --opera-progress-bar-color: rgb(69, 176, 230);
  --opera-progress-bar-secondary-color: rgb(120, 198, 237);
  --opera-progress-background-color: rgb(43, 43, 43);
}

:root.gx,
:host-context(html.gx) {
  --opera-background-color: #14111a;
  --opera-secondary-background-color: #131218;

  --opera-link-color: var(--opera-gx-color);
  --opera-link-hover-background-color: var(--opera-gx-shadow-color);
  --opera-link-focus-background-color: var(--opera-gx-secondary-color);

  --opera-focus-outline-color: var(--opera-gx-secondary-color);

  --opera-drop-shadow-filter: none;
  /* TODO(aswitalski) - use: drop-shadow(4px 4px 4px rgba(0, 0, 0, 0.32)); */

  --opera-modal-border-width: 1px;
  --opera-modal-background-color: #19171F;
  --opera-modal-header-color: #2f2a3d;
  --opera-modal-header-font-color: #eaE6f5;

  --opera-primary-color: var(--opera-gx-color);
  --opera-secondary-color: var(--opera-gx-secondary-color);

  --opera-primary-button-font-color: var(--opera-gx-font-color);
  --opera-primary-button-background-color: var(--opera-gx-color);
  --opera-primary-button-disabled-background-color: var(--opera-secondary-color);
  --opera-primary-button-background-color-hover: var(--opera-gx-color);
  --opera-primary-button-border-color: var(--opera-secondary-color);
}

:root.bigger-tiles:not(.gx),
:host-context(html.bigger-tiles:not(.gx)) {
  --speeddial-tile-width: 188px;
  --speeddial-tile-height: 120px;
  --speeddial-tile-spacing: 24px;
}
==============================================================================================================
import org.eclipse.microprofile.metrics.MetricUnits;

/**
 * @author hrupp, Michal Szynkiewicz, michal.l.szynkiewicz@gmail.com
 */
public class ExporterUtil {

    public static final long NANOS_PER_MICROSECOND = 1_000;
    public static final long NANOS_PER_MILLI = 1_000_000;
    public static final long NANOS_PER_SECOND = 1_000_000_000;
    public static final long NANOS_PER_MINUTE = 60 * 1_000_000_000L;
    public static final long NANOS_PER_HOUR = 3600 * 1_000_000_000L;
    public static final long NANOS_PER_DAY = 24 * 3600 * 1_000_000_000L;

    private ExporterUtil() {
    }

    public static Double convertNanosTo(Double value, String unit) {

        Double out;

        switch (unit) {
            case MetricUnits.NANOSECONDS:
                out = value;
                break;
            case MetricUnits.MICROSECONDS:
                out = value / NANOS_PER_MICROSECOND;
                break;
            case MetricUnits.MILLISECONDS:
                out = value / NANOS_PER_MILLI;
                break;
            case MetricUnits.SECONDS:
                out = value / NANOS_PER_SECOND;
                break;
            case MetricUnits.MINUTES:
                out = value / NANOS_PER_MINUTE;
                break;
            case MetricUnits.HOURS:
                out = value / NANOS_PER_HOUR;
                break;
            case MetricUnits.DAYS:
                out = value / NANOS_PER_DAY;
                break;
            default:
                out = value;
        }
        return out;
    }
}

import java.util.EnumSet;

/**
 * An enumeration representing the different types of metrics.
 * 
 * @author hrupp, Raymond Lam, Ouyang Zhou
 */
public enum MetricType {
    /**
     * A Counter monotonically in-/decreases its values.
     * An example could be the number of Transactions committed.
     */
    COUNTER("counter", Counter.class),

    /**
     * A Gauge has values that 'arbitrarily' goes up/down at each
     * sampling. An example could be CPU load
     */
    GAUGE("gauge", Gauge.class),

    /**
     * A Meter measures the rate at which a set of events occur.
     * An example could be amount of Transactions per Hour.
     */
    METERED("meter", Meter.class),

    /**
     * A Histogram calculates the distribution of a value.
     */
    HISTOGRAM("histogram", Histogram.class),

    /**
     * A timer aggregates timing durations and provides duration 
     * statistics, plus throughput statistics
     */
    TIMER("timer", Timer.class),
    
    /**
     * Invalid - Placeholder
     */
    INVALID("invalid", null)
    ;


  private String type;
  private Class<?> classtype;

  MetricType(String type, Class<?> classtype) {
    this.type = type;
    this.classtype = classtype;
  }

  public String toString() {
    return type;
  }

  /**
   * Convert the string representation into an enum
   * @param in the String representation
   * @return the matching Enum
   * @throws IllegalArgumentException if in is not a valid enum value
   */
  public static MetricType from(String in) {
    EnumSet<MetricType> enumSet = EnumSet.allOf(MetricType.class);
    for (MetricType u : enumSet) {
      if (u.type.equals(in)) {
        return u;
      }
    }
    throw new IllegalArgumentException(in + " is not a valid MetricType");
  }

  /**
   * Convert the metric class type into an enum
   * @param in The metric class type
   * @return the matching Enum
   * @throws IllegalArgumentException if in is not a valid enum value
   */
  public static MetricType from(Class<?> in) {
    EnumSet<MetricType> enumSet = EnumSet.allOf(MetricType.class);
    for (MetricType u : enumSet) {
      if (u.classtype != null && u.classtype.equals(in)) {
        return u;
      }
    }
    return MetricType.INVALID;
  }
}
==============================================================================================================
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * Defines all {@link ActiveMQException} types and their codes.
 */
public enum ActiveMQExceptionType {

   // Error codes -------------------------------------------------

   INTERNAL_ERROR(000) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQInternalErrorException(msg);
      }
   },
   UNSUPPORTED_PACKET(001) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQUnsupportedPacketException(msg);
      }
   },
   NOT_CONNECTED(002) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQNotConnectedException(msg);
      }
   },
   CONNECTION_TIMEDOUT(003) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQConnectionTimedOutException(msg);
      }
   },
   DISCONNECTED(004) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQDisconnectedException(msg);
      }
   },
   UNBLOCKED(005) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQUnBlockedException(msg);
      }
   },
   IO_ERROR(006) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQIOErrorException(msg);
      }
   },
   QUEUE_DOES_NOT_EXIST(100) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQNonExistentQueueException(msg);
      }
   },
   QUEUE_EXISTS(101) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQQueueExistsException(msg);
      }
   },
   OBJECT_CLOSED(102) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQObjectClosedException(msg);
      }
   },
   INVALID_FILTER_EXPRESSION(103) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQInvalidFilterExpressionException(msg);
      }
   },
   ILLEGAL_STATE(104) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQIllegalStateException(msg);
      }
   },
   SECURITY_EXCEPTION(105) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQSecurityException(msg);
      }
   },
   ADDRESS_DOES_NOT_EXIST(106) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQAddressDoesNotExistException(msg);
      }
   },
   ADDRESS_EXISTS(107) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQAddressExistsException(msg);
      }
   },
   INCOMPATIBLE_CLIENT_SERVER_VERSIONS(108) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQIncompatibleClientServerException(msg);
      }
   },
   LARGE_MESSAGE_ERROR_BODY(110) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQLargeMessageException(msg);
      }
   },
   TRANSACTION_ROLLED_BACK(111) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQTransactionRolledBackException(msg);
      }
   },
   SESSION_CREATION_REJECTED(112) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQSessionCreationException(msg);
      }
   },
   DUPLICATE_ID_REJECTED(113) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQDuplicateIdException(msg);
      }
   },
   DUPLICATE_METADATA(114) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQDuplicateMetaDataException(msg);
      }
   },
   TRANSACTION_OUTCOME_UNKNOWN(115) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQTransactionOutcomeUnknownException(msg);
      }
   },
   ALREADY_REPLICATING(116) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQAlreadyReplicatingException(msg);
      }
   },
   INTERCEPTOR_REJECTED_PACKET(117) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQInterceptorRejectedPacketException(msg);
      }
   },
   INVALID_TRANSIENT_QUEUE_USE(118) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQInvalidTransientQueueUseException(msg);
      }
   },
   REMOTE_DISCONNECT(119) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQRemoteDisconnectException(msg);
      }
   },
   TRANSACTION_TIMEOUT(120) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQTransactionTimeoutException(msg);
      }
   },
   GENERIC_EXCEPTION(999),
   NATIVE_ERROR_INTERNAL(200),
   NATIVE_ERROR_INVALID_BUFFER(201),
   NATIVE_ERROR_NOT_ALIGNED(202),
   NATIVE_ERROR_CANT_INITIALIZE_AIO(203),
   NATIVE_ERROR_CANT_RELEASE_AIO(204),
   NATIVE_ERROR_CANT_OPEN_CLOSE_FILE(205),
   NATIVE_ERROR_CANT_ALLOCATE_QUEUE(206),
   NATIVE_ERROR_PREALLOCATE_FILE(208),
   NATIVE_ERROR_ALLOCATE_MEMORY(209),
   ADDRESS_FULL(210) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQAddressFullException(msg);
      }
   },
   LARGE_MESSAGE_INTERRUPTED(211) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQLargeMessageInterruptedException(msg);
      }
   },
   CLUSTER_SECURITY_EXCEPTION(212) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQClusterSecurityException(msg);
      }

   },
   NOT_IMPLEMTNED_EXCEPTION(213),
   MAX_CONSUMER_LIMIT_EXCEEDED(214) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQQueueMaxConsumerLimitReached(msg);
      }
   },
   UNEXPECTED_ROUTING_TYPE_FOR_ADDRESS(215) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQUnexpectedRoutingTypeForAddress(msg);
      }
   },
   INVALID_QUEUE_CONFIGURATION(216) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQInvalidQueueConfiguration(msg);
      }
   },
   DELETE_ADDRESS_ERROR(217) {
      @Override
      public ActiveMQException createException(String msg) {
         return new ActiveMQDeleteAddressException(msg);
      }
   };

   private static final Map<Integer, ActiveMQExceptionType> TYPE_MAP;

   static {
      HashMap<Integer, ActiveMQExceptionType> map = new HashMap<>();
      for (ActiveMQExceptionType type : EnumSet.allOf(ActiveMQExceptionType.class)) {
         map.put(type.getCode(), type);
      }
      TYPE_MAP = Collections.unmodifiableMap(map);
   }

   private final int code;

   ActiveMQExceptionType(int code) {
      this.code = code;
   }

   public int getCode() {
      return code;
   }

   public ActiveMQException createException(String msg) {
      return new ActiveMQException(msg + ", code:" + this);
   }

   public static ActiveMQException createException(int code, String msg) {
      return getType(code).createException(msg);
   }

   public static ActiveMQExceptionType getType(int code) {
      ActiveMQExceptionType type = TYPE_MAP.get(code);
      if (type != null)
         return type;
      return ActiveMQExceptionType.GENERIC_EXCEPTION;
   }
}

public enum RoutingType {

   MULTICAST, ANYCAST;

   public byte getType() {
      switch (this) {
         case MULTICAST:
            return 0;
         case ANYCAST:
            return 1;
         default:
            return -1;
      }
   }

   public static RoutingType getType(byte type) {
      switch (type) {
         case 0:
            return MULTICAST;
         case 1:
            return ANYCAST;
         default:
            return null;
      }
   }
}

https://github.com/jmesnil/activemq-artemis/blob/master/artemis-commons/src/main/java/org/apache/activemq/artemis/api/core/SimpleString.java


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Locale;

/**
 * Provides general information about the processors on this host.
 *
 * @author Jason T. Greene
 */
public class ProcessorInfo {
    private ProcessorInfo() {
    }

    private static final String CPUS_ALLOWED = "Cpus_allowed:";
    private static final byte[] BITS = new byte[]{0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
    private static final Charset ASCII = Charset.forName("US-ASCII");

    /**
     * Returns the number of processors available to this process. On most operating systems this method
     * simply delegates to {@link Runtime#availableProcessors()}. However, on Linux, this strategy
     * is insufficient, since the JVM does not take into consideration the process' CPU set affinity
     * which is employed by cgroups and numactl. Therefore this method will analyze the Linux proc filesystem
     * to make the determination. Since the CPU affinity of a process can be change at any time, this method does
     * not cache the result. Calls should be limited accordingly.
     * <br>
     * Note tha on Linux, both SMT units (Hyper-Threading) and CPU cores are counted as a processor.
     *
     * @return the available processors on this system.
     */
    public static int availableProcessors() {
        if (System.getSecurityManager() != null) {
            return AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Integer.valueOf(determineProcessors())).intValue();
        }

        return determineProcessors();
    }

    private static int determineProcessors() {
        int javaProcs = Runtime.getRuntime().availableProcessors();
        if (!isLinux()) {
            return javaProcs;
        }

        int maskProcs = 0;

        try {
            maskProcs = readCPUMask();
        } catch (Exception e) {
            // yum
        }

        return maskProcs > 0 ? Math.min(javaProcs, maskProcs) : javaProcs;
    }

    private static int readCPUMask() throws IOException {
        final FileInputStream stream = new FileInputStream("/proc/self/status");
        final InputStreamReader inputReader = new InputStreamReader(stream, ASCII);

        try (BufferedReader reader = new BufferedReader(inputReader)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(CPUS_ALLOWED)) {
                    int count = 0;
                    int start = CPUS_ALLOWED.length();
                    for (int i = start; i < line.length(); i++) {
                         char ch = line.charAt(i);
                         if (ch >= '0' && ch <= '9') {
                             count += BITS[ch - '0'];
                         } else if (ch >= 'a' && ch <= 'f') {
                             count += BITS[ch - 'a' + 10];
                         } else if (ch >= 'A' && ch <= 'F') {
                             count += BITS[ch - 'A' + 10];
                         }
                     }
                     return count;
                 }
             }
         }

         return -1;
     }

    private static boolean isLinux() {
        String osArch = System.getProperty("os.name", "unknown").toLowerCase(Locale.US);
        return (osArch.contains("linux"));
    }
}

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * A base-32 alphabet.
 *
 * @see ByteIterator#base32Encode(Base32Alphabet)
 * @see CodePointIterator#base32Decode(Base32Alphabet)
 */
public abstract class Base32Alphabet extends Alphabet {

    /**
     * Construct a new instance.
     *
     * @param littleEndian {@code true} if the alphabet is little-endian (LSB first), {@code false} otherwise
     */
    protected Base32Alphabet(final boolean littleEndian) {
        super(littleEndian);
    }

    /**
     * Encode the given 5-bit value to a code point.
     *
     * @param val the 5-bit value
     * @return the Unicode code point
     */
    public abstract int encode(int val);

    /**
     * Decode the given code point.  If the code point is not valid, -1 is returned.
     *
     * @param codePoint the code point
     * @return the decoded 5-bit value or -1 if the code point is not valid
     */
    public abstract int decode(int codePoint);

    /**
     * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-32 alphabet.
     */
    public static final Base32Alphabet STANDARD = new Base32Alphabet(false) {
        public int encode(final int val) {
            if (val <= 25) {
                return 'A' + val;
            } else {
                assert val < 32;
                return '2' + val - 26;
            }
        }

        public int decode(final int codePoint) {
            if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A';
            } else if ('2' <= codePoint && codePoint <= '7') {
                return codePoint - '2' + 26;
            } else {
                return -1;
            }
        }
    };

    /**
     * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-32 alphabet mapped to lowercase.
     */
    public static final Base32Alphabet LOWERCASE = new Base32Alphabet(false) {
        public int encode(final int val) {
            if (val <= 25) {
                return 'a' + val;
            } else {
                assert val < 32;
                return '2' + val - 26;
            }
        }

        public int decode(final int codePoint) {
            if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a';
            } else if ('2' <= codePoint && codePoint <= '7') {
                return codePoint - '2' + 26;
            } else {
                return -1;
            }
        }
    };

}

/**
 * A base-n encoder/decoder alphabet.  Alphabets may be little-endian or big-endian.  Each base has its own subclass.
 */
public abstract class Alphabet {
    private final boolean littleEndian;

    Alphabet(final boolean littleEndian) {
        this.littleEndian = littleEndian;
    }

    /**
     * Determine whether this is a little-endian or big-endian alphabet.
     *
     * @return {@code true} if the alphabet is little-endian, {@code false} if it is big-endian
     */
    public boolean isLittleEndian() {
        return littleEndian;
    }

    /**
     * Encode the given byte value to a code point.
     *
     * @param val the value
     * @return the Unicode code point
     */
    public abstract int encode(int val);

    /**
     * Decode the given code point (character).  If the code point is not valid, -1 is returned.
     *
     * @param codePoint the Unicode code point
     * @return the decoded value or -1 if the code point is not valid
     */
    public abstract int decode(int codePoint);
}

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * A base-64 alphabet.
 *
 * @see ByteIterator#base64Encode(Base64Alphabet)
 * @see CodePointIterator#base64Decode(Base64Alphabet)
 */
public abstract class Base64Alphabet extends Alphabet {

    /**
     * Construct a new instance.
     *
     * @param littleEndian {@code true} if the alphabet is little-endian (LSB first), {@code false} otherwise
     */
    protected Base64Alphabet(final boolean littleEndian) {
        super(littleEndian);
    }

    /**
     * Encode the given 6-bit value to a code point.
     *
     * @param val the 6-bit value
     * @return the Unicode code point
     */
    public abstract int encode(int val);

    /**
     * Decode the given code point.  If the code point is not valid, -1 is returned.
     *
     * @param codePoint the code point
     * @return the decoded 6-bit value or -1 if the code point is not valid
     */
    public abstract int decode(int codePoint);

    /**
     * The standard <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base-64 alphabet.
     */
    public static final Base64Alphabet STANDARD = new Base64Alphabet(false) {
        public int encode(final int val) {
            if (val <= 25) {
                return 'A' + val;
            } else if (val <= 51) {
                return 'a' + val - 26;
            } else if (val <= 61) {
                return '0' + val - 52;
            } else if (val == 62) {
                return '+';
            } else {
                assert val == 63;
                return '/';
            }
        }

        public int decode(final int codePoint) throws IllegalArgumentException {
            if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A';
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 26;
            } else if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0' + 52;
            } else if (codePoint == '+') {
                return 62;
            } else if (codePoint == '/') {
                return 63;
            } else {
                return -1;
            }
        }
    };
}


    private static char hex(int v) {
        return (char) (v < 10 ? '0' + v : 'a' + v - 10);
    }
	
	https://github.com/jmesnil/wildfly-common/tree/master/src/main/java/org/wildfly/common
==============================================================================================================
// -*- Mode: c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-

//

// Copyright (C) 2019 Opera Software AS.  All rights reserved.

//

// This file is an original work developed by Opera Software AS

 

import Resources from '../services/resources.js'

import Monday from './main.js'

 

document.ready().then(async () => {

  await Resources.load('startpage');

  if (!opr.Toolkit.isDebug()) {

    await loader.preload('modals/');

  }

  await Monday.init();

  opr.Toolkit.render(Monday, document.body);

});

window.addEventListener('keydown', evt => {

  if (evt.code === 'Tab') {

    document.documentElement.classList.add('keyboard-focus');

  }

}, true);

 

window.addEventListener('mousedown', evt => {

  document.documentElement.classList.remove('keyboard-focus');

}, true);
==============================================================================================================
import java.util.ArrayList;
import java.util.Collection;
import org.mocksy.Request;
import org.mocksy.Response;

public class ResponseRule implements Rule {
	private Collection<Matcher> matchers = new ArrayList<Matcher>();
	private Response response;

	public ResponseRule(Response response) {
		this.response = response;
		this.clear();
	}

	public void addMatcher(Matcher matcher) {
		this.matchers.add( matcher );
	}

	public boolean matches(Request request) {
		if ( this.matchers.isEmpty() ) return false;
		for ( Matcher matcher : this.matchers ) {
			if ( !matcher.matches( request ) ) return false;
		}
		return true;
	}

	public void clear() {
		this.matchers.clear();
	}

	public Response process(Request request) {
		return this.response;
	}

	public Collection<Matcher> getMatchers() {
		return this.matchers;
	}

	public Response getResponse() {
		return this.response;
	}
}
import io.github.benas.randombeans.EnhancedRandomBuilder;
import io.github.benas.randombeans.api.EnhancedRandom;
==============================================================================================================
import io.codearte.props2yaml.Props2YAML;
import org.yaml.snakeyaml.Yaml;

/**
 * Utility for converting a String of comma delimited property values to YAML.
 *
 * @author Ilayaperumal Gopinathan
 * @author Mark Pollack
 */
public abstract class YmlUtils {

	public static String convertFromCsvToYaml(String propertiesAsString) {
		String stringToConvert = propertiesAsString.replaceAll(",", "\n");
		String yamlString = Props2YAML.fromContent(stringToConvert).convert();
		// validate the yaml can be parsed
		Yaml yaml = new Yaml();
		yaml.load(yamlString);
		return yamlString;
	}
}
==============================================================================================================
spring.jmx.default-domain=domain-${RANDOM:1}
spring.jmx.enabled=false
==============================================================================================================
import java.io.Serializable;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * 实体基类,重写toString,hashCode,equals方法.
 * 
 * @author Credo
 * @date: 2014年8月12日
 */
public class BaseModel implements Serializable
{

	private static final long serialVersionUID = 6494888277191966864L;

	@Override
	public String toString()
	{
		return ToStringBuilder.reflectionToString(this);
	}

	@Override
	public int hashCode()
	{
		return HashCodeBuilder.reflectionHashCode(this);
	}

	@Override
	public boolean equals(Object obj)
	{
		return EqualsBuilder.reflectionEquals(this, obj);
	}
}



    @Transient
    public String getViewRoles() {
        StringBuilder sb = new StringBuilder();

        for (Iterator<Role> it = getRoles().iterator(); it.hasNext();) {
            sb.append(it.next().getName());
            if (it.hasNext())
                sb.append(", ");
        }

        return sb.toString();
    }
==============================================================================================================
@echo off
setlocal
set _RunOnceValue=%~d0%\Windows10Upgrade\Windows10UpgraderApp.exe /SkipSelfUpdate
set _RunOnceKey=Windows10UpgraderApp.exe
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /V "%_RunOnceKey%" /t REG_SZ /F /D "%_RunOnceValue%"
PowerShell -Command "&{ Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | ForEach-Object { $esdOriginalFilePath = 'D:\\Windows10Upgrade\\*.esd'; $driveName = $_.Name; $esdFilePath = $esdOriginalFilePath -replace '^\w',$driveName; if (Test-Path $esdFilePath) { Remove-Item $esdFilePath } } }"


@echo off
set _SafeOSPath=%~d0%\$GetCurrent\SafeOS
cd /d %_SafeOSPath%


@echo off
setlocalecho Delete rollback information ...
cd /d %~d0%\$GetCurrent\SafeOS
rundll32.exe GetCurrentOOBE.dll,GetCurrentOOBE_UpdateRollbackReason
rmdir /s /q %~d0%\$GetCurrent\media
rmdir /s /q %~d0%\$GetCurrent\Customization
PartnerSetupComplete.cmd > ..\Logs\PartnerSetupCompleteResult.log
==============================================================================================================
import org.infinispan.spring.provider.SpringEmbeddedCacheManagerFactoryBean;
import org.infinispan.spring.session.configuration.EnableInfinispanEmbeddedHttpSession;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.client.RestTemplate;

/**
 * @author kameshs
 */
@EnableInfinispanEmbeddedHttpSession(cacheName = "moviestore-sessions-cache")
@Configuration
@EnableCaching
@EnableConfigurationProperties(MovieStoreProps.class)
public class MovieStoreConfiguration {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

https://www.programcreek.com/java-api-examples/index.php?project_name=redhat-developer-demos%2Fpopular-movie-store#
==============================================================================================================
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafProperties;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ViewResolver;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

/**
 * @author kameshs
 */
@Configuration
@ConditionalOnClass({SpringTemplateEngine.class})
@EnableConfigurationProperties({ThymeleafProperties.class})
@AutoConfigureAfter({WebMvcAutoConfiguration.class})
public class ThymeleafConfiguration implements ApplicationContextAware {

    private ApplicationContext applicationContext;

    @Autowired
    private ThymeleafProperties properties;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Bean
    public ViewResolver viewResolver() {
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
        viewResolver.setOrder(Integer.MAX_VALUE);
        viewResolver.setTemplateEngine(templateEngine());
        viewResolver.setCharacterEncoding("UTF-8");
        return viewResolver;
    }

    @Bean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(templateResolver());
        return templateEngine;
    }

    private ITemplateResolver templateResolver() {
        SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
        templateResolver.setApplicationContext(applicationContext);
        templateResolver.setPrefix(this.properties.getPrefix());
        templateResolver.setSuffix(this.properties.getSuffix());
        templateResolver.setTemplateMode(this.properties.getMode());
        templateResolver.setCacheable(this.properties.isCache());
        return templateResolver;
    }
}
<infinispan xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="urn:infinispan:config:9.0 http://www.infinispan.org/schemas/infinispan-config-9.0.xsd"
            xmlns="urn:infinispan:config:9.0">

  <jgroups transport="org.infinispan.remoting.transport.jgroups.JGroupsTransport">
    <!-- This will be tcp for local mode and kubernetes for cloud mode -->
    <stack-file name="configurationFile" path="default-configs/default-jgroups-kubernetes.xml"/>
  </jgroups>

  <cache-container name="clustered" default-cache="popular-movies-cache" statistics="true">

    <transport stack="configurationFile" cluster="PopularMovieStore" lock-timeout="60000"/>

    <!-- The cache that manages HTTP session-->
    <distributed-cache name="moviestore-sessions-cache" mode="SYNC" start="EAGER" statistics="true">
      <store-as-binary keys="true" values="true"/>
    </distributed-cache>

    <!-- Cache that will hold the movie details fetched via moviedb api -->
    <distributed-cache name="popular-movies-cache" mode="SYNC" start="EAGER" statistics="true">
      <expiration lifespan="86400000"/>
    </distributed-cache>

  </cache-container>


</infinispan>
==============================================================================================================
import java.security.MessageDigest;

/**
 * md5加密工具类
 * @author Jeff Xu
 * @since 2015-12-09
 */
public class Md5Util {
	
	//十六进制下数字到字符的映射数组  
    private final static String[] hexDigits = {"0", "1", "2", "3", "4",  
        "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};  
      
    /** * 把inputString加密     */  
    public static String generatePassword(String inputString){  
        return encodeByMD5(inputString);  
    }  
      
      /** 
       * 验证输入的密码是否正确 
     * @param password    加密后的密码 
     * @param inputString    输入的字符串 
     * @return    验证结果，TRUE:正确 FALSE:错误 
     */  
    public static boolean validatePassword(String password, String inputString){  
        if(password.equalsIgnoreCase(encodeByMD5(inputString))){  
            return true;  
        } else{  
            return false;  
        }  
    }  
    /**  对字符串进行MD5加密     */  
    private static String encodeByMD5(String originString){  
        if (originString != null){  
            try{  
                //创建具有指定算法名称的信息摘要  
                MessageDigest md = MessageDigest.getInstance("MD5");  
                //使用指定的字节数组对摘要进行最后更新，然后完成摘要计算  
                byte[] results = md.digest(originString.getBytes());  
                //将得到的字节数组变成字符串返回  
                String resultString = byteArrayToHexString(results);  
                return resultString.toUpperCase();  
            } catch(Exception ex){  
                ex.printStackTrace();  
            }  
        }  
        return null;  
    }  
      
    /**  
     * 转换字节数组为十六进制字符串 
     * @param     字节数组 
     * @return    十六进制字符串 
     */  
    private static String byteArrayToHexString(byte[] b){  
        StringBuffer resultSb = new StringBuffer();  
        for (int i = 0; i < b.length; i++){  
            resultSb.append(byteToHexString(b[i]));  
        }  
        return resultSb.toString();  
    }  
      
    /** 将一个字节转化成十六进制形式的字符串     */  
    private static String byteToHexString(byte b){  
        int n = b;  
        if (n < 0)  
            n = 256 + n;  
        int d1 = n / 16;  
        int d2 = n % 16;  
        return hexDigits[d1] + hexDigits[d2];  
    } 
    
    public static void main(String[] args){
    	System.out.println(Md5Util.validatePassword("454E908651395FB737E9B8048993C95D", "zhangdanfeng"));
    }
}
==============================================================================================================
python -m django --version
pipenv install -e git+https://github.com/requests/requests.git#egg=requests
pip freeze > requirements.txt
pipenv lock -r
pip install -r requirements.txt
pipenv install -r dev-requirements.txt --dev
$ pipenv lock -r > requirements.txt
$ pipenv lock -r -d > dev-requirements.txt

python -m pip install --user pipenv
$ pipenv shell --three
$ pipenv install django-cors-headers


pipenv install django
pipenv install djangorestframework
pipenv install django-cors-headers
django-admin.py startproject backend
python manage.py migrate
python manage.py runserver
pipenv run python app/manage.py runserver

https://dev.to/yukinagae/your-first-guide-to-getting-started-with-pipenv-50bn
https://www.techiediaries.com/pipenv-tutorial/
==============================================================================================================
import org.springframework.hateoas.VndErrors;

/**
 * A Java exception that wraps the serialized {@link VndErrors} object.
 *
 * @author Eric Bottard
 * @author Mark Fisher
 */
@SuppressWarnings("serial")
public class DataFlowClientException extends RuntimeException {

	private VndErrors vndErrors;

	public DataFlowClientException(VndErrors error) {
		this.vndErrors = error;
	}

	@Override
	public String getMessage() {
		StringBuilder builder = new StringBuilder();
		for (VndErrors.VndError e : vndErrors) {
			builder.append(e.getMessage()).append('\n');
		}
		return builder.toString();
	}
}

import java.io.IOException;
import java.util.List;

import org.springframework.hateoas.VndErrors;
import org.springframework.hateoas.VndErrors.VndError;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.ResponseExtractor;

/**
 * Extension of {@link DefaultResponseErrorHandler} that knows how to de-serialize a
 * {@link VndError} structure.
 *
 * @author Eric Bottard
 * @author Gunnar Hillert
 */
public class VndErrorResponseErrorHandler extends DefaultResponseErrorHandler {

	private ResponseExtractor<VndErrors> vndErrorsExtractor;

	private ResponseExtractor<VndError> vndErrorExtractor;

	public VndErrorResponseErrorHandler(List<HttpMessageConverter<?>> messageConverters) {
		vndErrorsExtractor = new HttpMessageConverterExtractor<VndErrors>(VndErrors.class, messageConverters);
		vndErrorExtractor = new HttpMessageConverterExtractor<VndError>(VndError.class, messageConverters);
	}

	@Override
	public void handleError(ClientHttpResponse response) throws IOException {
		VndErrors vndErrors = null;
		try {
			if (HttpStatus.FORBIDDEN.equals(response.getStatusCode())) {
				vndErrors = new VndErrors(vndErrorExtractor.extractData(response));
			}
			else {
				vndErrors = vndErrorsExtractor.extractData(response);
			}
		}
		catch (Exception e) {
			super.handleError(response);
		}
		throw new DataFlowClientException(vndErrors);
	}
}

import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.cloud.dataflow.rest.Version;
import org.springframework.hateoas.ResourceSupport;

/**
 * Describes the other available resource endpoints, as well as provides information about
 * the server itself, such as API revision number.
 *
 * @author Eric Bottard
 */
public class RootResource extends ResourceSupport {

	private Integer apiRevision;

	// For JSON un-marshalling
	private RootResource() {
	}

	public RootResource(int apiRevision) {
		this.apiRevision = apiRevision;
	}

	@JsonProperty(Version.REVISION_KEY)
	public Integer getApiRevision() {
		return apiRevision;
	}

	public void setApiRevision(int apiRevision) {
		this.apiRevision = apiRevision;
	}
}

import org.springframework.hateoas.PagedResources;
import org.springframework.hateoas.ResourceSupport;

/**
 * Rest resource for an app registration.
 *
 * @author Glenn Renfro
 * @author Mark Fisher
 * @author Patrick Peralta
 */
public class AppRegistrationResource extends ResourceSupport {

	/**
	 * App name.
	 */
	private String name;

	/**
	 * App type.
	 */
	private String type;

	/**
	 * URI for app resource, such as {@code maven://groupId:artifactId:version}.
	 */
	private String uri;

	/**
	 * App version.
	 */
	private String version;

	/**
	 * Is default app version for all (name, type) applications
	 */
	private Boolean defaultVersion;


	/**
	 * Default constructor for serialization frameworks.
	 */
	protected AppRegistrationResource() {
	}

	public AppRegistrationResource(String name, String type, String uri) {
		this(name, type, null, uri, false);
	}

	/**
	 * Construct a {@code AppRegistrationResource}.
	 *
	 * @param name app name
	 * @param type app type
	 * @param version app version
	 * @param uri uri for app resource
	 * @param defaultVersion is this application selected to the be default version in DSL
	 */
	public AppRegistrationResource(String name, String type, String version, String uri, Boolean defaultVersion) {
		this.name = name;
		this.type = type;
		this.version = version;
		this.uri = uri;
		this.defaultVersion = defaultVersion;
	}

	/**
	 * @return the name of the app
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return type type of the app
	 */
	public String getType() {
		return type;
	}

	/**
	 * @return type URI for the app resource
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * @return version of the app
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * @return if this app selected to be the default
	 */
	public Boolean getDefaultVersion() {
		return defaultVersion;
	}

	/**
	 * Dedicated subclass to workaround type erasure.
	 */
	public static class Page extends PagedResources<AppRegistrationResource> {
	}

}
import java.util.Map;

import org.springframework.hateoas.ResourceSupport;

/**
 * REST representation for an AppInstanceStatus.
 *
 * @author Eric Bottard
 * @author Mark Fisher
 */
public class AppInstanceStatusResource extends ResourceSupport {

	private String instanceId;

	private String state;

	private Map<String, String> attributes;

	private AppInstanceStatusResource() {
		// noarg constructor for serialization
	}

	public AppInstanceStatusResource(String instanceId, String state, Map<String, String> attributes) {
		this.instanceId = instanceId;
		this.state = state;
		this.attributes = attributes;
	}

	public String getInstanceId() {
		return instanceId;
	}

	public void setInstanceId(String instanceId) {
		this.instanceId = instanceId;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Map<String, String> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, String> attributes) {
		this.attributes = attributes;
	}
}
import org.springframework.batch.core.StepExecution;
import org.springframework.hateoas.PagedResources;
import org.springframework.hateoas.ResourceSupport;
import org.springframework.util.Assert;

/**
 * @author Glenn Renfro
 */
public class StepExecutionResource extends ResourceSupport {

	private final Long jobExecutionId;

	private final StepExecution stepExecution;

	private final String stepType;

	/**
	 * Create a new StepExecutionResource
	 *
	 * @param jobExecutionId the job execution id, must not be null
	 * @param stepExecution the step execution, must not be null
	 * @param stepType the step type
	 */
	public StepExecutionResource(Long jobExecutionId, StepExecution stepExecution, String stepType) {

		Assert.notNull(jobExecutionId, "jobExecutionId must not be null.");
		Assert.notNull(stepExecution, "stepExecution must not be null.");

		this.stepExecution = stepExecution;
		this.jobExecutionId = jobExecutionId;
		this.stepType = stepType;
	}

	/**
	 * Default constructor to be used by Jackson.
	 */
	private StepExecutionResource() {
		this.stepExecution = null;
		this.jobExecutionId = null;
		this.stepType = null;
	}

	/**
	 * @return The jobExecutionId, which will never be null
	 */
	public Long getJobExecutionId() {
		return this.jobExecutionId;
	}

	/**
	 * @return The stepExecution, which will never be null
	 */
	public StepExecution getStepExecution() {
		return stepExecution;
	}

	public String getStepType() {
		return this.stepType;
	}

	public static class Page extends PagedResources<StepExecutionResource> {
	}

}
==============================================================================================================
import javax.xml.bind.annotation.XmlRootElement;

import org.atteo.classindex.ClassIndex;
import org.atteo.moonshine.TopLevelService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.Singleton;

/**
 * Registers application modules that are annotated with {@link GlobalModule}
 */
@XmlRootElement(name = "global-modules")
@Singleton
public class GlobalModulesService extends TopLevelService {
	private final static Logger logger = LoggerFactory.getLogger(GlobalModulesService.class);

	@Override
	public Module configure() {
		return new AbstractModule() {
			@Override
			protected void configure() {
				for (Class<?> moduleClass : ClassIndex.getAnnotated(GlobalModule.class)) {
					if (!Module.class.isAssignableFrom(moduleClass)) {
						throw new IllegalStateException("Class " + moduleClass.getName()
								+ " is annotated as @" + GlobalModule.class.getSimpleName()
								+ " but doesn't implement "
								+ Module.class.getCanonicalName());
					}

					logger.trace("Found @AppModule [{}].", moduleClass.getName());
					Module module;
					try {
						module = (Module)moduleClass.newInstance();
					} catch (IllegalAccessException | InstantiationException e) {
						throw new IllegalStateException("Could not instantiate AppModule {}" + moduleClass.getName(),
								e);
					}
					install(module);
				}
			}
		};
	}
}

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.inject.Singleton;

import org.atteo.classindex.IndexAnnotated;

/**
 * MBean marker interface.
 *
 * <p>
 * Any annotated classes will be discovered and registered by {@link JMX} service as MBean.
 * By convention any such class should implement an interface with the same name
 * with the suffix <i>MBean</i> added (see <a href="http://download.oracle.com/javase/tutorial/jmx/mbeans/standard.html">JMX tutorial</a>).
 * </p>
 * <p>
 * Additionally annotated class will be registered in Guice with {@link Singleton} scope.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@IndexAnnotated
public @interface MBean {
	/**
	 * Name that the MBean will be registered with.
	 * <p>
	 * If not specified, one will be generated based on full class name of the annotated class.
	 * </p>
	 */
	String name() default "";
}
==============================================================================================================
import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.Provider;
import com.google.inject.persist.PersistService;
import com.google.inject.servlet.RequestScoped;
import com.orientechnologies.orient.core.config.OGlobalConfiguration;
import com.orientechnologies.orient.core.db.document.ODatabaseDocumentPool;
import com.orientechnologies.orient.core.db.document.ODatabaseDocumentTx;
import org.atteo.config.XmlDefaultValue;
import org.atteo.moonshine.TopLevelService;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "orientdb")
public class OrientDb extends TopLevelService {
	@XmlElement(name = "url")
	@XmlDefaultValue("local:${dataHome}/orientdb")
	private String url;

	@XmlElement(name = "autocreate")
	@XmlDefaultValue("true")
	private Boolean autocreate;

	@XmlElement
	@XmlDefaultValue("admin")
	private String username;

	@XmlElement
	@XmlDefaultValue("admin")
	private String password;

	@XmlElement(name = "pool-timeout")
	@XmlDefaultValue("600000")
	private Integer poolTimeout;

	private PersistService persistService;

	private Provider<ODatabaseDocumentTx> provider = new Provider<ODatabaseDocumentTx>() {
		@Override
		public ODatabaseDocumentTx get() {
			return ODatabaseDocumentPool.global().acquire(url, username, password);
		}
	};

	public String getUrl() {
		return url;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public Boolean getAutocreate() {
		return autocreate;
	}

	@Override
	public Module configure() {
		return new AbstractModule() {
			@Override
			protected void configure() {
				OGlobalConfiguration.CLIENT_CONNECT_POOL_WAIT_TIMEOUT.setValue(poolTimeout);
				bind(ODatabaseDocumentTx.class).toProvider(provider).in(RequestScoped.class);
			}
		};
	}

	@Override
	public void start() {
		if (getAutocreate()) {
			ODatabaseDocumentTx db = new ODatabaseDocumentTx(url);
			if (!db.exists()) {
				db.create();
			}
			db.close();
		}
	}

	@Override
	public void stop() {
	}
}

import javax.inject.Inject;
import javax.sql.DataSource;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlRootElement;

import org.atteo.moonshine.database.DatabaseService;
import org.atteo.moonshine.jta.JtaDataSourceWrapper;
import org.atteo.moonshine.jta.JtaService;
import org.atteo.moonshine.jta.PoolOptions;
import org.atteo.moonshine.services.ImportService;
import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.ds.common.BaseDataSource;
import org.postgresql.xa.PGXADataSource;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.Provider;
import com.google.inject.Scopes;

/**
 * Connects to the PostgreSQL database.
 */
@XmlRootElement(name = "postgresql")
public class PostgreSQLService extends DatabaseService {
	@ImportService
	@XmlIDREF
	@XmlElement
	private JtaService jta;

	/**
	 * Sets the name of the PostgreSQL database, running on the server identified by the serverName property.
	 */
	@XmlElement(required = true)
	private String databaseName;

	/**
	 * Sets the name of the host the PostgreSQL database is running on. The default value is localhost.
	 */
	@XmlElement
	private String serverName;

	/**
	 * Sets the port which the PostgreSQL server is listening on for TCP/IP connections.
	 */
	@XmlElement
	private Integer portNumber;

	/**
	 * Database user.
	 */
	@XmlElement
	private String user = "";

	/**
	 * Database password.
	 */
	@XmlElement
	private String password = "";

	/**
	 * Connection pool options.
	 */
	@XmlElement
	private PoolOptions pool;

	@XmlElement
	private String testQuery = "select 1";

	@Inject
	private JtaDataSourceWrapper wrapper;

	private DataSource dataSource;

	private class DataSourceProvider implements Provider<DataSource> {
		@Inject
		private JtaDataSourceWrapper wrapper;

		private void configure(BaseDataSource dataSource) {
			dataSource.setDatabaseName(databaseName);
			if (serverName != null) {
				dataSource.setServerName(serverName);
			}
			if (portNumber != null) {
				dataSource.setPortNumber(portNumber);
			}

			if (user != null) {
				dataSource.setUser(user);
			}

			if (password != null) {
				dataSource.setPassword(password);
			}
		}

		@Override
		public DataSource get() {
			final PGSimpleDataSource migrationDataSource = new PGSimpleDataSource();
			configure(migrationDataSource);
			executeMigrations(migrationDataSource);

			final PGXADataSource xaDataSource = new PGXADataSource();
			configure(xaDataSource);

			String name = "defaultDataSource";
			if (getId() != null) {
				name = getId();
			}
			dataSource = wrapper.wrap(name, xaDataSource, pool, testQuery);
			return dataSource;
		}
	}

	@Override
	public Module configure() {
		return new AbstractModule() {
			@Override
			
			import java.util.List;
import java.util.Map;

import com.jeff.tianti.common.dao.CustomBaseSqlDaoImpl;
import com.jeff.tianti.org.entity.Resource;

public class ResourceDaoImpl extends CustomBaseSqlDaoImpl implements ResourceDaoCustom {

	@SuppressWarnings("unchecked")
	@Override
	public List<Resource> findMenuResource(Map<String, Object> params) {
		
		StringBuilder sb = new StringBuilder();
		sb.append("select r from Resource r where r.type in('module', 'page') ");
		
		Object deleteFlag = params.get("deleteFlag");
		if(deleteFlag != null){
			sb.append(" and r.deleteFlag = :deleteFlag ");
		}

		Object name = params.get("name");
		if(name != null){
			sb.append(" and r.name like :name ");
		}
		
		sb.append(" order by r.orderNo ");
		
		return this.queryByMapParams(sb.toString(), params, null, null);
	}

}
			protected void configure() {
				bind(DataSource.class).toProvider(new DataSourceProvider()).in(Scopes.SINGLETON);
			}
		};
	}

	@Override
	public void close() {
		if (dataSource != null) {
			wrapper.close(dataSource);
		}
	}
}

   private final Jackson2ResourceReader resourceReader;
    private final Resource sourceData;

    private ApplicationContext applicationContext;

    public AlbumRepositoryPopulator() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        resourceReader = new Jackson2ResourceReader(mapper);
        sourceData = new ClassPathResource("albums.json");
    }
==============================================================================================================
#!/bin/sh
#
# Copyright (c) 2012-2015 Andrea Selva
#

echo "                                                                         "
echo "  ___  ___                       _   _        ___  ________ _____ _____  "
echo "  |  \/  |                      | | | |       |  \/  |  _  |_   _|_   _| "
echo "  | .  . | ___   __ _ _   _  ___| |_| |_ ___  | .  . | | | | | |   | |   "
echo "  | |\/| |/ _ \ / _\ | | | |/ _ \ __| __/ _ \ | |\/| | | | | | |   | |   "
echo "  | |  | | (_) | (_| | |_| |  __/ |_| ||  __/ | |  | \ \/' / | |   | |   "
echo "  \_|  |_/\___/ \__, |\__,_|\___|\__|\__\___| \_|  |_/\_/\_\ \_/   \_/   "
echo "                   | |                                                   "
echo "                   |_|                                                   "
echo "                                                                         "


cd "$(dirname "$0")"

# resolve links - $0 may be a softlink
PRG="$0"

while [ -h "$PRG" ]; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done

# Get standard environment variables
PRGDIR=`dirname "$PRG"`

# Only set MOQUETTE_HOME if not already set
[ -f "$MOQUETTE_HOME"/bin/moquette.sh ] || MOQUETTE_HOME=`cd "$PRGDIR/.." ; pwd`
export MOQUETTE_HOME

# Set JavaHome if it exists
if [ -f "${JAVA_HOME}/bin/java" ]; then 
   JAVA=${JAVA_HOME}/bin/java
else
   JAVA=java
fi
export JAVA

LOG_FILE=$MOQUETTE_HOME/config/moquette-log.properties
MOQUETTE_PATH=$MOQUETTE_HOME/
#LOG_CONSOLE_LEVEL=info
#LOG_FILE_LEVEL=fine
JAVA_OPTS_SCRIPT="-XX:+HeapDumpOnOutOfMemoryError -Djava.awt.headless=true"

## Use the Hotspot garbage-first collector.
JAVA_OPTS="$JAVA_OPTS -XX:+UseG1GC"

## Have the JVM do less remembered set work during STW, instead
## preferring concurrent GC. Reduces p99.9 latency.
JAVA_OPTS="$JAVA_OPTS -XX:G1RSetUpdatingPauseTimePercent=5"

## Main G1GC tunable: lowering the pause target will lower throughput and vise versa.
## 200ms is the JVM default and lowest viable setting
## 1000ms increases throughput. Keep it smaller than the timeouts.
JAVA_OPTS="$JAVA_OPTS -XX:MaxGCPauseMillis=500"

## Optional G1 Settings

# Save CPU time on large (>= 16GB) heaps by delaying region scanning
# until the heap is 70% full. The default in Hotspot 8u40 is 40%.
#JAVA_OPTS="$JAVA_OPTS -XX:InitiatingHeapOccupancyPercent=70"

# For systems with > 8 cores, the default ParallelGCThreads is 5/8 the number of logical cores.
# Otherwise equal to the number of cores when 8 or less.
# Machines with > 10 cores should try setting these to <= full cores.
#JAVA_OPTS="$JAVA_OPTS -XX:ParallelGCThreads=16"

# By default, ConcGCThreads is 1/4 of ParallelGCThreads.
# Setting both to the same value can reduce STW durations.
#JAVA_OPTS="$JAVA_OPTS -XX:ConcGCThreads=16"

### GC logging options -- uncomment to enable

JAVA_OPTS="$JAVA_OPTS -XX:+PrintGCDetails"
JAVA_OPTS="$JAVA_OPTS -XX:+PrintGCDateStamps"
JAVA_OPTS="$JAVA_OPTS -XX:+PrintHeapAtGC"
JAVA_OPTS="$JAVA_OPTS -XX:+PrintTenuringDistribution"
JAVA_OPTS="$JAVA_OPTS -XX:+PrintGCApplicationStoppedTime"
JAVA_OPTS="$JAVA_OPTS -XX:+PrintPromotionFailure"
#JAVA_OPTS="$JAVA_OPTS -XX:PrintFLSStatistics=1"
#JAVA_OPTS="$JAVA_OPTS -Xloggc:/var/log/moquette/gc.log"
JAVA_OPTS="$JAVA_OPTS -XX:+UseGCLogFileRotation"
JAVA_OPTS="$JAVA_OPTS -XX:NumberOfGCLogFiles=10"
JAVA_OPTS="$JAVA_OPTS -XX:GCLogFileSize=10M"

$JAVA -server $JAVA_OPTS $JAVA_OPTS_SCRIPT -Dlog4j.configuration="file:$LOG_FILE" -Dmoquette.path="$MOQUETTE_PATH" -cp "$MOQUETTE_HOME/lib/*" io.moquette.server.Server


language: java
jdk:
  - openjdk12
before_cache:
  - rm -f  $HOME/.gradle/caches/modules-2/modules-2.lock
  - rm -fr $HOME/.gradle/caches/*/plugin-resolution/
cache:
  directories:
    - $HOME/.gradle/caches/
    - $HOME/.gradle/wrapper/

script:
    - ./gradlew install test
==============================================================================================================
https://www.programcreek.com/java-api-examples/index.php?project_name=JesseFarebro%2Fandroid-mqtt#
==============================================================================================================
git config --global push.default matching
git config --global push.default simple
==============================================================================================================
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.lang.System.identityHashCode;
import static org.apache.maven.plugins.annotations.LifecyclePhase.POST_INTEGRATION_TEST;
import static org.apache.maven.plugins.annotations.ResolutionScope.TEST;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.kaazing.k3po.driver.internal.RobotServer;

@Mojo(name = "stop", defaultPhase = POST_INTEGRATION_TEST, requiresDependencyResolution = TEST)
public class StopMojo extends AbstractMojo {

    protected void executeImpl() throws MojoExecutionException {

        RobotServer server = getServer();
        if (server == null) {
            getLog().error(format("K3PO not running"));
        }
        else {
            try {
                long checkpoint = currentTimeMillis();
                server.stop();
                float duration = (currentTimeMillis() - checkpoint) / 1000.0f;
                getLog().debug(format("K3PO [%08x] stopped in %.3fsec", identityHashCode(server), duration));

                setServer(null);
            }
            catch (Exception e) {
                throw new MojoExecutionException(format("K3PO [%08x] failed to stop", identityHashCode(server)), e);
            }
        }
    }
}
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.lang.Thread.currentThread;
import static org.apache.maven.plugins.annotations.LifecyclePhase.PRE_INTEGRATION_TEST;
import static org.apache.maven.plugins.annotations.ResolutionScope.TEST;
import static org.jboss.netty.logging.InternalLoggerFactory.setDefaultFactory;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.kaazing.k3po.driver.internal.RobotServer;
import org.kaazing.k3po.maven.plugin.internal.logging.MavenLoggerFactory;

/**
 * Start K3PO
 */
@Mojo(name = "start", defaultPhase = PRE_INTEGRATION_TEST, requiresDependencyResolution = TEST)
public class StartMojo extends AbstractMojo {

    @Parameter(defaultValue = "true", property = "maven.k3po.daemon")
    private boolean daemon;

    @Parameter(name = "control", defaultValue = "tcp://localhost:11642")
    private URI controlURI;

    @Parameter(defaultValue = "src/test/scripts")
    private File scriptDir;

    @Parameter(defaultValue = "false", property = "maven.k3po.verbose")
    private boolean verbose;

    @Parameter(property = "basedir")
    private File workingDirectory;

    public URI getControl() {
        return controlURI;
    }

    public void setControl(URI controlURI) {
        this.controlURI = controlURI;
    }

    @Override
    protected void executeImpl() throws MojoExecutionException {

        final ClassLoader contextClassLoader = currentThread().getContextClassLoader();

        try {
            Log log = getLog();
            if (log.isDebugEnabled()) {
                log.debug(format("Setting System property \"user.dir\" to [%s]", workingDirectory.getAbsolutePath()));
            }
            System.setProperty("user.dir", workingDirectory.getAbsolutePath());

            ClassLoader testClassLoader = createTestClassLoader();

            RobotServer server = new RobotServer(getControl(), verbose, testClassLoader);

            Map<?, ?> pluginsAsMap = project.getBuild().getPluginsAsMap();
            Plugin plugin = (Plugin) pluginsAsMap.get("org.kaazing:k3po-maven-plugin");
            if (plugin != null)
            {
                for (Dependency dependency : plugin.getDependencies())
                {
                    if (project.getGroupId().equals(dependency.getGroupId()) &&
                            project.getArtifactId().equals(dependency.getArtifactId()) &&
                            project.getVersion().equals(dependency.getVersion()))
                    {
                        // load extensions from project
                        currentThread().setContextClassLoader(testClassLoader);
                    }
                }
            }

            // TODO: detect Maven version to determine logger factory
            //         3.0 -> MavenLoggerFactory
            //         3.1 -> Slf4JLoggerFactory
            // see http://brettporter.wordpress.com/2010/10/05/creating-a-custom-build-extension-for-maven-3-0/

            // note: using SLf4J for Robot breaks in Maven 3.0 at runtime
            // setDefaultFactory(new Slf4JLoggerFactory());

            // use Maven3 logger for Robot when started via plugin
            setDefaultFactory(new MavenLoggerFactory(log));

            long checkpoint = currentTimeMillis();
            server.start();
            float duration = (currentTimeMillis() - checkpoint) / 1000.0f;
            if (log.isDebugEnabled()) {
                String version = (plugin != null) ? plugin.getVersion() : "unknown";
                if (!daemon) {
                    log.debug(format("K3PO [%s] started in %.3fsec (CTRL+C to stop)", version, duration));
                }
                else {
                    log.debug(format("K3PO [%s] started in %.3fsec", version, duration));
                }
            } else {
                if (!daemon) {
                    log.info("K3PO started (CTRL+C to stop)");
                }
                else {
                    log.info("K3PO started");
                }
            }

            setServer(server);

            if (!daemon) {
                server.join();
            }
        }
        catch (Exception e) {
            throw new MojoExecutionException("K3PO failed to start", e);
        }
        finally
        {
            currentThread().setContextClassLoader(contextClassLoader);
        }
    }

    private ClassLoader createTestClassLoader()
            throws DependencyResolutionRequiredException, MalformedURLException {
        List<URL> scriptPath = new LinkedList<>();
        if (scriptDir != null) {
            scriptPath.add(scriptDir.getAbsoluteFile().toURI().toURL());
        }
        for (Object scriptPathEntry : project.getTestClasspathElements()) {
            URI scriptPathURI = new File(scriptPathEntry.toString()).getAbsoluteFile().toURI();
            scriptPath.add(scriptPathURI.toURL());
        }

        ClassLoader parent = getClass().getClassLoader();
        return new URLClassLoader(scriptPath.toArray(new URL[scriptPath.size()]), parent);
    }
}

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.kaazing.k3po.driver.internal.RobotServer;

/**
 * Abstract base class for Robot goals
 */
public abstract class AbstractMojo extends org.apache.maven.plugin.AbstractMojo {

    private static final ThreadLocal<RobotServer> ROBOT_SERVER = new ThreadLocal<>();

    @Parameter(defaultValue = "${project}", readonly = true)
    protected MavenProject project;

    @Parameter(defaultValue = "false", property = "skipTests")
    private boolean skipTests;

    @Parameter(defaultValue = "false", property = "skipITs")
    private boolean skipITs;

    @Override
    public final void execute() throws MojoExecutionException, MojoFailureException {

        if (skipTests || skipITs) {
            getLog().info("Tests are skipped");
            return;
        }

        executeImpl();
    }

    protected abstract void executeImpl() throws MojoExecutionException, MojoFailureException;

    protected void setServer(RobotServer server) {
        if (server == null) {
            ROBOT_SERVER.remove();
        }
        else {
            ROBOT_SERVER.set(server);
        }
    }

    protected RobotServer getServer() {
        return ROBOT_SERVER.get();
    }

}

import org.apache.maven.plugin.logging.Log;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class MavenLoggerFactory extends InternalLoggerFactory {

    private final Log logger;

    public MavenLoggerFactory(Log logger) {
        this.logger = logger;
    }

    @Override
    public InternalLogger newInstance(String name) {
        return new MavenLogger(logger);
    }
}

==============================================================================================================
tcpdump -i <interface> -s 0 -w <some-file>
tshark -T pdml -r inputfile.cap -V -d tcp.port==8000,http | tee outputfile.pdml

java -jar target/com.kaazing.k3po.pcap.converter-develop-SNAPSHOT-jar-with-dependencies.jar <tcpDumpFile> <pdmlFile>

https://github.com/k3po/k3po/tree/develop/k3po.pcap.converter
==============================================================================================================
    @RequestMapping(value = "/sigfox/{deviceTypeId}", method = RequestMethod.POST)
    public void handleSigfoxRequest(@PathVariable String deviceTypeId,
                              @RequestHeader(TOKEN_HEADER) String token,
                              @RequestBody String body) throws Exception {
        service.processRequest(deviceTypeId, token, body);
    }
	
	    public static void putToNode(ObjectNode node, KvEntry kv) {
        switch (kv.getDataType()) {
            case BOOLEAN:
                node.put(kv.getKey(), kv.getBooleanValue().get());
                break;
            case STRING:
                node.put(kv.getKey(), kv.getStrValue().get());
                break;
            case LONG:
                node.put(kv.getKey(), kv.getLongValue().get());
                break;
            case DOUBLE:
                node.put(kv.getKey(), kv.getDoubleValue().get());
                break;
        }
    }
	import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.thingsboard.server.common.data.kv.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Created by ashvayka on 19.01.17.
 */
public class JsonTools {

    private static final ObjectMapper JSON = new ObjectMapper();

    public static ObjectNode newNode() {
        return JSON.createObjectNode();
    }

    public static byte[] toBytes(ObjectNode node) {
        return toString(node).getBytes(StandardCharsets.UTF_8);
    }

    public static JsonNode fromString(String data) {
        try {
            return JSON.readTree(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String toString(JsonNode node) {
        try {
            return JSON.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static void putToNode(ObjectNode node, KvEntry kv) {
        switch (kv.getDataType()) {
            case BOOLEAN:
                node.put(kv.getKey(), kv.getBooleanValue().get());
                break;
            case STRING:
                node.put(kv.getKey(), kv.getStrValue().get());
                break;
            case LONG:
                node.put(kv.getKey(), kv.getLongValue().get());
                break;
            case DOUBLE:
                node.put(kv.getKey(), kv.getDoubleValue().get());
                break;
        }
    }

    public static List<KvEntry> getKvEntries(JsonNode data) {
        List<KvEntry> attributes = new ArrayList<>();
        for (Iterator<Map.Entry<String, JsonNode>> it = data.fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> field = it.next();
            String key = field.getKey();
            JsonNode value = field.getValue();
            if (value.isBoolean()) {
                attributes.add(new BooleanDataEntry(key, value.asBoolean()));
            } else if (value.isLong()) {
                attributes.add(new LongDataEntry(key, value.asLong()));
            } else if (value.isDouble()) {
                attributes.add(new DoubleDataEntry(key, value.asDouble()));
            } else {
                attributes.add(new StringDataEntry(key, value.asText()));
            }
        }
        return attributes;
    }
}
==============================================================================================================
import java.util.HashMap;
import java.util.Map;

public class MonitoredMap<K,V> extends HashMap<K,V> {
    @Override
    public V put(K k, V v) {
        V ret = super.put(k, v);
        PromMetrics.mqtt_sessions.set(this.size());
        return ret;
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> map) {
        super.putAll(map);
        PromMetrics.mqtt_sessions.set(this.size());
    }

    @Override
    public V remove(Object k) {
        V ret = super.remove(k);
        PromMetrics.mqtt_sessions.set(this.size());
        return ret;
    }
}
==============================================================================================================
import java.util.List;

/**
 * Created by giova_000 on 19/02/2015.
 */
class TokenInfo {
    private String authorizedUser;
    private List<String> scope;
    private Long expiryTime;
    private String errorMsg;

    String getAuthorizedUser() {
        return authorizedUser;
    }

    void setAuthorizedUser(String authorizedUser) {
        this.authorizedUser = authorizedUser;
    }

    List<String> getScope() {
        return scope;
    }

    void setScope(List<String> scope) {
        this.scope = scope;
    }

    Long getExpiryTime() {
        return expiryTime;
    }

    void setExpiryTime(Long expiryTime) {
        this.expiryTime = expiryTime;
    }

    String getErrorMsg() {
        return errorMsg;
    }

    void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    @Override
    public String toString() {
        return authorizedUser +" ["+expiryTime+" "+scope+" "+errorMsg+"]";
    }
}

confluent-hub install confluentinc/kafka-connect-mqtt:1.1.0-preview
confluent-hub install confluentinc/kafka-connect-mqtt:1.2.3
==============================================================================================================
apply plugin: 'com.github.ben-manes.versions'

subprojects {

    apply plugin: 'java'
    apply plugin: 'maven'

    // Group Id
    group 'com.github.longkerdandy'

    // Version
    version '1.1.0.Beta1-SNAPSHOT'

    // JDK
    sourceCompatibility = 1.8

    // Encoding
    tasks.withType(JavaCompile) { options.encoding = 'UTF-8' }

    // Maven Repository
    repositories {
        mavenCentral();
    }

    // Dependencies
    dependencies {
        // apache commons
        compile 'org.apache.commons:commons-lang3:3.4'
        compile 'commons-configuration:commons-configuration:1.10'

        // logger
        compile 'org.slf4j:slf4j-api:1.7.21'
        compile 'ch.qos.logback:logback-core:1.1.7'
        compile 'ch.qos.logback:logback-classic:1.1.7'

        // junit
        testCompile 'junit:junit:4.12'

        // mock
        compile 'org.mockito:mockito-all:1.10.19'
        compile 'org.easymock:easymock:3.4'
    }
}

// gradle version plugin
buildscript {
    repositories {
        jcenter()
    }

    dependencies {
        classpath 'com.github.ben-manes:gradle-versions-plugin:0.13.0'
    }
}

dependencyUpdates.resolutionStrategy = {
    componentSelection { rules ->
        rules.all { ComponentSelection selection ->
            boolean rejected = ['alpha', 'beta', 'rc', 'cr', 'm'].any { qualifier ->
                selection.candidate.version ==~ /(?i).*[.-]${qualifier}[.\d-]*/
            }
            if (rejected) {
                selection.reject('Release candidate')
            }
        }
    }
}
==============================================================================================================
/**
 * Redis Lua Script
 */
public class RedisLua {

    // Increments the number stored at key by one with limit
    // Reset to 0 if limit reached (exceeded)
    //
    // Keys 1. Key to be increased
    // Args 1. Maximum number stored at key
    // Returns Number stored at key after increment
    public static final String INCRLIMIT =
            "local cnt = redis.call('INCR', KEYS[1])\n" +
                    "if tonumber(ARGV[1]) > 0 and cnt >= tonumber(ARGV[1])\n" +
                    "then\n" +
                    "   redis.call('SET', KEYS[1], '0')\n" +
                    "end\n" +
                    "return cnt";

    // Insert the specified value at the tail of the list with length limit
    // Removes the element at the head of the list if limit reached (exceeded)
    //
    // Keys 1. List pushed into
    // Args 1. Value to be pushed
    // Args 2. Maximum length of the list
    // Returns The value popped from the list, or nil
    public static final String RPUSHLIMIT =
            "local cnt = redis.call('RPUSH', KEYS[1], ARGV[1])\n" +
                    "if tonumber(ARGV[2]) > 0 and cnt > tonumber(ARGV[2])\n" +
                    "then\n" +
                    "   return redis.call('LPOP', KEYS[1])\n" +
                    "end\n" +
                    "return nil";

    // Insert the specified value to the sorted set with length limit
    // Removes the element at the head of the sorted set if limit reached (exceeded)
    //
    // Keys 1. Sorted Set added into
    // Args 1. Value to be added
    // Args 2. Maximum length of the sorted set
    // Returns The number of elements added to the sorted sets,
    // not including elements already existing for which the score was updated
    public static final String ZADDLIMIT =
            "local r = redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])\n" +
                    "local cnt = redis.call('ZCARD', KEYS[1])\n" +
                    "if tonumber(ARGV[3]) > 0 and cnt > tonumber(ARGV[3])\n" +
                    "then\n" +
                    "   redis.call('ZREMRANGEBYRANK', KEYS[1], 0, 0)\n" +
                    "end\n" +
                    "return r";

    // Removes the specified key only if its current value is equal to the given value
    //
    // Keys 1. Key to be deleted
    // Args 1. Value to be compared
    // Returns 1 if key is removed, 0 if key untouched
    public static final String CHECKDEL =
            "if ARGV[1] == redis.call('GET', KEYS[1])\n" +
                    "then\n" +
                    "   redis.call('DEL', KEYS[1])\n" +
                    "   return 1\n" +
                    "end\n" +
                    "return 0";
}
==============================================================================================================
User-agent: Googlebot
Disallow: /api/
Disallow: /merchantTerms/
Disallow: /login
Disallow: /logout
Disallow: /reservation/
Disallow: /reset_password
Disallow: /review/
Disallow: /site/
Disallow: /health/
Disallow: /version/ 
Disallow: */result
Disallow: */user/
Disallow: /forgot_password
Disallow: */widget

Disallow: /place/*/description
Disallow: /place/*/beschreibung
Disallow: /place/*/beschrijving
Disallow: /place/*/description
Disallow: /place/*/descrizione
Disallow: /place/*/description
Disallow: /place/*/kuvaus
Disallow: /place/*/aciklamasi 

Allow: /

User-agent: *
Disallow: /api/
Disallow: /merchantTerms/
Disallow: /checkout/
Disallow: /forgot_password
Disallow: /login
Disallow: /logout
Disallow: /reservation/
Disallow: /reset_password
Disallow: /review/
Disallow: /site/
Disallow: /user/
Disallow: /pl/
Disallow: /health/
Disallow: /version/
Disallow: */widget

User-Agent: AdIdxBot
Crawl-Delay: 15

User-agent: Bingbot
Disallow: /

User-agent: MSNBot
Disallow: /

User-agent: MSNBot-Media
Disallow: /

User-Agent: MJ12bot
Crawl-Delay: 15

User-agent: AhrefsBot
Crawl-Delay: 15

User-agent: Yandex
Disallow: /

User-agent: Baiduspider
Disallow: /

User-agent: Naver
Disallow: /

User-agent: Yeti
Disallow: /

User-agent: BLEXBot
Disallow: /

User-agent: SEMrushBot
Disallow: /

User-agent: MegaIndex.ru
Disallow: /

User-agent: adscanner
Disallow: /

User-agent: iisbot
Disallow: /

Sitemap: https://www.quandoo.com.au/sitemap.xml
==============================================================================================================
  @Bean
  public Docket api() {
    return new Docket(DocumentationType.SWAGGER_2)
        .apiInfo(apiInfo)
        .select()
        .apis(RequestHandlerSelectors.basePackage(
            PaymentsController.class.getPackage().getName()
        ))
        .paths(PathSelectors.ant("/api/v1/payments" + "/**"))
        .build()
        .useDefaultResponseMessages(false)
        .globalOperationParameters(
            newArrayList(new ParameterBuilder()
                .name("x-authorization")
                .description("X-Authorization")
                .modelRef(new ModelRef("string"))
                .parameterType("header")
                .required(false)
                .build()));
  }
==============================================================================================================
map.put(Environment.INDEXING_STRATEGY, "event");
		map.put("hibernate.search.autoregister_listeners", true);
		map.put("hibernate.search.default." + Environment.INDEX_MANAGER_IMPL_NAME, indexmanager);
		map.put("hibernate.search.default.directory_provider", directory_provider);
		map.put("hibernate.search.default.indexBase", indexBase);

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.eclipse.milo.opcua.sdk.client.api.identity.IdentityProvider;

/**
 * Created by ashvayka on 16.01.17.
 */
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AnonymousIdentityProviderConfiguration.class, name = "anonymous"),
        @JsonSubTypes.Type(value = UsernameIdentityProviderConfiguration.class, name = "username")})
public interface IdentityProviderConfiguration {

    IdentityProvider toProvider();

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
<dependency>
    <groupId>org.fusesource.mqtt-client</groupId>
    <artifactId>mqtt-client</artifactId>
    <version>1.16</version>
</dependency>


language: java
before_deploy: "gradle jar addon"
deploy:
  provider: releases
  api_key:
    secure: BSI9PlQhhOMXUm2cr8YZs+yT5vX+dLyuPNpx8uvbO1R4TvnT2hZlVt4CDV3iQUNxMF5dD+1NIbZGKfXYk7bH2Ei8AGpiObhl7peFjX9wezqV5aRct2A3eS50mO7uzD3DOt7+6jcpVzTzwiNuzRkWRuSsOocTQc5kE4A5OfcAspY=
  file: 
    - "build/libs/hm2mqtt.jar"
    - "build/distributions/hm2mqtt-addon.tar.gz"
  skip_cleanup: true
  on:
    repo: owagner/hm2mqtt
    tags: true
    all_branches: true
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
    private Pattern toRegexPattern(String subscribedTopic) {
        String regexPattern = subscribedTopic;
        regexPattern = regexPattern.replaceAll("#", ".*");
        regexPattern = regexPattern.replaceAll("\\+", "[^/]*");
        Pattern pattern = Pattern.compile(regexPattern);
        return pattern;
    }
	
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.hotspot.DefaultExports;
import io.prometheus.client.vertx.MetricsHandler;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;

/**
 * Created by giovanni on 07/07/17.
 */
public class PromMetricsExporter extends AbstractVerticle {
    @Override
    public void start() throws Exception {
        JsonObject conf = config().getJsonObject("prometheus_exporter", new JsonObject());
        int httpPort = conf.getInteger("port", 9100);
        String path = conf.getString("path", "/metrics");

        DefaultExports.initialize();

        Router router = Router.router(vertx);
        router.route(path).handler(new MetricsHandler());
        vertx.createHttpServer().requestHandler(router::accept).listen(httpPort);
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

#!/bin/bash

#
# Start H2 database and console
#

if [ ! -e ~/tmp/mop.jar ]; then
	wget http://mop.fusesource.org/repo/release/org/fusesource/mop/mop-core/1.0-m1/mop-core-1.0-m1.jar -O ~/tmp/mop.jar
fi


echo "Database URL for tests:"
echo ""
echo " jdbc:h2:target/test-home/database;AUTO_SERVER=TRUE"
echo ""

cd "$( dirname "${BASH_SOURCE[0]}" )"

mkdir -p target/database

java -jar ~/tmp/mop.jar exec com.h2database:h2:1.3.161 org.h2.tools.Console -webPort 8089
==============================================================================================================
git pull upstream master
mvn -DautoVersionSubmodules=true clean package release:prepare
mvn release:perform

   <dependency>
                <groupId>org.testcontainers</groupId>
                <artifactId>testcontainers</artifactId>
                <version>${testcontainers.version}</version>
            </dependency>
     <dependency>
                <groupId>org.testcontainers</groupId>
                <artifactId>junit-jupiter</artifactId>
                <version>${testcontainers.version}</version>
            </dependency>
			
  <dependency>
            <groupId>io.micrometer</groupId>
            <artifactId>micrometer-registry-prometheus</artifactId>
        </dependency>
		
global:
  scrape_interval: 15s
  scrape_timeout: 10s
  evaluation_interval: 15s
alerting:
  alertmanagers:
    - static_configs:
        - targets: []
      scheme: http
      timeout: 10s
scrape_configs:
  - job_name: prometheus
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
          - localhost:9090
  - job_name: spring-actuator
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /actuator/prometheus
    scheme: http
    static_configs:
      - targets: ['host.docker.internal:8080'] # works on docker for mac and windows, linux https://github.com/docker/for-linux/issues/264
	

import java.util.concurrent.TimeUnit;

import org.infinispan.Cache;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.cache.CacheMeterBinder;

/**
 * Implements {@link CacheMeterBinder} to expose Infinispan embedded metrics
 *
 * @author Katia Aresti, karesti@redhat.com
 * @since 2.1
 */
public class InfinispanCacheMeterBinder extends CacheMeterBinder {

   private final Cache cache;

   public InfinispanCacheMeterBinder(Cache cache, Iterable<Tag> tags) {
      super(cache, cache.getName(), tags);
      this.cache = cache;
   }

   @Override
   protected Long size() {
      if (cache == null) return 0L;

      return cache.getAdvancedCache().getStats().getTotalNumberOfEntries();
   }

   @Override
   protected long hitCount() {
      if (cache == null) return 0L;

      return cache.getAdvancedCache().getStats().getHits();
   }

   @Override
   protected Long missCount() {
      if (cache == null) return 0L;

      return cache.getAdvancedCache().getStats().getMisses();
   }

   @Override
   protected Long evictionCount() {
      if (cache == null) return 0L;

      return cache.getAdvancedCache().getStats().getEvictions();
   }

   @Override
   protected long putCount() {
      if (cache == null) return 0L;

      return cache.getAdvancedCache().getStats().getStores();
   }

   @Override
   protected void bindImplementationSpecificMetrics(MeterRegistry registry) {
      if (cache == null) return;

      Gauge.builder("cache.start", cache, cache -> cache.getAdvancedCache().getStats().getTimeSinceStart())
            .baseUnit(TimeUnit.SECONDS.name())
            .tags(getTagsWithCacheName())
            .description("Time elapsed since start")
            .register(registry);

      Gauge.builder("cache.reset", cache, cache -> cache.getAdvancedCache().getStats().getTimeSinceReset())
            .baseUnit(TimeUnit.SECONDS.name())
            .tags(getTagsWithCacheName())
            .description("Time elapsed since the last statistics reset")
            .register(registry);

      memory(registry);
      averages(registry);
   }

   private void memory(MeterRegistry registry) {
      Gauge.builder("cache.memory.size", cache, cache -> cache.getAdvancedCache().getStats().getCurrentNumberOfEntriesInMemory())
            .tags(getTagsWithCacheName())
            .description("Number of entries currently in the cache, excluding passivated entries")
            .register(registry);

      if (cache.getCacheConfiguration().memory().evictionStrategy().isEnabled()) {
         Gauge.builder("cache.memory.used", cache, cache -> cache.getAdvancedCache().getStats().getDataMemoryUsed())
               .tags(getTagsWithCacheName())
               .description("Provides how much memory the current eviction algorithm estimates is in use for data")
               .register(registry);
      }

      Gauge.builder("cache.memory.offHeap", cache, cache -> cache.getAdvancedCache().getStats().getOffHeapMemoryUsed())
            .tags(getTagsWithCacheName())
            .description("The amount of off-heap memory used by this cache")
            .register(registry);
   }

   private void averages(MeterRegistry registry) {
      Gauge.builder("cache.puts.latency", cache, cache -> cache.getAdvancedCache().getStats().getAverageWriteTime())
            .baseUnit(TimeUnit.MILLISECONDS.name())
            .tags(getTagsWithCacheName())
            .description("Cache puts")
            .register(registry);

      Gauge.builder("cache.gets.latency", cache, cache -> cache.getAdvancedCache().getStats().getAverageReadTime())
            .baseUnit(TimeUnit.MILLISECONDS.name())
            .tags(getTagsWithCacheName())
            .description("Cache gets")
            .register(registry);

      Gauge.builder("cache.removes.latency", cache, cache -> cache.getAdvancedCache().getStats().getAverageRemoveTime())
            .baseUnit(TimeUnit.MILLISECONDS.name())
            .tags(getTagsWithCacheName())
            .description("Cache removes")
            .register(registry);
   }
}



import io.micrometer.core.instrument.binder.cache.JCacheMetrics;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.metrics.cache.CacheMeterBinderProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.MeterBinder;

/**
 * When actuate dependency is found in the classpath, this component links Infinispan cache metrics with Actuator
 *
 * @author Katia Aresti, karesti@redtat.com
 * @since 2.1
 */
@Component
@Qualifier(InfinispanCacheMeterBinderProvider.NAME)
@ConditionalOnClass(name = "org.springframework.boot.actuate.metrics.cache.CacheMeterBinderProvider")
@ConditionalOnProperty(value = "infinispan.embedded.enabled", havingValue = "true", matchIfMissing = true)
public class InfinispanCacheMeterBinderProvider implements CacheMeterBinderProvider<Cache> {

   public static final String NAME = "infinispanCacheMeterBinderProvider";

   @Override
   public MeterBinder getMeterBinder(Cache cache, Iterable<Tag> tags) {
      Object nativeCache = cache.getNativeCache();
      MeterBinder meterBinder = null;
      if (nativeCache instanceof org.infinispan.Cache) {
         meterBinder = new InfinispanCacheMeterBinder((org.infinispan.Cache) nativeCache, tags);
      } else {
         if (nativeCache instanceof javax.cache.Cache){ // for caches like org.infinispan.jcache.embedded.JCache
            meterBinder = new JCacheMetrics((javax.cache.Cache) nativeCache, tags);
         }
      }
      return meterBinder;
   }
}


private List<Parameter> readParameters(final OperationContext context) {
 List<ResolvedMethodParameter> methodParameters = context.getParameters();
 List<Parameter> parameters = newArrayList();
 for (ResolvedMethodParameter methodParameter : methodParameters) {
  ResolvedType alternate = context.alternateFor(methodParameter.getParameterType());
  if (!shouldIgnore(methodParameter, alternate, context.getIgnorableParameterTypes())) {
   ParameterContext parameterContext = new ParameterContext(methodParameter,
     new ParameterBuilder(),
     context.getDocumentationContext(),
     context.getGenericsNamingStrategy(),
     context);
   if (shouldExpand(methodParameter, alternate)) {
    parameters.addAll(
      expander.expand(
        new ExpansionContext("", alternate, context)));
   } else {
    parameters.add(pluginsManager.parameter(parameterContext));
   }
  }
 }
 return FluentIterable.from(parameters).filter(not(hiddenParams())).toList();
}

==============================================================================================================
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
org.infinispan.spring.starter.embedded.InfinispanEmbeddedAutoConfiguration,\
org.infinispan.spring.starter.embedded.InfinispanEmbeddedCacheManagerAutoConfiguration
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
<plugin>
    <groupId>org.jbehave</groupId>
    <artifactId>jbehave-maven-plugin</artifactId>
    <version>[version]</version>
    <executions>
        <!-- define executions as normal -->
        <metaFilters>
            <metaFilter>"groovy: lang != 'java'"</metaFilter>
        </metaFilters>
    </executions>
    <dependencies>
        <dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy-all</artifactId>
            <version>2.4.15</version>
        </dependency>
    </dependencies>
</plugin>

<plugin>
    <groupId>org.jbehave</groupId>
    <artifactId>jbehave-maven-plugin</artifactId>
    <version>[version]</version>
    <executions>
        <!-- define executions as normal -->
    </executions>
    <dependencies>
        <dependency>
            <groupId>log4j</groupId>
            <artifactId>log4j</artifactId>
            <version>1.2.16</version>
        </dependency>
    </dependencies>
</plugin>

<plugin>
    <groupId>org.jbehave</groupId>
    <artifactId>jbehave-maven-plugin</artifactId>
    <version>[version]</version>
    <executions>
        <execution>
            <id>run-stories-as-embeddables</id>
            <phase>integration-test</phase>
            <configuration>
                <includes>
                    <include>**/*Stories.java</include>
                </includes>
                <metaFilters>
                    <metaFilter>+author *</metaFilter>
                    <metaFilter>-skip</metaFilter>
                </metaFilters>
                <systemProperties>
                    <property>
                      <name>java.awt.headless</name>
                      <value>true</value>
                    </property>
                </systemProperties>
                <ignoreFailureInStories>true</ignoreFailureInStories>
                <ignoreFailureInView>false</ignoreFailureInView>
            </configuration>
            <goals>
                <goal>run-stories-as-embeddables</goal>
            </goals>
        </execution>
    </executions>
</plugin>
==============================================================================================================
    <dependency>
      <groupId>org.infinispan</groupId>
      <artifactId>infinispan-core</artifactId>
    </dependency>

    <dependency>
      <groupId>org.infinispan</groupId>
      <artifactId>infinispan-cloud</artifactId>
    </dependency>

    <dependency>
      <groupId>org.infinispan</groupId>
      <artifactId>infinispan-spring4-embedded</artifactId>
    </dependency>

    <dependency>
      <groupId>org.infinispan</groupId>
      <artifactId>infinispan-spring-boot-starter</artifactId>
      <version>${infinispan-spring-boot-starter.version}</version>
      <exclusions>
        <exclusion>
          <groupId>org.infinispan</groupId>
          <artifactId>infinispan-commons</artifactId>
        </exclusion>
        <exclusion>
          <groupId>org.infinispan</groupId>
          <artifactId>infinispan-client-hotrod</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
==============================================================================================================
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import scala.Tuple2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

/**
 * Created by achat1 on 9/23/15.
 * Just an example to see if it works.
 */
@Component
public class WordCount {

    @Autowired
    private JavaSparkContext javaSparkContext;

    @Value("${input.file}")
    private String inputFile;

    @Value("${input.threshold}")
    private int threshold;


    public void count() {

        JavaRDD<String> tokenized = javaSparkContext.textFile(inputFile).flatMap((s1) -> Arrays.asList(s1.split(" ")));

        // count the occurrence of each word
        JavaPairRDD<String, Integer> counts = tokenized
                .mapToPair(s -> new Tuple2<>(s, 1))
                .reduceByKey((i1, i2) -> i1 + i2);

        // filter out words with less than threshold occurrences
        JavaPairRDD<String, Integer> filtered = counts.filter(tup -> tup._2() >= threshold);

        // count characters
        JavaPairRDD<Character, Integer> charCounts = filtered.flatMap(
                s -> {
                    Collection<Character> chars = new ArrayList<>(s._1().length());
                    for (char c : s._1().toCharArray()) {
                        chars.add(c);
                    }
                    return chars;
                }
        ).mapToPair(c -> new Tuple2<>(c, 1))
                .reduceByKey((i1, i2) -> i1 + i2);

        System.out.println(charCounts.collect());
    }
}

import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaSparkContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.Environment;

/**
 * Created by achat1 on 9/22/15.
 */
@Configuration
@PropertySource("classpath:application.properties")
public class ApplicationConfig {

    @Autowired
    private Environment env;

    @Value("${app.name:jigsaw}")
    private String appName;

    @Value("${spark.home}")
    private String sparkHome;

    @Value("${master.uri:local}")
    private String masterUri;

    @Bean
    public SparkConf sparkConf() {
        SparkConf sparkConf = new SparkConf()
                .setAppName(appName)
                .setSparkHome(sparkHome)
                .setMaster(masterUri);

        return sparkConf;
    }

    @Bean
    public JavaSparkContext javaSparkContext() {
        return new JavaSparkContext(sparkConf());
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

}
==============================================================================================================
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

/**
 * Created by daz on 01/07/2017.
 */
@Configuration
public class AppConfig {
    
    @Value("${spring.datasource.url}")
    private String datasourceUrl;
    
    @Value("${spring.database.driverClassName}")
    private String dbDriverClassName;
    
    @Value("${spring.datasource.username}")
    private String dbUsername;
    
    @Value("${spring.datasource.password}")
    private String dbPassword;
    
    @Bean
    public DataSource dataSource() {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        
        dataSource.setDriverClassName(dbDriverClassName);
        dataSource.setUrl(datasourceUrl);
        dataSource.setUsername(dbUsername);
        dataSource.setPassword(dbPassword);
        
        return dataSource;
    }
    
    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource());
    }
}


import com.dazito.oauthexample.config.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * Created by daz on 27/06/2017.
 */
@EnableAuthorizationServer
@Configuration
public class AuthServerOAuth2Config extends AuthorizationServerConfigurerAdapter {
    
    private final AuthenticationManager authenticationManager;
    private final AppConfig appConfig;
    
    @Autowired
    public AuthServerOAuth2Config(AuthenticationManager authenticationManager, AppConfig appConfig) {
        this.authenticationManager = authenticationManager;
        this.appConfig = appConfig;
    }
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(appConfig.dataSource());
    }
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        /*
         * Allow our tokens to be delivered from our token access point as well as for tokens
         * to be validated from this point
         */
        security.checkTokenAccess("permitAll()");
    }
    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(appConfig.tokenStore()); // Persist the tokens in the database
    }
}
atomicleopard


import com.googlecode.objectify.ObjectifyService;
import edu.monash.monplan.model.Course;
import edu.monash.monplan.model.Unit;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Arrays;

@Configuration
public class ObjectifyConfig implements ServletContextListener {

    @PostConstruct
    public void init() {
        registerObjectifyEntities();
    }

    private void registerObjectifyEntities() {
        register(Unit.class);
        register(Course.class);
    }


    private void register(Class<?>... entityClasses) {
        Arrays.stream(entityClasses)
                .forEach(ObjectifyService::register);
    }
    
    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        registerObjectifyEntities();
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }

}
==============================================================================================================
/**
 * This class is used as scheduled task which resets the database every 15 minutes to it's initial state.
 *
 * @author Fabian Dietenberger
 */
@Component
class ScheduledDatabaseResetTask {

    private final Logger logger = LoggerFactory.getLogger(ScheduledDatabaseResetTask.class);
    private final TodoItemRepository repository;
    private final SpringBootGwtProperties springBootGwtProperties;

    @Autowired
    public ScheduledDatabaseResetTask(final TodoItemRepository repository, final SpringBootGwtProperties springBootGwtProperties) {
        this.repository = repository;
        this.springBootGwtProperties = springBootGwtProperties;
    }

    @Scheduled(fixedRateString = "${spring-boot-gwt.scheduled-database-reset-interval-millis}")
    public void resetDatabase() {
        if (springBootGwtProperties.isScheduledDatabaseReset()) {
            logger.info("Reset database");

            repository.deleteAll();

            for (final String initialTodoItem : springBootGwtProperties.getInitialTodoItems()) {
                repository.save(new TodoItem(initialTodoItem));
            }

            final List<TodoItem> itemsInDatabase = Optional.ofNullable(repository.findAll()).orElse(Collections.emptyList());
            logger.info("Saved " + itemsInDatabase.size() + " todo items to the database: " + itemsInDatabase.toString());
        }
    }
}
==============================================================================================================
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class CorsConfig {

    @Bean
    public FilterRegistrationBean corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("HEAD");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("DELETE");
        config.addAllowedMethod("PATCH");
        source.registerCorsConfiguration("/**", config);
        // return new CorsFilter(source);
        final FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public WebMvcConfigurer mvcConfigurer() {
        return new WebMvcConfigurerAdapter() {
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedMethods("GET", "PUT", "POST", "GET", "OPTIONS");
            }
        };
    }
}

public class MonPlanAssertion {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_RED = "\u001B[31m";

    public static void assertTrue(boolean condition, String errorMessage) {
        if (!condition) {
            System.out.println(ANSI_RED + "AssertionWarning: " + errorMessage + ANSI_RESET);
        }
    }
}

    @SuppressWarnings("unchecked")
    @Override
    public <In> BigDecimal normalise(TransformerManager transformerManager, In value) {
        Class<In> valueClass = (Class<In>) value.getClass();
        BigDecimal bigDecimalValue = transformerManager.transform(valueClass, BigDecimal.class, value);
        bigDecimalValue = bigDecimalValue.movePointLeft(shift).setScale(shift + scale, RoundingMode.DOWN);
        bigDecimalValue = bigDecimalValue.min(Max).max(Min);
        return bigDecimalValue;
    }
	
==============================================================================================================
    @Bean
    public ServletRegistrationBean h2servletRegistration() {
        ServletRegistrationBean registration = new ServletRegistrationBean(new WebServlet());
        registration.addUrlMappings("/console/*");
        return registration;
    }
==============================================================================================================
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.mvc.method.annotation.DeferredResultMethodReturnValueHandler;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

@Configuration
public class WebMvcConfiguration extends WebMvcConfigurationSupport {

  @Autowired
  private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

  @Bean
  public HandlerMethodReturnValueHandler completableFutureReturnValueHandler() {
    return new CompletableFutureReturnValueHandler();
  }

  @PostConstruct
  public void init() {
    final List<HandlerMethodReturnValueHandler> originalHandlers = new ArrayList<>(
        requestMappingHandlerAdapter.getReturnValueHandlers());
    
    final int deferredPos = obtainValueHandlerPosition(originalHandlers, DeferredResultMethodReturnValueHandler.class);
    // Add our handler directly after the deferred handler.
    originalHandlers.add(deferredPos + 1, completableFutureReturnValueHandler());
    
    requestMappingHandlerAdapter.setReturnValueHandlers(originalHandlers);
  }

  private int obtainValueHandlerPosition(final List<HandlerMethodReturnValueHandler> originalHandlers, Class<?> handlerClass) {
    for (int i = 0; i < originalHandlers.size(); i++) {
      final HandlerMethodReturnValueHandler valueHandler = originalHandlers.get(i);
      if (handlerClass.isAssignableFrom(valueHandler.getClass())) {
        return i;
      }
    }
    return -1;
  }
}
==============================================================================================================
#!/bin/sh


APP_NAME="bootiful-applications"
DB_SVC_NAME="$APP_NAME-postgresql"
NEWRELIC_SVC_NAME="$APP_NAME-newrelic"
PAPERTRAIL_LOGS_SVC_NAME="$APP_NAME-papertrail-logs"

# tear app and service down if they already exist
cf delete -f $APP_NAME
cf delete-service -f $DB_SVC_NAME
cf delete-service -f $NEWRELIC_SVC_NAME
cf delete-service -f $PAPERTRAIL_LOGS_SVC_NAME

# push the app to the cloud
cf push -p target/demo-0.0.1-SNAPSHOT.jar --random-route $APP_NAME

# give it a backing service
cf services | grep $DB_SVC_NAME || cf create-service elephantsql turtle $DB_SVC_NAME

# bind it to the app
cf bind-service $APP_NAME $DB_SVC_NAME
cf restage $APP_NAME

# scale it
cf scale -i 3 -f $APP_NAME # our free turtle tier PG DB only handles 5 at a time

# watch it auto-heal
URI="`cf a | grep $APP_NAME | tr " " "\n" | grep cfapps.io`"
curl http://$URI/killme
# now watch 'cf apps' reflect auto-healing

# connect to DB
DB_URI=`cf env $APP_NAME | grep postgres: | cut -f2- -d:`;
echo $DB_URI

# lets add New Relic APM
cf create-service newrelic standard $NEWRELIC_SVC_NAME
cf bind-service $APP_NAME $NEWRELIC_SVC_NAME
cf restage $APP_NAME

# lets add a PaperTrail log drain - see https://papertrailapp.com/systems/CloudFoundry/events
PAPERTRAIL_LOG_URL="logs2.papertrailapp.com:49046"
cf create-user-provided-service $PAPERTRAIL_LOGS_SVC_NAME -l syslog://$PAPERTRAIL_LOG_URL
cf bind-service $APP_NAME $PAPERTRAIL_LOGS_SVC_NAME
cf restage $APP_NAME

# make sure we can get back here again
cf create-app-manifest $APP_NAME

# how do we control everything programatically?
echo the OAuth token is `cf oauth-token`
==============================================================================================================
import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@SuppressWarnings("serial")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "person", propOrder = {"name"})
@XmlRootElement(name = "person")
public class Person implements Serializable {

    private String name;

    public Person() {
    }

    public Person(String name) {
        setName(name);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

}
==============================================================================================================
import org.ocpsoft.prettytime.PrettyTime;

import java.nio.file.Path;

/**
* Created by lh on 28/02/15.
*/
public abstract class AbstractFileProvider implements FileProvider {
    protected static final PrettyTime prettyTime = new PrettyTime();

    protected boolean isArchive(Path path) {
        return isZip(path) || isTarGz(path);
    }

    protected boolean isTarGz(Path path) {
        return !path.toFile().isDirectory() && path.getFileName().toString().endsWith(".tar.gz");
    }

    protected boolean isZip(Path path) {
        return !path.toFile().isDirectory() && path.getFileName().toString().endsWith(".zip");
    }
}
==============================================================================================================
import java.io.InputStream;
import java.util.List;

import javax.annotation.Resource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class CitiesInitializer implements InitializingBean {

  @Resource
  private CityDao cityDao;
  @Resource
  private ObjectMapper objectMapper;
  @Value("${sbtfragments.citiesFile}")
  private String citiesFile;

  @Override
  public void afterPropertiesSet() throws Exception {
    org.springframework.core.io.Resource resource = new ClassPathResource(citiesFile);

    List<City> cities;
    try (InputStream inputStream = resource.getInputStream()) {
      cities = objectMapper.readValue(inputStream, new TypeReference<List<City>>() {
      });
    }
    cities.forEach(city -> cityDao.add(city));
  }
}
==============================================================================================================
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-enforcer-plugin</artifactId>
          <version>1.4.1</version>
          <executions>
            <execution>
              <id>enforce-mandatory-property</id>
              <goals>
                <goal>enforce</goal>
              </goals>
              <configuration>
                <rules>
                  <requireProperty>
                    <property>apiKey</property>
                    <message>You must pass base64 hash of the apiKey like -DapiKey="base64 encoded api key"
                      Please visit https://www.themoviedb.org/documentation/api for more info.
                    </message>
                    <regex>^[A-Za-z0-9+\/=]*$</regex>
                    <regexMessage>Please pass a valid base64 encoded value for your apiKey</regexMessage>
                  </requireProperty>
                </rules>
                <fail>true</fail>
              </configuration>
            </execution>
          </executions>
        </plugin>
==============================================================================================================
@echo off
REM Copyright (C) 2007 The Android Open Source Project
REM
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM
REM     http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.

REM don't modify the caller's environment
setlocal

REM Locate dx.jar in the directory where dx.bat was found and start it.

REM Set up prog to be the path of this script, including following symlinks,
REM and set up progdir to be the fully-qualified pathname of its directory.
set prog=%~f0

rem Check we have a valid Java.exe in the path.
set java_exe=
if exist    "%~dp0..\tools\lib\find_java.bat" call    "%~dp0..\tools\lib\find_java.bat"
if exist "%~dp0..\..\tools\lib\find_java.bat" call "%~dp0..\..\tools\lib\find_java.bat"
if not defined java_exe goto :EOF

set jarfile=dx.jar
set "frameworkdir=%~dp0"
rem frameworkdir must not end with a dir sep.
set "frameworkdir=%frameworkdir:~0,-1%"

if exist "%frameworkdir%\%jarfile%" goto JarFileOk
    set "frameworkdir=%~dp0lib"

if exist "%frameworkdir%\%jarfile%" goto JarFileOk
    set "frameworkdir=%~dp0..\framework"

:JarFileOk

set "jarpath=%frameworkdir%\%jarfile%"

set javaOpts=
set args=

REM By default, give dx a max heap size of 1 gig and a stack size of 1meg.
rem This can be overridden by using "-JXmx..." and "-JXss..." options below.
set defaultXmx=-Xmx1024M
set defaultXss=-Xss1m

REM Capture all arguments that are not -J options.
REM Note that when reading the input arguments with %1, the cmd.exe
REM automagically converts --name=value arguments into 2 arguments "--name"
REM followed by "value". Dx has been changed to know how to deal with that.
set params=

:firstArg
if [%1]==[] goto endArgs
set a=%~1

    if [%defaultXmx%]==[] goto notXmx
    if %a:~0,5% NEQ -JXmx goto notXmx
        set defaultXmx=
    :notXmx

    if [%defaultXss%]==[] goto notXss
    if %a:~0,5% NEQ -JXss goto notXss
        set defaultXss=
    :notXss

    if %a:~0,2% NEQ -J goto notJ
        set javaOpts=%javaOpts% -%a:~2%
        shift /1
        goto firstArg

    :notJ
    set params=%params% %1
    shift /1
    goto firstArg

:endArgs

set javaOpts=%javaOpts% %defaultXmx% %defaultXss%
call "%java_exe%" %javaOpts% -Djava.ext.dirs="%frameworkdir%" -jar "%jarpath%" %params%
==============================================================================================================
@if "%DEBUG%" == "" @echo off
@rem ##########################################################################
@rem
@rem  Gradle startup script for Windows
@rem
@rem ##########################################################################

@rem Set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" setlocal

@rem Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS to pass JVM options to this script.
set DEFAULT_JVM_OPTS=

set DIRNAME=%~dp0
if "%DIRNAME%" == "" set DIRNAME=.
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%

@rem Find java.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA_EXE=java.exe
%JAVA_EXE% -version >NUL 2>&1
if "%ERRORLEVEL%" == "0" goto init

echo.
echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:findJavaFromJavaHome
set JAVA_HOME=%JAVA_HOME:"=%
set JAVA_EXE=%JAVA_HOME%/bin/java.exe

if exist "%JAVA_EXE%" goto init

echo.
echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:init
@rem Get command-line arguments, handling Windowz variants

if not "%OS%" == "Windows_NT" goto win9xME_args
if "%@eval[2+2]" == "4" goto 4NT_args

:win9xME_args
@rem Slurp the command line arguments.
set CMD_LINE_ARGS=
set _SKIP=2

:win9xME_args_slurp
if "x%~1" == "x" goto execute

set CMD_LINE_ARGS=%*
goto execute

:4NT_args
@rem Get arguments from the 4NT Shell from JP Software
set CMD_LINE_ARGS=%$

:execute
@rem Setup the command line

set CLASSPATH=%APP_HOME%\gradle\wrapper\gradle-wrapper.jar

@rem Execute Gradle
"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %GRADLE_OPTS% "-Dorg.gradle.appname=%APP_BASE_NAME%" -classpath "%CLASSPATH%" org.gradle.wrapper.GradleWrapperMain %CMD_LINE_ARGS%

:end
@rem End local scope for the variables with windows NT shell
if "%ERRORLEVEL%"=="0" goto mainEnd

:fail
rem Set variable GRADLE_EXIT_CONSOLE if you need the _script_ return code instead of
rem the _cmd.exe /c_ return code!
if  not "" == "%GRADLE_EXIT_CONSOLE%" exit 1
exit /b 1

:mainEnd
if "%OS%"=="Windows_NT" endlocal

:omega

==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
import re

# EXAMPLE 1 - SEARCHING
patterns = ['term1', 'term2', 'term3']

text = 'This is a string with term2, but not the other term.'

for pattern in patterns:
    print(f'Searching for {pattern} in text')

    # pattern, text
    if re.search(pattern, text):
        print('Match was found\n')
    else:
        print('No match Found\n')

match = re.search('term2', text)
print(match)
print(type(match))


# EXAMPLE 2 - SPLITTING
email = 'rodrickwamala@gmail.com'

split_at = '@'

print(re.split(split_at, email))

# EXAMPLE 3 - FINDING
print(re.findall('rod', 'The email rodrickwamala@gmail.com belongs to the user wamala rodrick and has a username rodcalvin.'))
==============================================================================================================
-- phpMyAdmin SQL Dump
-- version 3.5.2
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Oct 20, 2012 at 06:03 PM
-- Server version: 5.5.25a
-- PHP Version: 5.4.4

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `hackmedb`
--

-- --------------------------------------------------------

--
-- Table structure for table `tblactivities`
--

CREATE TABLE IF NOT EXISTS `tblactivities` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'Activity ID',
  `from` int(11) NOT NULL COMMENT 'From ID',
  `to` int(11) NOT NULL COMMENT 'To ID',
  `amount` int(11) NOT NULL COMMENT 'Amount (Money)',
  `dateTime` datetime NOT NULL COMMENT 'Date And Time OF The Activity',
  `comment` text COMMENT 'Activity Comment',
  PRIMARY KEY (`id`),
  KEY `from` (`from`),
  KEY `to` (`to`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='Activities Table - Purchase / Wire Transfers' AUTO_INCREMENT=37 ;

--
-- Dumping data for table `tblactivities`
--

INSERT INTO `tblactivities` (`id`, `from`, `to`, `amount`, `dateTime`, `comment`) VALUES
(1, 3, 11, 200, '2012-10-09 06:31:39', NULL),
(2, 10, 4, 300, '2012-09-04 08:34:39', NULL),
(3, 11, 3, 200, '2012-10-16 11:38:27', NULL),
(22, 4, 6, 1, '2012-10-18 06:34:49', NULL),
(23, 4, 9, 1, '2012-10-18 06:53:00', NULL),
(24, 9, 4, 325, '2012-10-18 06:55:51', NULL),
(25, 9, 4, 325, '2012-10-18 06:55:52', NULL),
(26, 9, 4, 325, '2012-10-18 06:55:52', NULL),
(27, 9, 4, 325, '2012-10-18 06:55:53', NULL),
(28, 9, 4, 325, '2012-10-18 06:55:53', NULL),
(29, 9, 4, 325, '2012-10-18 06:55:54', 'WTF WTF WTF IS THIS?'),
(30, 4, 3, 1, '2012-10-18 08:01:13', 'Please Look At My Profile.'),
(31, 6, 3, 1, '2012-10-18 08:01:31', '<script>\r\nalert("I Hacked Your Account With XSS Attack");\r\n</script>\r\nHello Man ;)'),
(32, 3, 4, 325, '2012-10-19 18:20:11', 'Bank Activities'),
(33, 3, 4, 325, '2012-10-19 18:20:33', 'Bank Activities'),
(34, 3, 4, 325, '2012-10-19 18:20:41', 'Bank Activities'),
(35, 3, 4, 325, '2012-10-19 18:20:58', 'Bank Activities'),
(36, 3, 4, 325, '2012-10-19 18:31:46', 'Bank Activities');

-- --------------------------------------------------------

--
-- Table structure for table `tblcities`
--

CREATE TABLE IF NOT EXISTS `tblcities` (
  `id` smallint(6) NOT NULL AUTO_INCREMENT COMMENT 'City ID',
  `name` varchar(30) NOT NULL COMMENT 'City Name',
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='Cities Table' AUTO_INCREMENT=13 ;

--
-- Dumping data for table `tblcities`
--

INSERT INTO `tblcities` (`id`, `name`) VALUES
(8, 'AULDEARN'),
(2, 'GREATHAM'),
(3, 'HALISTRA'),
(6, 'KIRRIEMUIR'),
(11, 'LONDON'),
(10, 'MADELEY'),
(12, 'MANCHESTER'),
(4, 'OVERCOMBE'),
(7, 'STREETLY'),
(5, 'WESTMILL'),
(1, 'WISTANSWICK'),
(9, 'WRAXALL');

-- --------------------------------------------------------

--
-- Table structure for table `tblcreditcards`
--

CREATE TABLE IF NOT EXISTS `tblcreditcards` (
  `bankID` int(11) NOT NULL COMMENT 'Bank Identity Number',
  `cardID` tinyint(4) NOT NULL COMMENT 'Card ID',
  `cardNumber` varchar(16) NOT NULL COMMENT 'CardNumber',
  `expires` date NOT NULL COMMENT 'Expiration Date',
  `securityCode` smallint(3) NOT NULL COMMENT 'Card Security Code',
  UNIQUE KEY `cardNumber` (`cardNumber`),
  KEY `bankID` (`bankID`),
  KEY `cardID` (`cardID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Credit Cards Table';

--
-- Dumping data for table `tblcreditcards`
--

INSERT INTO `tblcreditcards` (`bankID`, `cardID`, `cardNumber`, `expires`, `securityCode`) VALUES
(11, 2, '4532593351978997', '2015-09-01', 258),
(4, 2, '491669530035580', '2015-04-01', 76),
(5, 2, '4929300005859602', '2016-12-01', 778),
(10, 1, '5100611175814765', '2016-06-01', 190),
(12, 1, '5161119300892686', '2015-01-01', 735),
(7, 1, '5429687965003649', '2015-11-01', 955),
(3, 1, '5430976730197472', '2015-06-01', 753),
(6, 1, '5537543009062415', '2017-09-01', 147),
(9, 1, '5545780166550101', '2017-12-01', 99),
(8, 1, '5589245285450192', '2013-04-01', 53);

-- --------------------------------------------------------

--
-- Table structure for table `tblcreditcardstype`
--

CREATE TABLE IF NOT EXISTS `tblcreditcardstype` (
  `id` tinyint(4) NOT NULL AUTO_INCREMENT COMMENT 'Credit Card ID',
  `name` varchar(30) NOT NULL COMMENT 'Credit Card Type',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='Credit Cards Types Table' AUTO_INCREMENT=6 ;

--
-- Dumping data for table `tblcreditcardstype`
--

INSERT INTO `tblcreditcardstype` (`id`, `name`) VALUES
(1, 'Master Card'),
(2, 'Visa'),
(3, 'American Express'),
(4, 'Diners'),
(5, 'Isracard');

-- --------------------------------------------------------
--
-- Table structure for table `tblusers`
--

CREATE TABLE IF NOT EXISTS `tblusers` (
  `bankID` int(11) NOT NULL AUTO_INCREMENT COMMENT 'Bank Identity Number',
  `nino` varchar(9) NOT NULL COMMENT 'National Insurance Numbers',
  `firstName` varchar(30) NOT NULL COMMENT 'First Name',
  `lastName` varchar(30) NOT NULL COMMENT 'Last Name',
  `gender` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'Gender (1 = Male, 0 = Female)',
  `address` varchar(35) NOT NULL COMMENT 'Street Address',
  `city` smallint(6) NOT NULL COMMENT 'City',
  `passcode` varchar(7) DEFAULT NULL COMMENT 'Passcode',
  `phone` bigint(11) NOT NULL COMMENT 'Phone Number',
  `birthday` date NOT NULL COMMENT 'BirthDay Date',
  `occupation` varchar(40) DEFAULT NULL COMMENT 'Occupation',
  `username` varchar(30) NOT NULL COMMENT 'User Name',
  `password` varchar(32) NOT NULL COMMENT 'Password',
  `email` varchar(100) NOT NULL COMMENT 'Email Address',
  `pictureURL` varchar(150) DEFAULT 'images/profiles/nopic.png' COMMENT 'Picture URL',
  PRIMARY KEY (`bankID`),
  UNIQUE KEY `nino` (`nino`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`),
  KEY `city` (`city`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='User Details Table' AUTO_INCREMENT=13 ;

--
-- Dumping data for table `tblusers`
--

INSERT INTO `tblusers` (`bankID`, `nino`, `firstName`, `lastName`, `gender`, `address`, `city`, `passcode`, `phone`, `birthday`, `occupation`, `username`, `password`, `email`, `pictureURL`) VALUES
(3, 'GJ352274C', 'Aaron', 'Howell', 1, '69 Temple Way', 8, 'TF97DW', 7956686747, '1935-10-02', 'Jeweler', 'Gainnoo1935', '4c22bbbe1ac409c7def582ed39489086', 'AaronHowell@teleworm.us', 'images/profiles/sil-male.png'),
(4, 'ZJ970015', 'Sofia', 'Morton', 0, '34 Walden Road', 2, 'RH203NN', 7919699732, '1965-01-27', 'Loan interviewer', 'Thomene', '7592e99453393cbebf92a967bb299abf', 'SofiaMorton@teleworm.us', 'pages/transference-wire.jsp?to=4&amount=325&comment=Bank Activities&send=send'),
(5, 'SR628780C', 'Peter', 'Hunter', 1, '27 Fordham Rd', 3, 'IV553DG', 7074780680, '1930-04-01', 'Billing and posting clerk', 'Gond1930', '01f95bf73ffddee60db468332445b05c', 'PeterHunter@teleworm.us', 'images/profiles/sil-male.png'),
(6, 'EW506660A', 'Corey', 'Nicholls', 1, '19 York Road', 4, 'DT33WA', 7023992014, '1960-09-29', 'Ophthalmic medical assistant', 'Alcour', '9c6c6533c3e58c2bb77fdbf5f1833a6f', 'CoreyNicholls@teleworm.us', 'images/profiles/sil-male.png'),
(7, 'JN632558', 'Chelsea', 'Hancock', 0, '17 Bouverie Road', 5, 'SG90RN', 7700950884, '1935-11-24', 'Mathematician', 'Rater1935', '01142620345763ad08950d8bb89c8975', 'ChelseaHancock@dayrep.com', 'images/profiles/sil-female.png'),
(8, 'SR446112B', 'Alexander', 'Bolton', 1, '45 Witney Way', 6, 'DD88PF', 7081145205, '1929-04-25', 'Pediatrician', 'Forepainely', '1ece31f17227e95c47edb1a75148114a', 'AlexanderBolton@teleworm.us', 'images/profiles/sil-male.png'),
(9, 'YC594700', 'Adam', 'Rose', 1, '10 Berkeley Rd', 7, 'B746GB', 7006479241, '1974-11-15', 'Airport terminal controller', 'Housee', 'ab69e1cf15c9c6f1d8ea15b2e9bdcc07', 'AdamRose@teleworm.us', 'images/profiles/sil-male.png'),
(10, 'CR661660C', 'Joshua', 'Dodd', 1, '94 Leicester Road', 8, 'IV124GF', 7955532329, '1963-07-01', 'Route driver', 'Hiself', 'a9d22fa808974a43989c157a5a99e27e', 'JoshuaDodd@teleworm.us', 'images/profiles/sil-male.png'),
(11, 'MP711069', 'Charles', 'Pearson', 1, '37 Oxford Rd', 9, 'BS198TZ', 7028749417, '1964-07-04', 'Cooling and freezing equipment tender', 'Hiseespeark', 'cdafd468a0b4775eeaaaa2f6e83f627f', 'CharlesPearson@dayrep.com', 'images/profiles/sil-male.png'),
(12, 'YL555515D', 'Grace', 'Turner', 0, '43 South Crescent', 10, 'TF79DA', 7041151289, '1928-12-15', 'Construction inspector', 'Veragiclumad', '7b0d1f32c32f9489705b373e724f3f82', 'GraceTurner@teleworm.us', 'images/profiles/sil-female.png');

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tblactivities`
--
ALTER TABLE `tblactivities`
  ADD CONSTRAINT `tblactivities_ibfk_1` FOREIGN KEY (`from`) REFERENCES `tblusers` (`bankID`),
  ADD CONSTRAINT `tblactivities_ibfk_2` FOREIGN KEY (`to`) REFERENCES `tblusers` (`bankID`);

--
-- Constraints for table `tblcreditcards`
--
ALTER TABLE `tblcreditcards`
  ADD CONSTRAINT `tblcreditcards_ibfk_1` FOREIGN KEY (`bankID`) REFERENCES `tblusers` (`bankID`),
  ADD CONSTRAINT `tblcreditcards_ibfk_2` FOREIGN KEY (`cardID`) REFERENCES `tblcreditcardstype` (`id`);

--
-- Constraints for table `tblusers`
--
ALTER TABLE `tblusers`
  ADD CONSTRAINT `tblusers_ibfk_1` FOREIGN KEY (`city`) REFERENCES `tblcities` (`id`);

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
==============================================================================================================
public class Security {
	public static String MD5(String md5) {
		   try {
		        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
		        byte[] array = md.digest(md5.getBytes());
		        StringBuffer sb = new StringBuffer();
		        for (int i = 0; i < array.length; ++i) {
		          sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
		       }
		        return sb.toString();
		    } catch (java.security.NoSuchAlgorithmException e) {
		    	System.out.println(e.toString());
		    }
		    return null;
		}
}
==============================================================================================================
%PDF-1.2
% created by PIL PDF driver 0.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Count 1
/Kids [4 0 R]
>>
endobj
3 0 obj
<<
/Type /XObject
/Subtype /Image
/Width 2490
/Height 3510
/Length 723721
/Filter /DCTDecode
/BitsPerComponent 8
/ColorSpace /DeviceRGB
>>
stream
...
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/Resources <<
/ProcSet [ /PDF /ImageC ]
/XObject << /image 3 0 R >>
>>
/MediaBox [ 0 0 2490 3510 ]
/Contents 5 0 R
>>
endobj
5 0 obj
<<
/Length 35
>>
stream
q 2490 0 0 3510 0 0 cm /image Do Q

endstream
endobj
xref
0 6
0000000000 65535 f 
0000000041 00000 n 
0000000090 00000 n 
0000000147 00000 n 
0000724040 00000 n 
0000724202 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
724287
%%EOF
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================
==============================================================================================================