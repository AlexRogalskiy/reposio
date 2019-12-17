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
